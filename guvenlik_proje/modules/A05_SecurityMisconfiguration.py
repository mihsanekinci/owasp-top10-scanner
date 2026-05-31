"""
modules/A05_SecurityMisconfiguration.py

OWASP A05:2021 – Security Misconfiguration

Test stratejisi (tamamen statik analiz):
  Güvenlik Başlıkları:
    - X-Frame-Options, Content-Security-Policy, X-Content-Type-Options,
      Referrer-Policy, Permissions-Policy başlıklarının varlığı kontrol edilir.
    - Her eksik başlık ayrı bir bulgu üretir.
  Sunucu Bilgi Sızıntısı:
    - Server ve X-Powered-By başlıklarında versiyon bilgisi tespiti.
  Hata Sayfası Bilgi Sızıntısı:
    - Kasıtlı hatalı istekle tetiklenen PHP/stack trace yayımı.
  Dizin Listeleme:
    - Yaygın dizinlere GET atılır, index listesi dönen yanıt bulgu olur.
  Hassas Dosya Erişimi:
    - .git, .env, backup gibi kritik dosyaların erişilebilirlik kontrolü.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests

from core.base_module import BaseModule, Finding, Confidence, Severity
from core.http_client import HTTPClient
from core.llm_client import LLMClient

# ---------------------------------------------------------------------------
# Güvenlik başlığı tanımları: (başlık_adı, ciddiyet, açıklama)
# ---------------------------------------------------------------------------

_SECURITY_HEADERS: list[tuple[str, Severity, str]] = [
    ("Content-Security-Policy",   Severity.HIGH,   "XSS ve veri enjeksiyonu saldırılarına karşı koruma sağlar."),
    ("X-Frame-Options",           Severity.MEDIUM, "Clickjacking saldırılarını engeller."),
    ("X-Content-Type-Options",    Severity.MEDIUM, "MIME sniffing saldırılarını engeller."),
    ("Strict-Transport-Security", Severity.HIGH,   "HTTPS zorunluluğu; MITM saldırısını önler."),
    ("Referrer-Policy",           Severity.LOW,    "Referrer sızıntısını kontrol eder."),
    ("Permissions-Policy",        Severity.LOW,    "Tarayıcı API erişimini kısıtlar."),
]

# Sunucu versiyon sızıntısı deseni
_VERSION_PATTERN = re.compile(
    r"(?:apache|nginx|iis|php|tomcat|lighttpd|jetty|gunicorn)[/\s]+([\d.]+)",
    re.IGNORECASE,
)

# Hata sayfası imzaları
_ERROR_SIGNATURES: list[re.Pattern] = [
    re.compile(r"Fatal error.*on line \d+", re.IGNORECASE),
    re.compile(r"Warning:.*in.*\.php on line", re.IGNORECASE),
    re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE),
    re.compile(r"at .*\(.*\.java:\d+\)", re.IGNORECASE),       # Java stack trace
    re.compile(r"Microsoft .NET Framework", re.IGNORECASE),
    re.compile(r"mysqli_connect\(\).*failed", re.IGNORECASE),
]

# Dizin listeleme belirteci
_DIR_LISTING_PATTERNS: list[re.Pattern] = [
    re.compile(r"Index of /", re.IGNORECASE),
    re.compile(r"<title>Directory listing", re.IGNORECASE),
    re.compile(r"Parent Directory", re.IGNORECASE),
]

# Hassas dizinler ve dosyalar
_SENSITIVE_PATHS: list[str] = [
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/backup.zip",
    "/backup.tar.gz",
    "/backup.sql",
    "/db.sql",
    "/dump.sql",
    "/.htaccess",
    "/phpinfo.php",
    "/info.php",
    "/server-status",    # Apache
    "/server-info",      # Apache
    "/robots.txt",       # Bilgilendirici; içerik analiz edilir
    "/sitemap.xml",
    "/crossdomain.xml",
    "/config.php.bak",
    "/wp-config.php.bak",
]

# Dizin listeleme için kontrol edilecek yollar
_DIR_PATHS: list[str] = [
    "/images/", "/uploads/", "/backup/", "/files/",
    "/tmp/", "/temp/", "/logs/", "/data/",
    "/dvwa/hackable/uploads/",
]


class A05SecurityMisconfigurationModule(BaseModule):
    """OWASP A05:2021 – Security Misconfiguration tarayıcı modülü."""

    OWASP_ID = "A05"
    TITLE    = "Security Misconfiguration"

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
        self.logger.info("A05 Security Misconfiguration başlatılıyor → %s", self.target)
        base_resp = self._safe_get(self.target)
        if base_resp:
            self._check_security_headers(base_resp)
            self._check_server_version(base_resp)

        self._check_error_disclosure()
        self._check_directory_listing()
        self._check_sensitive_files()

        if self.enable_llm:
            self._enrich_with_llm()
        self.logger.info("A05 tamamlandı. %d bulgu.", len(self._findings))
        return self.get_findings()

    # ------------------------------------------------------------------
    # Güvenlik Başlıkları
    # ------------------------------------------------------------------

    def _check_security_headers(self, resp: requests.Response) -> None:
        """Yanıt başlıklarında eksik güvenlik direktiflerini bulur."""
        headers = {k.lower(): v for k, v in resp.headers.items()}
        missing: list[str] = []

        for header_name, severity, description in _SECURITY_HEADERS:
            if header_name.lower() not in headers:
                missing.append(header_name)
                self._add_finding(Finding(
                    owasp_id=self.OWASP_ID,
                    title=f"Güvenlik Yanlış Yapılandırması – Eksik Başlık: {header_name}",
                    url=self.target,
                    parameter=header_name,
                    payload="(başlık yok)",
                    method="GET",
                    response_snippet=f"'{header_name}' başlığı yanıtta bulunamadı. {description}",
                    confidence=Confidence.HIGH,
                    severity=severity,
                    raw_details={
                        "missing_header": header_name,
                        "description": description,
                        "headers_present": list(resp.headers.keys()),
                    },
                ))

        if missing:
            self.logger.info("Eksik güvenlik başlıkları: %s", missing)

    # ------------------------------------------------------------------
    # Sunucu Versiyon Sızıntısı
    # ------------------------------------------------------------------

    def _check_server_version(self, resp: requests.Response) -> None:
        """Server ve X-Powered-By başlıklarında versiyon bilgisi arar."""
        for hdr in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
            val = resp.headers.get(hdr, "")
            if not val:
                continue

            m = _VERSION_PATTERN.search(val)
            if m or any(c.isdigit() for c in val):
                self._add_finding(Finding(
                    owasp_id=self.OWASP_ID,
                    title=f"Güvenlik Yanlış Yapılandırması – Sunucu Versiyon Sızıntısı ({hdr})",
                    url=self.target,
                    parameter=hdr,
                    payload=val,
                    method="GET",
                    response_snippet=f"{hdr}: {val}",
                    confidence=Confidence.HIGH,
                    severity=Severity.LOW,
                    raw_details={
                        "header": hdr,
                        "value": val,
                        "version_detected": m.group(0) if m else val,
                    },
                ))

    # ------------------------------------------------------------------
    # Hata Sayfası Bilgi Sızıntısı
    # ------------------------------------------------------------------

    def _check_error_disclosure(self) -> None:
        """Hatalı istek ile stack trace / PHP hatası üretilip üretilmediğini test eder."""
        error_triggers = [
            f"{self.target}/?{{}}{{}}{{}}" ,
            f"{self.target}/nonexistent_page_zz99",
            f"{self.target}/index.php?id=INVALID_INPUT'",
        ]
        for url in error_triggers:
            resp = self._safe_get(url)
            if not resp:
                continue

            for sig in _ERROR_SIGNATURES:
                m = sig.search(resp.text)
                if m:
                    snippet = self._extract_context(resp.text, m.start())
                    self._add_finding(Finding(
                        owasp_id=self.OWASP_ID,
                        title="Güvenlik Yanlış Yapılandırması – Hata Mesajında Bilgi Sızıntısı",
                        url=url,
                        parameter="error_page",
                        payload=url,
                        method="GET",
                        response_snippet=snippet,
                        confidence=Confidence.HIGH,
                        severity=Severity.MEDIUM,
                        raw_details={
                            "signature": sig.pattern,
                            "status_code": resp.status_code,
                        },
                    ))
                    break  # URL başına tek bulgu

    # ------------------------------------------------------------------
    # Dizin Listeleme
    # ------------------------------------------------------------------

    def _check_directory_listing(self) -> None:
        """Dizin listeleme açık olan yolları tespit eder."""
        for path in _DIR_PATHS:
            url = urljoin(self.target + "/", path.lstrip("/"))
            resp = self._safe_get(url)
            if not resp or resp.status_code != 200:
                continue

            for pat in _DIR_LISTING_PATTERNS:
                if pat.search(resp.text):
                    self._add_finding(Finding(
                        owasp_id=self.OWASP_ID,
                        title="Güvenlik Yanlış Yapılandırması – Dizin Listeleme Açık",
                        url=url,
                        parameter="directory",
                        payload=path,
                        method="GET",
                        response_snippet=self._truncate_snippet(resp.text),
                        confidence=Confidence.HIGH,
                        severity=Severity.MEDIUM,
                        raw_details={
                            "pattern": pat.pattern,
                            "status_code": resp.status_code,
                        },
                    ))
                    break

    # ------------------------------------------------------------------
    # Hassas Dosya Erişimi
    # ------------------------------------------------------------------

    def _check_sensitive_files(self) -> None:
        """Kritik yapılandırma dosyalarının dışarıdan erişilebilir olup olmadığını test eder."""
        for path in _SENSITIVE_PATHS:
            url = urljoin(self.target + "/", path.lstrip("/"))
            resp = self._safe_get(url)
            if not resp:
                continue

            if resp.status_code == 200 and len(resp.content) > 10:
                # robots.txt: DISALLOW direktifleri bilgilendiricidir
                severity = Severity.INFO if path in ("/robots.txt", "/sitemap.xml") else Severity.HIGH
                confidence = Confidence.HIGH if path in ("/robots.txt", "/sitemap.xml") else Confidence.HIGH

                self._add_finding(Finding(
                    owasp_id=self.OWASP_ID,
                    title=f"Güvenlik Yanlış Yapılandırması – Hassas Dosya Erişilebilir: {path}",
                    url=url,
                    parameter="file_path",
                    payload=path,
                    method="GET",
                    response_snippet=self._truncate_snippet(resp.text),
                    confidence=confidence,
                    severity=severity,
                    raw_details={
                        "file": path,
                        "status_code": resp.status_code,
                        "content_length": len(resp.content),
                    },
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
        self.logger.info("A05 LLM zenginleştirme (%d bulgu)...", len(self._findings))
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
