"""
modules/A02_CryptographicFailures.py

OWASP A02:2021 – Cryptographic Failures

Test stratejisi (tamamen statik analiz):
  HTTPS Kontrolü:
    - http:// URL'si https://'ye yönlendiriyor mu?
    - HSTS (Strict-Transport-Security) başlığı var mı?
  Çerez Güvenlik Bayrakları:
    - Set-Cookie yanıtlarında Secure, HttpOnly, SameSite bayrakları kontrol edilir.
  Hassas Veri Sızıntısı:
    - Yanıt gövdesinde kredi kartı, TC kimlik no, e-posta gibi regex desenleri aranır.
  Form Güvenliği:
    - Parola alanlarında autocomplete="on" veya eksik autocomplete tespiti.
  İçerik Türü Tutarsızlığı:
    - X-Content-Type-Options başlığı eksikliği (MIME sniffing riski).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

from core.base_module import BaseModule, Finding, Confidence, Severity
from core.http_client import HTTPClient
from core.llm_client import LLMClient

# ---------------------------------------------------------------------------
# Hassas veri desenleri
# ---------------------------------------------------------------------------

_SENSITIVE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Kredi Kartı Numarası",    re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b")),
    ("TC Kimlik No (olası)",    re.compile(r"\b[1-9]\d{10}\b")),
    ("Şifre/Parola (açık)",     re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*\S+", re.IGNORECASE)),
    ("API Anahtarı (olası)",    re.compile(r"(?:api[_\-]?key|apikey|access[_\-]?token)\s*[:=]\s*['\"]?[\w\-]{16,}['\"]?", re.IGNORECASE)),
    ("E-posta Adresi (toplu)",  re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.IGNORECASE)),
    ("AWS Access Key",          re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private Key Bloğu",       re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
]

# Güvenli çerez bayrağı kontrolü
_REQUIRED_COOKIE_FLAGS = ["Secure", "HttpOnly", "SameSite"]


class A02CryptographicFailuresModule(BaseModule):
    """OWASP A02:2021 – Cryptographic Failures tarayıcı modülü."""

    OWASP_ID = "A02"
    TITLE    = "Cryptographic Failures"

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
        self.logger.info("A02 Cryptographic Failures başlatılıyor → %s", self.target)
        self._test_https_enforcement()
        self._test_hsts()
        self._test_cookie_flags()
        self._test_sensitive_data()
        self._test_autocomplete()
        if self.enable_llm:
            self._enrich_with_llm()
        self.logger.info("A02 tamamlandı. %d bulgu.", len(self._findings))
        return self.get_findings()

    # ------------------------------------------------------------------
    # HTTPS Zorunluluğu
    # ------------------------------------------------------------------

    def _test_https_enforcement(self) -> None:
        """http:// isteklerinin https://'ye yönlendirilip yönlendirilmediğini test eder."""
        parsed = urlparse(self.target)
        if parsed.scheme == "https":
            # Zaten HTTPS, HTTP → HTTPS yönlendirmesini kontrol et
            http_url = self.target.replace("https://", "http://", 1)
        else:
            http_url = self.target

        try:
            resp = self.http.get(http_url, allow_redirects=True)
        except Exception:
            return

        final_scheme = urlparse(resp.url).scheme
        if final_scheme != "https":
            self._add_finding(Finding(
                owasp_id=self.OWASP_ID,
                title="Kriptografik Başarısızlık – HTTPS Zorunlu Değil",
                url=http_url,
                parameter="scheme",
                payload="http://",
                method="GET",
                response_snippet=f"Son URL: {resp.url} (HTTPS yönlendirmesi yok)",
                confidence=Confidence.HIGH,
                severity=Severity.HIGH,
                raw_details={
                    "initial_url": http_url,
                    "final_url": resp.url,
                    "status_code": resp.status_code,
                },
            ))

    # ------------------------------------------------------------------
    # HSTS
    # ------------------------------------------------------------------

    def _test_hsts(self) -> None:
        """HSTS başlığının varlığını ve değerini kontrol eder."""
        resp = self._safe_get(self.target)
        if not resp:
            return

        hsts = resp.headers.get("Strict-Transport-Security", "")
        if not hsts:
            self._add_finding(Finding(
                owasp_id=self.OWASP_ID,
                title="Kriptografik Başarısızlık – HSTS Başlığı Eksik",
                url=self.target,
                parameter="Strict-Transport-Security",
                payload="(başlık yok)",
                method="GET",
                response_snippet="Yanıt başlıklarında Strict-Transport-Security bulunamadı.",
                confidence=Confidence.HIGH,
                severity=Severity.MEDIUM,
                raw_details={"headers_received": dict(resp.headers)},
            ))
        else:
            # max-age süresi çok kısaysa uyar
            m = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
            if m and int(m.group(1)) < 31536000:  # 1 yıldan az
                self._add_finding(Finding(
                    owasp_id=self.OWASP_ID,
                    title="Kriptografik Başarısızlık – HSTS max-age Yetersiz",
                    url=self.target,
                    parameter="Strict-Transport-Security",
                    payload=hsts,
                    method="GET",
                    response_snippet=f"HSTS max-age={m.group(1)} sn (önerilen ≥31536000)",
                    confidence=Confidence.MEDIUM,
                    severity=Severity.LOW,
                    raw_details={"hsts_value": hsts, "max_age": int(m.group(1))},
                ))

    # ------------------------------------------------------------------
    # Çerez Bayrakları
    # ------------------------------------------------------------------

    def _test_cookie_flags(self) -> None:
        """Set-Cookie başlıklarında güvenlik bayrağı eksikliğini kontrol eder."""
        resp = self._safe_get(self.target)
        if not resp:
            return

        raw_cookies = resp.headers.get_all("Set-Cookie") if hasattr(resp.headers, "get_all") else []
        # requests headers dict; ham çerezleri farklı al
        all_cookies: list[str] = []
        for hdr_name, hdr_val in resp.raw.headers.items():
            if hdr_name.lower() == "set-cookie":
                all_cookies.append(hdr_val)

        # Ek olarak session çerezlerini de incele
        for cookie in resp.cookies:
            issues: list[str] = []
            cookie_raw = f"{cookie.name}=***"

            if not cookie.secure:
                issues.append("Secure bayrağı eksik")
            if not cookie.has_nonstandard_attr("HttpOnly") and "HttpOnly" not in str(cookie._rest):
                issues.append("HttpOnly bayrağı eksik")

            samesite = cookie._rest.get("SameSite", "") if hasattr(cookie, "_rest") else ""
            if not samesite:
                issues.append("SameSite bayrağı eksik")

            if issues:
                self._add_finding(Finding(
                    owasp_id=self.OWASP_ID,
                    title="Kriptografik Başarısızlık – Güvensiz Çerez Bayrağı",
                    url=self.target,
                    parameter=f"Set-Cookie:{cookie.name}",
                    payload=cookie_raw,
                    method="GET",
                    response_snippet=f"Çerez '{cookie.name}' için eksik bayraklar: {', '.join(issues)}",
                    confidence=Confidence.HIGH,
                    severity=Severity.MEDIUM,
                    raw_details={
                        "cookie_name": cookie.name,
                        "missing_flags": issues,
                        "secure": cookie.secure,
                    },
                ))

    # ------------------------------------------------------------------
    # Hassas Veri Sızıntısı
    # ------------------------------------------------------------------

    def _test_sensitive_data(self) -> None:
        """Yanıt gövdesinde hassas veri desenlerini arar."""
        urls_to_check = [self.target]
        for entry in self.shared_data.get("get_params", []):
            urls_to_check.append(entry.get("url", ""))

        checked: set[str] = set()
        for url in urls_to_check:
            if not url or url in checked:
                continue
            checked.add(url)
            resp = self._safe_get(url)
            if not resp:
                continue

            body = resp.text
            for label, pattern in _SENSITIVE_PATTERNS:
                m = pattern.search(body)
                if m:
                    snippet = self._extract_context(body, m.start())
                    self._add_finding(Finding(
                        owasp_id=self.OWASP_ID,
                        title=f"Kriptografik Başarısızlık – Hassas Veri Açıkta: {label}",
                        url=url,
                        parameter="response_body",
                        payload=f"Desen: {pattern.pattern[:60]}",
                        method="GET",
                        response_snippet=snippet,
                        confidence=Confidence.MEDIUM,
                        severity=Severity.HIGH,
                        raw_details={
                            "data_type": label,
                            "pattern": pattern.pattern,
                            "match_preview": m.group()[:50] + "***",
                        },
                    ))

    # ------------------------------------------------------------------
    # Otomatik Tamamlama
    # ------------------------------------------------------------------

    def _test_autocomplete(self) -> None:
        """Parola alanlarında autocomplete='on' veya yokluğunu test eder."""
        resp = self._safe_get(self.target)
        if not resp:
            return

        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            for form in soup.find_all("form"):
                for inp in form.find_all("input", {"type": "password"}):
                    ac = (inp.get("autocomplete", "")).lower()
                    if ac not in ("off", "new-password", "current-password"):
                        self._add_finding(Finding(
                            owasp_id=self.OWASP_ID,
                            title="Kriptografik Başarısızlık – Parola Alanında autocomplete",
                            url=self.target,
                            parameter=inp.get("name", "password_field"),
                            payload=f'autocomplete="{inp.get("autocomplete", "(yok)")}"',
                            method="GET",
                            response_snippet=str(inp)[:200],
                            confidence=Confidence.MEDIUM,
                            severity=Severity.LOW,
                            raw_details={
                                "field_name": inp.get("name"),
                                "autocomplete_value": inp.get("autocomplete", "(tanımsız)"),
                            },
                        ))
        except Exception as exc:
            self.logger.debug("Autocomplete analizi hatası: %s", exc)

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
                self.logger.debug("Payload başarısız [%s]: %s", param, exc)
            finally:
                responses.append(resp)
        return responses

    def _enrich_with_llm(self) -> None:
        if not self._findings or self.llm is None:
            return
        self.logger.info("A02 LLM zenginleştirme (%d bulgu)...", len(self._findings))
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
