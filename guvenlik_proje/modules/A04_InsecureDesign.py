"""
modules/A04_InsecureDesign.py

OWASP A04:2021 – Insecure Design

Test stratejisi (statik analiz + davranışsal gözlem):
  Hız Sınırı (Rate Limiting):
    - Aynı endpoint'e 25 ardışık istek gönderilir.
    - 429 / 503 dönmüyorsa ve hesap kilitlenmiyorsa bulgu oluşturulur.
    - DVWA /vulnerabilities/brute/ varsayılan hedef.
  CAPTCHA Yokluğu:
    - Login, kayıt ve yorum formlarında reCAPTCHA / hCaptcha varlığı kontrol edilir.
  Brute-Force Koruması:
    - 10 başarısız giriş denemesi sonrası hesap kilidi kontrol edilir.
  İş Mantığı (Kavramsal):
    - Negatif miktar, sıfır fiyat gibi uç değerlerin form kabul durumu test edilir.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from core.base_module import BaseModule, Finding, Confidence, Severity
from core.http_client import HTTPClient
from core.llm_client import LLMClient

_RATE_LIMIT_REQUEST_COUNT = 25
_RATE_LIMIT_WINDOW_SEC    = 5      # 25 istek / 5 saniye = 5 req/s
_CAPTCHA_KEYWORDS = [
    "recaptcha", "hcaptcha", "g-recaptcha", "captcha",
    "turnstile", "challenge", "cf-turnstile",
]

# DVWA brute-force formu POST alanları
_DVWA_BRUTE_URL    = "/vulnerabilities/brute/"
_DVWA_BRUTE_PARAMS = {"username": "admin", "password": "wrong_pass", "Login": "Login"}

# Genel login formu tespiti
_LOGIN_FORM_INDICATORS = ["login", "signin", "sign-in", "auth", "session"]

# İş mantığı: uç değer payload'ları
_BOUNDARY_PAYLOADS = ["-1", "0", "99999999", "1.0e308", "' OR 1=1 --"]


class A04InsecureDesignModule(BaseModule):
    """OWASP A04:2021 – Insecure Design tarayıcı modülü."""

    OWASP_ID = "A04"
    TITLE    = "Insecure Design"

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
        self.logger.info("A04 Insecure Design başlatılıyor → %s", self.target)
        self._test_rate_limiting()
        self._test_captcha_absence()
        self._test_bruteforce_protection()
        self._test_boundary_values()
        if self.enable_llm:
            self._enrich_with_llm()
        self.logger.info("A04 tamamlandı. %d bulgu.", len(self._findings))
        return self.get_findings()

    # ------------------------------------------------------------------
    # Rate Limiting
    # ------------------------------------------------------------------

    def _test_rate_limiting(self) -> None:
        """Endpoint'e ardışık istek atarak hız sınırı varlığını ölçer."""
        # Önce DVWA brute endpoint'ini dene, yoksa ana hedefi kullan
        brute_url = urljoin(self.target + "/", _DVWA_BRUTE_URL.lstrip("/"))
        probe = self._safe_get(brute_url)
        test_url = brute_url if (probe and probe.status_code == 200) else self.target

        rate_limited = False
        statuses: list[int] = []
        start = time.monotonic()

        for i in range(_RATE_LIMIT_REQUEST_COUNT):
            resp = self._safe_get(test_url)
            if resp:
                statuses.append(resp.status_code)
                if resp.status_code in (429, 503):
                    rate_limited = True
                    self.logger.debug("Rate limit algılandı: istek #%d → %d", i + 1, resp.status_code)
                    break

        elapsed = time.monotonic() - start

        if not rate_limited:
            self._add_finding(Finding(
                owasp_id=self.OWASP_ID,
                title="Güvensiz Tasarım – Rate Limiting Yok",
                url=test_url,
                parameter="request_rate",
                payload=f"{_RATE_LIMIT_REQUEST_COUNT} istek / {elapsed:.1f}s",
                method="GET",
                response_snippet=(
                    f"{_RATE_LIMIT_REQUEST_COUNT} ardışık istek gönderildi, "
                    f"hiç 429/503 alınmadı. "
                    f"Durum kodları: {set(statuses)}"
                ),
                confidence=Confidence.HIGH,
                severity=Severity.MEDIUM,
                raw_details={
                    "requests_sent": _RATE_LIMIT_REQUEST_COUNT,
                    "elapsed_sec": round(elapsed, 2),
                    "status_codes": statuses,
                    "rate_limited": False,
                },
            ))

    # ------------------------------------------------------------------
    # CAPTCHA Yokluğu
    # ------------------------------------------------------------------

    def _test_captcha_absence(self) -> None:
        """Login ve kayıt formlarında CAPTCHA kontrolü yapar."""
        # Kontrol edilecek URL'ler
        candidate_urls = [self.target]
        for suffix in ["/login", "/login.php", "/register", "/signup", "/contact"]:
            candidate_urls.append(urljoin(self.target + "/", suffix.lstrip("/")))

        for entry in self.shared_data.get("forms", []):
            action = entry.get("action", "")
            if any(kw in action.lower() for kw in _LOGIN_FORM_INDICATORS):
                candidate_urls.append(action)

        checked: set[str] = set()
        for url in candidate_urls:
            if url in checked:
                continue
            checked.add(url)
            resp = self._safe_get(url)
            if not resp or resp.status_code != 200:
                continue

            body_lower = resp.text.lower()
            # Sayfa login/kayıt formu mu?
            is_auth_page = any(kw in body_lower for kw in _LOGIN_FORM_INDICATORS)
            has_captcha  = any(kw in body_lower for kw in _CAPTCHA_KEYWORDS)

            if is_auth_page and not has_captcha:
                self._add_finding(Finding(
                    owasp_id=self.OWASP_ID,
                    title="Güvensiz Tasarım – Kimlik Doğrulama Formunda CAPTCHA Yok",
                    url=url,
                    parameter="form",
                    payload="(CAPTCHA kontrolü)",
                    method="GET",
                    response_snippet=self._truncate_snippet(resp.text, max_len=200),
                    confidence=Confidence.MEDIUM,
                    severity=Severity.MEDIUM,
                    raw_details={
                        "captcha_keywords_checked": _CAPTCHA_KEYWORDS,
                        "auth_page_detected": True,
                        "status_code": resp.status_code,
                    },
                ))

    # ------------------------------------------------------------------
    # Brute-Force Koruması
    # ------------------------------------------------------------------

    def _test_bruteforce_protection(self) -> None:
        """10 başarısız giriş denemesinde hesap kilitlenmesini kontrol eder."""
        brute_url = urljoin(self.target + "/", _DVWA_BRUTE_URL.lstrip("/"))
        probe = self._safe_get(brute_url)
        if not probe or probe.status_code not in (200,):
            self.logger.debug("DVWA brute-force endpoint erişilemez: %s", brute_url)
            return

        lockout_detected = False
        for attempt in range(10):
            params = {**_DVWA_BRUTE_PARAMS, "password": f"wrongpass_{attempt}"}
            resp = self._safe_get(brute_url, params=params)
            if not resp:
                continue

            body_lower = resp.text.lower()
            if any(kw in body_lower for kw in ["account locked", "too many", "blocked", "suspended"]):
                lockout_detected = True
                break

        if not lockout_detected:
            self._add_finding(Finding(
                owasp_id=self.OWASP_ID,
                title="Güvensiz Tasarım – Brute-Force Koruması Yok (Hesap Kilitleme)",
                url=brute_url,
                parameter="password",
                payload="wrongpass_0..wrongpass_9",
                method="GET",
                response_snippet="10 başarısız giriş denemesinde hesap kilitleme mekanizması tespit edilmedi.",
                confidence=Confidence.HIGH,
                severity=Severity.HIGH,
                raw_details={
                    "attempts": 10,
                    "lockout_detected": False,
                    "endpoint": brute_url,
                },
            ))

    # ------------------------------------------------------------------
    # İş Mantığı – Sınır Değer Testi
    # ------------------------------------------------------------------

    def _test_boundary_values(self) -> None:
        """Sayısal form alanlarına uç değer payload'u gönderir."""
        numeric_params = []
        for entry in self.shared_data.get("get_params", []):
            for param in entry.get("params", []):
                if param.lower() in ("qty", "quantity", "amount", "price", "count", "num"):
                    numeric_params.append((entry["url"], param, "GET", {}))

        for form in self.shared_data.get("forms", []):
            for inp in form.get("inputs", []):
                if inp.lower() in ("qty", "quantity", "amount", "price", "count"):
                    numeric_params.append((form.get("action", self.target), inp, form.get("method", "GET").upper(), {}))

        for url, param, method, base in numeric_params:
            responses = self._test_payloads(url, param, _BOUNDARY_PAYLOADS, method, base)
            for payload, resp in zip(_BOUNDARY_PAYLOADS, responses):
                if resp is None:
                    continue
                # Negatif/sıfır değer sunucudan hata değil 200 dönüyorsa şüpheli
                if resp.status_code == 200 and payload in ("-1", "0"):
                    self._add_finding(Finding(
                        owasp_id=self.OWASP_ID,
                        title="Güvensiz Tasarım – Sınır Değer İş Mantığı Hatası",
                        url=url,
                        parameter=param,
                        payload=payload,
                        method=method,
                        response_snippet=self._truncate_snippet(resp.text),
                        confidence=Confidence.LOW,
                        severity=Severity.MEDIUM,
                        raw_details={
                            "boundary_value": payload,
                            "status_code": resp.status_code,
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
        self.logger.info("A04 LLM zenginleştirme (%d bulgu)...", len(self._findings))
        for finding in self._findings:
            try:
                finding.llm_analysis = self.llm.query(finding.to_dict())
            except Exception as exc:
                finding.llm_analysis = {"llm_hatasi": True, "hata_nedeni": str(exc)}
