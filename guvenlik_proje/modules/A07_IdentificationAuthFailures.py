"""
modules/A07_IdentificationAuthFailures.py

OWASP A07:2021 – Identification and Authentication Failures

Test stratejisi (tamamen statik analiz):
  Oturum Token Entropi Analizi:
    - Mevcut PHPSESSID / session cookie değerini entropik gücüne göre değerlendirir.
    - Tahmin edilebilir (kısa, sadece sayısal, artan) token'lar bulgu üretir.
  Çerez Güvenlik Bayrakları:
    - HttpOnly, Secure, SameSite bayrakları kontrol edilir.
  Kullanıcı Adı Numaralandırma:
    - Geçerli/geçersiz kullanıcı için farklı hata mesajı dönen formlar tespit edilir.
  Varsayılan/Zayıf Kimlik Bilgisi Testi:
    - DVWA ve yaygın uygulama varsayılan kimlik bilgileri denenir.
  URL'de Hassas Bilgi:
    - Token, oturum kimliği veya şifrenin URL parametresinde geçmesi kontrol edilir.
  Oturum Sabitlenmesi (Session Fixation):
    - Giriş öncesi ve sonrası oturum token'ının değişip değişmediği gözlemlenir.
"""

from __future__ import annotations

import math
import re
import string
from collections import Counter
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

from core.base_module import BaseModule, Finding, Confidence, Severity
from core.http_client import HTTPClient
from core.llm_client import LLMClient

# ---------------------------------------------------------------------------
# Varsayılan kimlik bilgileri listesi (DVWA + yaygın uygulamalar)
# ---------------------------------------------------------------------------

_DEFAULT_CREDENTIALS: List[tuple[str, str]] = [
    ("admin",        "admin"),
    ("admin",        "password"),
    ("admin",        "123456"),
    ("admin",        "password123"),
    ("administrator","administrator"),
    ("root",         "root"),
    ("root",         "toor"),
    ("user",         "user"),
    ("test",         "test"),
    ("guest",        "guest"),
    ("dvwa",         "dvwa"),
    ("admin",        ""),           # Boş şifre
]

# DVWA login endpoint
_DVWA_LOGIN_URL    = "/login.php"
_DVWA_LOGIN_PARAMS = {"username": "", "password": "", "Login": "Login"}

# Başarılı giriş göstergeleri (DVWA'ya özgü)
_LOGIN_SUCCESS_INDICATORS = [
    "welcome", "dashboard", "logout", "security level", "dvwa security",
]

# Oturum parametresi adları (URL'de olmamalı)
_SESSION_PARAM_NAMES = frozenset(
    ["session", "sessionid", "sessid", "token", "auth", "jwt", "access_token",
     "api_key", "password", "passwd", "pwd"]
)

# Numaralandırma hatası desenleri
_ENUM_USER_VALID    = re.compile(r"(invalid password|wrong password|incorrect password)", re.IGNORECASE)
_ENUM_USER_INVALID  = re.compile(r"(invalid username|user not found|unknown user|no account)", re.IGNORECASE)

_MIN_TOKEN_ENTROPY  = 3.5   # Shannon entropi eşiği (bit/karakter)
_MIN_TOKEN_LENGTH   = 16    # Güvenli minimum token uzunluğu


def _shannon_entropy(s: str) -> float:
    """Shannon entropisini hesaplar (bit/karakter)."""
    if not s:
        return 0.0
    freq = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


class A07IdentificationAuthFailuresModule(BaseModule):
    """OWASP A07:2021 – Identification and Authentication Failures tarayıcı modülü."""

    OWASP_ID = "A07"
    TITLE    = "Identification and Authentication Failures"

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
        self.logger.info("A07 Identification & Auth Failures başlatılıyor → %s", self.target)
        self._test_session_token_entropy()
        self._test_cookie_flags()
        self._test_url_sensitive_params()
        self._test_username_enumeration()
        self._test_default_credentials()
        self._test_session_fixation()
        if self.enable_llm:
            self._enrich_with_llm()
        self.logger.info("A07 tamamlandı. %d bulgu.", len(self._findings))
        return self.get_findings()

    # ------------------------------------------------------------------
    # Token Entropisi
    # ------------------------------------------------------------------

    def _test_session_token_entropy(self) -> None:
        """Session token'ın entropik gücünü analiz eder."""
        resp = self._safe_get(self.target)
        if not resp:
            return

        for cookie in resp.cookies:
            name_lower = cookie.name.lower()
            if not any(kw in name_lower for kw in ["sess", "session", "token", "auth", "id"]):
                continue

            value   = cookie.value
            length  = len(value)
            entropy = _shannon_entropy(value)

            issues: List[str] = []
            if length < _MIN_TOKEN_LENGTH:
                issues.append(f"Uzunluk çok kısa: {length} karakter (minimum {_MIN_TOKEN_LENGTH})")
            if entropy < _MIN_TOKEN_ENTROPY:
                issues.append(f"Entropi düşük: {entropy:.2f} bit/kar (minimum {_MIN_TOKEN_ENTROPY})")
            if value.isdigit():
                issues.append("Token tamamen sayısal – tahmin edilebilir")
            if re.match(r"^[0-9a-f]+$", value, re.IGNORECASE) and length < 24:
                issues.append("Kısa hex token – brute-force riski")

            if issues:
                self._add_finding(Finding(
                    owasp_id=self.OWASP_ID,
                    title=f"Kimlik Doğrulama Başarısızlığı – Zayıf Session Token ({cookie.name})",
                    url=self.target,
                    parameter=f"Cookie:{cookie.name}",
                    payload=f"{cookie.name}=***{value[-4:]}",
                    method="GET",
                    response_snippet=f"Sorunlar: {'; '.join(issues)}",
                    confidence=Confidence.MEDIUM,
                    severity=Severity.HIGH,
                    raw_details={
                        "cookie_name": cookie.name,
                        "token_length": length,
                        "shannon_entropy": round(entropy, 3),
                        "issues": issues,
                    },
                ))

    # ------------------------------------------------------------------
    # Çerez Güvenlik Bayrakları
    # ------------------------------------------------------------------

    def _test_cookie_flags(self) -> None:
        """Kimlik doğrulama çerezlerinde güvenlik bayraklarını kontrol eder."""
        resp = self._safe_get(self.target)
        if not resp:
            return

        for cookie in resp.cookies:
            name_lower = cookie.name.lower()
            if not any(kw in name_lower for kw in ["sess", "session", "token", "auth"]):
                continue

            issues: List[str] = []
            if not cookie.secure:
                issues.append("Secure bayrağı eksik – HTTP üzerinden çerez ifşa olabilir")

            # HttpOnly kontrolü (_rest dict)
            rest = getattr(cookie, "_rest", {})
            if "HttpOnly" not in str(rest) and not any("httponly" in str(k).lower() for k in rest):
                issues.append("HttpOnly bayrağı eksik – XSS ile çerez çalınabilir")

            samesite = rest.get("SameSite", "") if isinstance(rest, dict) else ""
            if not samesite:
                issues.append("SameSite bayrağı eksik – CSRF saldırısı riski")
            elif samesite.lower() == "none" and not cookie.secure:
                issues.append("SameSite=None fakat Secure bayrağı yok – geçersiz kombinasyon")

            if issues:
                self._add_finding(Finding(
                    owasp_id=self.OWASP_ID,
                    title=f"Kimlik Doğrulama Başarısızlığı – Güvensiz Çerez Bayrağı ({cookie.name})",
                    url=self.target,
                    parameter=f"Cookie:{cookie.name}",
                    payload=f"{cookie.name}=***",
                    method="GET",
                    response_snippet=f"Eksik bayraklar: {'; '.join(issues)}",
                    confidence=Confidence.HIGH,
                    severity=Severity.MEDIUM,
                    raw_details={
                        "cookie_name": cookie.name,
                        "secure": cookie.secure,
                        "missing_flags": issues,
                    },
                ))

    # ------------------------------------------------------------------
    # URL'de Hassas Parametre
    # ------------------------------------------------------------------

    def _test_url_sensitive_params(self) -> None:
        """GET parametrelerinde token/şifre adları geçip geçmediğini kontrol eder."""
        urls_to_check = [self.target] + [
            e.get("url", "") for e in self.shared_data.get("get_params", [])
        ]
        for url in urls_to_check:
            if not url:
                continue
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param_name in params:
                if param_name.lower() in _SESSION_PARAM_NAMES:
                    self._add_finding(Finding(
                        owasp_id=self.OWASP_ID,
                        title="Kimlik Doğrulama Başarısızlığı – Hassas Parametre URL'de",
                        url=url,
                        parameter=param_name,
                        payload=f"?{param_name}=***",
                        method="GET",
                        response_snippet=(
                            f"Oturum/kimlik bilgisi '{param_name}' GET parametresi olarak URL'de görünüyor. "
                            f"Sunucu logları, tarayıcı geçmişi ve Referer başlığı aracılığıyla sızabilir."
                        ),
                        confidence=Confidence.HIGH,
                        severity=Severity.HIGH,
                        raw_details={"sensitive_param": param_name, "full_url": url},
                    ))

    # ------------------------------------------------------------------
    # Kullanıcı Adı Numaralandırma
    # ------------------------------------------------------------------

    def _test_username_enumeration(self) -> None:
        """Geçerli/geçersiz kullanıcı için farklı hata mesajı tespiti."""
        login_url = urljoin(self.target + "/", _DVWA_LOGIN_URL.lstrip("/"))
        probe     = self._safe_get(login_url)
        if not probe or probe.status_code != 200:
            return

        # Geçersiz kullanıcı adı ile dene
        resp_invalid_user = self._safe_post(
            login_url,
            data={"username": "nonexistent_zzz_user", "password": "test", "Login": "Login"},
        )
        # Geçerli kullanıcı adı (DVWA default) ile dene
        resp_valid_user = self._safe_post(
            login_url,
            data={"username": "admin", "password": "wrong_pass_xyz", "Login": "Login"},
        )

        if not resp_invalid_user or not resp_valid_user:
            return

        inv_body  = resp_invalid_user.text.lower()
        val_body  = resp_valid_user.text.lower()
        # Mesajlar farklıysa numaralandırma mümkün
        if inv_body != val_body:
            has_enum_signal = (
                _ENUM_USER_VALID.search(val_body) or
                _ENUM_USER_INVALID.search(inv_body)
            )
            if has_enum_signal or abs(len(inv_body) - len(val_body)) > 30:
                self._add_finding(Finding(
                    owasp_id=self.OWASP_ID,
                    title="Kimlik Doğrulama Başarısızlığı – Kullanıcı Adı Numaralandırma",
                    url=login_url,
                    parameter="username",
                    payload="admin vs nonexistent_zzz_user",
                    method="POST",
                    response_snippet=(
                        f"Geçersiz kullanıcı yanıt uzunluğu: {len(inv_body)} | "
                        f"Geçerli kullanıcı yanıt uzunluğu: {len(val_body)}"
                    ),
                    confidence=Confidence.MEDIUM,
                    severity=Severity.MEDIUM,
                    raw_details={
                        "invalid_user_len": len(inv_body),
                        "valid_user_len": len(val_body),
                        "enum_signal_detected": bool(has_enum_signal),
                    },
                ))

    # ------------------------------------------------------------------
    # Varsayılan Kimlik Bilgileri
    # ------------------------------------------------------------------

    def _test_default_credentials(self) -> None:
        """Yaygın varsayılan kullanıcı/şifre kombinasyonlarını dener."""
        login_url = urljoin(self.target + "/", _DVWA_LOGIN_URL.lstrip("/"))
        probe     = self._safe_get(login_url)
        if not probe or probe.status_code != 200:
            return

        for username, password in _DEFAULT_CREDENTIALS:
            resp = self._safe_post(
                login_url,
                data={"username": username, "password": password, "Login": "Login"},
            )
            if not resp:
                continue

            body_lower = resp.text.lower()
            # Giriş başarılı mı?
            if any(ind in body_lower for ind in _LOGIN_SUCCESS_INDICATORS):
                self._add_finding(Finding(
                    owasp_id=self.OWASP_ID,
                    title="Kimlik Doğrulama Başarısızlığı – Varsayılan Kimlik Bilgisi Çalışıyor",
                    url=login_url,
                    parameter="username+password",
                    payload=f"{username}:{password}",
                    method="POST",
                    response_snippet=self._truncate_snippet(resp.text),
                    confidence=Confidence.HIGH,
                    severity=Severity.CRITICAL,
                    raw_details={
                        "username": username,
                        "password": "***",
                        "status_code": resp.status_code,
                        "final_url": resp.url,
                    },
                ))
                return  # İlk başarı yeterli

    # ------------------------------------------------------------------
    # Session Fixation
    # ------------------------------------------------------------------

    def _test_session_fixation(self) -> None:
        """Giriş öncesi ve sonrası session token'ının değişip değişmediğini kontrol eder."""
        login_url = urljoin(self.target + "/", _DVWA_LOGIN_URL.lstrip("/"))

        pre_resp = self._safe_get(login_url)
        if not pre_resp:
            return

        pre_token = pre_resp.cookies.get("PHPSESSID") or pre_resp.cookies.get("JSESSIONID")
        if not pre_token:
            return

        # Varsayılan DVWA kimlik bilgileriyle giriş yap
        post_resp = self._safe_post(
            login_url,
            data={"username": "admin", "password": "password", "Login": "Login"},
        )
        if not post_resp:
            return

        post_token = post_resp.cookies.get("PHPSESSID") or post_resp.cookies.get("JSESSIONID")

        # Giriş sonrası token değişmediyse → session fixation şüphesi
        if post_token and pre_token == post_token:
            self._add_finding(Finding(
                owasp_id=self.OWASP_ID,
                title="Kimlik Doğrulama Başarısızlığı – Session Fixation Şüphesi",
                url=login_url,
                parameter="PHPSESSID",
                payload=f"öncesi={pre_token[:8]}… sonrası={post_token[:8]}…",
                method="POST",
                response_snippet=(
                    "Giriş öncesi ve sonrası session token değişmedi. "
                    "Saldırgan önceden bildiği token'ı kurbanla paylaşarak oturum sabitleyebilir."
                ),
                confidence=Confidence.MEDIUM,
                severity=Severity.HIGH,
                raw_details={
                    "pre_login_token_prefix": pre_token[:8],
                    "post_login_token_prefix": post_token[:8],
                    "tokens_identical": True,
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
        self.logger.info("A07 LLM zenginleştirme (%d bulgu)...", len(self._findings))
        for finding in self._findings:
            try:
                finding.llm_analysis = self.llm.query(finding.to_dict())
            except Exception as exc:
                finding.llm_analysis = {"llm_hatasi": True, "hata_nedeni": str(exc)}
