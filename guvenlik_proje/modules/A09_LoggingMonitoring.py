"""
modules/A09_LoggingMonitoring.py

OWASP A09:2021 – Security Logging and Monitoring Failures

Test stratejisi (davranışsal gözlem + LLM destekli analiz):
  Stack Trace / Hata Detayı Sızıntısı:
    - Kasıtlı hatalı isteklerle PHP/Python/Java stack trace tetiklenir.
    - Bu bulgular hem A05 hem A09'u ilgilendirir; burada izleme açısından değerlendirilir.
  Yönetici Log Arayüzü Açığı:
    - /logs, /log, /audit, /access.log, /error.log gibi yaygın log yolları test edilir.
  Güvenlik Olayı Yanıt Mekanizması:
    - Ardışık başarısız giriş denemelerinde alarm/blok gelip gelmediği gözlemlenir.
  HTTP Durum Kodu İzleme Eksikliği:
    - 4xx/5xx yanıtlarının sunucu tarafında loglanıp loglanmadığı x-request-id
      veya benzeri başlık yokluğuyla tahmin edilir.
  LLM Odaklı Analiz:
    - Bu kategoride otomatik tespiti zor olan durumlar LLM'e açıklatılır.
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
# Sabitler
# ---------------------------------------------------------------------------

_LOG_PATHS: list[str] = [
    "/logs/", "/log/", "/logs/access.log", "/logs/error.log",
    "/access.log", "/error.log", "/debug.log", "/application.log",
    "/audit.log", "/audit/", "/audit-log/",
    "/admin/logs", "/management/logs",
    "/dvwa/php.ini",           # DVWA ortamına özgü
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
]

_ERROR_SIGNATURES: list[re.Pattern] = [
    re.compile(r"Fatal error.*on line \d+",           re.IGNORECASE),
    re.compile(r"Warning:.*in.*\.php on line",        re.IGNORECASE),
    re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE),
    re.compile(r"at .*\(.*\.java:\d+\)",              re.IGNORECASE),
    re.compile(r"Unhandled Exception:",               re.IGNORECASE),
    re.compile(r"NullPointerException",               re.IGNORECASE),
    re.compile(r"NameError:|AttributeError:",         re.IGNORECASE),
]

# Log başlıkları (izleme sağlıklıysa sunucunun göndermesi beklenir)
_MONITORING_HEADERS = ["X-Request-Id", "X-Trace-Id", "X-Correlation-Id", "X-Log-Id"]

# DVWA login endpoint (brute-force algılama testi için)
_DVWA_LOGIN_URL = "/login.php"

# Sunucu genelinde izleme açığı için LLM prompt şablonu
_LLM_STATIC_PROMPT_FINDING = {
    "owasp_id": "A09",
    "title": "Security Logging & Monitoring – Genel Değerlendirme",
    "url": "(genel)",
    "parameter": "(statik analiz)",
    "payload": "N/A",
    "response_snippet": (
        "Uygulama güvenlik olaylarını (başarısız giriş, yetkisiz erişim, hata) "
        "yeterince loglamamıyor olabilir. Otomatik test sınırlıdır; LLM değerlendirmesi isteniyor."
    ),
    "confidence": "Low",
}


class A09LoggingMonitoringModule(BaseModule):
    """OWASP A09:2021 – Security Logging and Monitoring Failures tarayıcı modülü."""

    OWASP_ID = "A09"
    TITLE    = "Security Logging and Monitoring Failures"

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
        self.logger.info("A09 Logging & Monitoring başlatılıyor → %s", self.target)
        self._check_error_disclosure()
        self._check_log_file_exposure()
        self._check_monitoring_headers()
        self._check_bruteforce_alerting()
        # NOT: LLM tespit kararı vermez (mimari karar) — kavramsal bulgu kaldırıldı.
        # LLM zenginleştirmesi artık orkestratörde merkezi olarak yapılıyor.
        self.logger.info("A09 tamamlandı. %d bulgu.", len(self._findings))
        return self.get_findings()

    # ------------------------------------------------------------------
    # Hata Sayfası – İzleme Açısından
    # ------------------------------------------------------------------

    def _check_error_disclosure(self) -> None:
        """Stack trace/hata detayı, izleme başarısızlığının da kanıtıdır."""
        error_urls = [
            f"{self.target}/nonexistent_zzz",
            f"{self.target}/?id='",
            f"{self.target}/index.php?INVALID=1",
        ]
        for url in error_urls:
            resp = self._safe_get(url)
            if not resp:
                continue

            for sig in _ERROR_SIGNATURES:
                m = sig.search(resp.text)
                if m:
                    snippet = self._extract_context(resp.text, m.start())
                    self._add_finding(Finding(
                        owasp_id=self.OWASP_ID,
                        title="Loglama Başarısızlığı – Hata Detayı Yanıtta Görünüyor",
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
                            "note": (
                                "Hata ayrıntılarının yanıtta görünmesi, sunucunun hata "
                                "olaylarını güvenli şekilde loglamadığının ve dışa sızdırmadığının kanıtıdır."
                            ),
                        },
                    ))
                    break

    # ------------------------------------------------------------------
    # Log Dosyası Erişimi
    # ------------------------------------------------------------------

    def _check_log_file_exposure(self) -> None:
        """Log dosyalarının dışarıdan erişilebilir olup olmadığını kontrol eder."""
        for path in _LOG_PATHS:
            url = urljoin(self.target + "/", path.lstrip("/"))
            resp = self._safe_get(url)
            if not resp or resp.status_code != 200 or len(resp.content) < 20:
                continue

            body_lower = resp.text.lower()
            # Gerçek log içeriği belirteci
            is_log = any(kw in body_lower for kw in [
                "get /", "post /", "http/1.", "[error]", "[warn]",
                "access log", "error log", "exception", "traceback",
            ])
            if is_log:
                self._add_finding(Finding(
                    owasp_id=self.OWASP_ID,
                    title=f"Loglama Başarısızlığı – Log Dosyası Dışarıdan Erişilebilir ({path})",
                    url=url,
                    parameter="file_path",
                    payload=path,
                    method="GET",
                    response_snippet=self._truncate_snippet(resp.text, max_len=300),
                    confidence=Confidence.HIGH,
                    severity=Severity.HIGH,
                    raw_details={
                        "log_path": path,
                        "status_code": resp.status_code,
                        "content_length": len(resp.content),
                    },
                ))

    # ------------------------------------------------------------------
    # İzleme Başlığı Yokluğu
    # ------------------------------------------------------------------

    def _check_monitoring_headers(self) -> None:
        """Request-id / trace-id başlığı yoksa izleme altyapısı eksik olabilir."""
        resp = self._safe_get(self.target)
        if not resp:
            return

        has_trace = any(
            h.lower() in {hdr.lower() for hdr in resp.headers}
            for h in _MONITORING_HEADERS
        )
        if not has_trace:
            self._add_finding(Finding(
                owasp_id=self.OWASP_ID,
                title="Loglama Başarısızlığı – İstek İzleme Başlığı (Request-ID) Yok",
                url=self.target,
                parameter=", ".join(_MONITORING_HEADERS),
                payload="(başlık yok)",
                method="GET",
                response_snippet=(
                    f"Yanıtta şu başlıklardan hiçbiri bulunamadı: {_MONITORING_HEADERS}. "
                    f"İzleme altyapısının eksik olabileceğine işaret eder."
                ),
                confidence=Confidence.LOW,
                severity=Severity.LOW,
                raw_details={
                    "checked_headers": _MONITORING_HEADERS,
                    "found": False,
                    "all_response_headers": list(resp.headers.keys()),
                },
            ))

    # ------------------------------------------------------------------
    # Brute-Force Olay Algılama
    # ------------------------------------------------------------------

    def _check_bruteforce_alerting(self) -> None:
        """Birden fazla başarısız giriş sonrası alarm/blok alınıp alınmadığını test eder."""
        login_url = urljoin(self.target + "/", _DVWA_LOGIN_URL.lstrip("/"))
        probe = self._safe_get(login_url)
        if not probe or probe.status_code != 200:
            return

        alert_detected = False
        for i in range(8):
            resp = self._safe_post(
                login_url,
                data={"username": "admin", "password": f"fail_{i}", "Login": "Login"},
            )
            if not resp:
                continue
            body_lower = resp.text.lower()
            if any(kw in body_lower for kw in [
                "too many", "account locked", "blocked", "suspended",
                "captcha", "unusual activity",
            ]):
                alert_detected = True
                self.logger.debug("Brute-force alarmı algılandı: deneme #%d", i + 1)
                break

        if not alert_detected:
            self._add_finding(Finding(
                owasp_id=self.OWASP_ID,
                title="Loglama Başarısızlığı – Brute-Force Saldırısı Algılanmıyor",
                url=login_url,
                parameter="password",
                payload="fail_0..fail_7 (8 başarısız giriş)",
                method="POST",
                response_snippet=(
                    "8 ardışık başarısız giriş denemesinde alarm, engelleme veya "
                    "CAPTCHA tetiklenmedi. Güvenlik olayları izlenmiyor olabilir."
                ),
                confidence=Confidence.MEDIUM,
                severity=Severity.MEDIUM,
                raw_details={
                    "attempts": 8,
                    "alert_detected": False,
                    "login_url": login_url,
                },
            ))

    # ------------------------------------------------------------------
    # Kavramsal LLM Bulgusu
    # ------------------------------------------------------------------

    def _add_conceptual_finding(self) -> None:
        """A09 için her zaman LLM'in değerlendireceği kavramsal bir bulgu ekler."""
        self._add_finding(Finding(
            owasp_id=self.OWASP_ID,
            title="Loglama Başarısızlığı – Kavramsal Değerlendirme (LLM Analizi)",
            url=self.target,
            parameter="(genel)",
            payload="N/A",
            method="GET",
            response_snippet=(
                "Uygulama güvenlik olaylarını (başarısız giriş, yetkisiz erişim, "
                "anormal trafik) yeterince loglamıyor ve izlemiyor olabilir. "
                "Otomatik test bu kategori için sınırlıdır; LLM değerlendirmesi eklendi."
            ),
            confidence=Confidence.LOW,
            severity=Severity.MEDIUM,
            raw_details={"type": "conceptual", "requires_manual_review": True},
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
        self.logger.info("A09 LLM zenginleştirme (%d bulgu)...", len(self._findings))
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

    def _truncate_snippet(self, text: str, max_len: int = 300) -> str:
        text = text.strip()
        return text[:max_len] + "…" if len(text) > max_len else text
