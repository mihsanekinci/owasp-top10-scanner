"""
modules/A03_Injection.py

OWASP A03:2021 – Injection (SQL Injection + Cross-Site Scripting)

Test stratejisi (tamamen statik analiz):
  SQLi:
    - Hata bazlı: yanıt gövdesinde SQL hata deseni aranır.
    - Zaman bazlı: SLEEP/WAITFOR ile yanıt süresi ölçülür (blind).
  XSS:
    - Yansıtılan: payload yanıtta birebir görünüyor mu?
    - Event-handler: <img onerror=...> tarzı vektörler.

LLM entegrasyonu:
  Tespit sonrası her Finding için llm_client.query(finding.to_dict())
  çağrılır. LLM asla tespit kararı vermez; yalnızca analiz zenginleştirir.
"""

from __future__ import annotations

import re
import time
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import requests
from bs4 import BeautifulSoup

from core.base_module import BaseModule, Finding, Confidence, Severity
from core.http_client import HTTPClient
from core.llm_client import LLMClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SQL Injection – tespit desenleri
# ---------------------------------------------------------------------------

_SQLI_ERROR_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"you have an error in your sql syntax",
        r"warning.*mysql.*",
        r"unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"sql syntax.*near",
        r"pg_query\(\).*failed",
        r"ORA-\d{5}",
        r"Microsoft OLE DB Provider for SQL Server",
        r"Incorrect syntax near",
        r"sqlite3\.OperationalError",
        r"psycopg2\.ProgrammingError",
    ]
]

_SQLI_PAYLOADS: list[str] = [
    "'",                          # Temel hata tetikleyici
    "' OR '1'='1",               # Classic bypass
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1",
    "1 AND 1=2",                  # Boolean-bazlı
    "1' AND SLEEP(4) --",        # Zaman-bazlı (MySQL)
    "1'; WAITFOR DELAY '0:0:4' --",  # Zaman-bazlı (MSSQL)
    "' UNION SELECT NULL --",     # UNION keşif
]

_SQLI_TIME_THRESHOLD = 3.5  # saniye; bu süre aşılırsa zaman bazlı SQLi şüphesi

# ---------------------------------------------------------------------------
# XSS – payload ve tespit
# ---------------------------------------------------------------------------

_XSS_PAYLOADS: list[str] = [
    "<script>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "'><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
    "<%00script>alert(1)</%00script>",  # Null-byte bypass denemesi
]


class A03InjectionModule(BaseModule):
    """
    OWASP A03:2021 – Injection tarayıcı modülü.

    Desteklenen test vektörleri:
      - GET parametreleri (URL sorgu dizesi)
      - POST form alanları (HTML form tespiti ile)
    """

    OWASP_ID = "A03"
    TITLE = "Injection (SQLi & XSS)"

    def __init__(
        self,
        target: str,
        http_client: HTTPClient,
        shared_data: Optional[Dict[str, Any]] = None,
        llm_client: Optional[LLMClient] = None,
        enable_llm: bool = True,
    ) -> None:
        """
        Args:
            llm_client : LLM entegrasyonu için istemci (None → LLM atlanır).
            enable_llm : False ise bulgu zenginleştirmesi yapılmaz.
        """
        super().__init__(target, http_client, shared_data)
        self.llm = llm_client
        self.enable_llm = enable_llm and (llm_client is not None)

    # ------------------------------------------------------------------
    # Ana orkestrasyon
    # ------------------------------------------------------------------

    def run(self) -> List[Finding]:
        """
        Tüm SQLi ve XSS testlerini yürütür.

        İş akışı:
          1. Taranacak endpoint'leri topla (shared_data veya hedef URL).
          2. Her endpoint için SQLi testlerini çalıştır.
          3. Her endpoint için XSS testlerini çalıştır.
          4. Opsiyonel: LLM ile bulguları zenginleştir.
        """
        self.logger.info("A03 Injection modülü başlatılıyor → %s", self.target)
        endpoints = self._collect_endpoints()

        for url, param, method, base_data in endpoints:
            self._run_sqli(url, param, method, base_data)
            self._run_xss(url, param, method, base_data)

        if self.enable_llm:
            self._enrich_with_llm()

        self.logger.info(
            "A03 tamamlandı. %d bulgu tespit edildi.", len(self._findings)
        )
        return self.get_findings()

    # ------------------------------------------------------------------
    # Endpoint toplama
    # ------------------------------------------------------------------

    def _collect_endpoints(self) -> List[tuple[str, str, str, Dict[str, str]]]:
        """
        Test edilecek (url, parametre, method, base_data) demetlerini üretir.

        Önce shared_data'daki crawler çıktısına bakar.
        Yoksa hedef URL'yi doğrudan tarar.
        """
        endpoints: List[tuple[str, str, str, Dict[str, str]]] = []

        # Crawler verisi varsa kullan
        crawler_forms: list = self.shared_data.get("forms", [])
        crawler_params: list = self.shared_data.get("get_params", [])

        for entry in crawler_params:
            url = entry.get("url", "")
            for param in entry.get("params", []):
                endpoints.append((url, param, "GET", {}))

        for form in crawler_forms:
            action = form.get("action", self.target)
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])
            base_data = {inp: "test" for inp in inputs if inp}
            for inp in inputs:
                if inp:
                    endpoints.append((action, inp, method, base_data.copy()))

        # Crawler verisi yoksa hedef URL'yi analiz et
        if not endpoints:
            endpoints.extend(self._discover_from_target())

        return endpoints

    # DVWA ve yaygın test ortamları için bilinen zafiyetli path'ler.
    # Crawler yoksa A03 bu sayfaları otomatik dener — kara kutu tarama için
    # makul varsayılan davranış.
    _COMMON_INJECTION_PATHS: List[tuple[str, str, str]] = [
        # path, param, method
        ("vulnerabilities/sqli/",            "id",       "GET"),
        ("vulnerabilities/sqli_blind/",      "id",       "GET"),
        ("vulnerabilities/xss_r/",           "name",     "GET"),
        ("vulnerabilities/xss_s/",           "txtName",  "POST"),
        ("vulnerabilities/xss_d/",           "default",  "GET"),
        ("vulnerabilities/exec/",            "ip",       "POST"),
        ("vulnerabilities/brute/",           "username", "GET"),
        # Juice Shop tipik query parametreleri
        ("rest/products/search",             "q",        "GET"),
        # Genel
        ("search",                           "q",        "GET"),
        ("search.php",                       "q",        "GET"),
        ("index.php",                        "id",       "GET"),
    ]

    def _discover_from_target(self) -> List[tuple[str, str, str, Dict[str, str]]]:
        """Hedef URL'yi GET ile çeker, formları ve GET parametrelerini çıkarır."""
        results: List[tuple[str, str, str, Dict[str, str]]] = []
        response = self._safe_get(self.target)
        if not response:
            return results

        # GET parametreleri
        parsed = urlparse(self.target)
        get_params = parse_qs(parsed.query)
        for param in get_params:
            results.append((self.target, param, "GET", {}))

        # HTML formları
        try:
            soup = BeautifulSoup(response.text, "html.parser")
            for form in soup.find_all("form"):
                raw_action = form.get("action", "")
                action = urljoin(self.target, raw_action) if raw_action else self.target
                method = (form.get("method", "GET") or "GET").upper()
                inputs = [
                    inp.get("name", "")
                    for inp in form.find_all("input")
                    if inp.get("name")
                ]
                base_data = {inp: "test" for inp in inputs}
                for inp in inputs:
                    results.append((action, inp, method, base_data.copy()))
        except Exception as exc:
            self.logger.debug("Form ayrıştırma hatası: %s", exc)

        # Yaygın zafiyetli path'leri otomatik dene (DVWA/Juice Shop/genel)
        # Sadece şu durumda eklenir:
        #   - 200 OK döner ve
        #   - login/redirect sayfasına yönlendirmemiştir.
        for path, param, method in self._COMMON_INJECTION_PATHS:
            url = urljoin(self.target + "/", path)
            probe = self._safe_get(url)
            if probe is None or probe.status_code >= 400:
                continue
            # Login veya error sayfasına yönlendirildiyse (DVWA için tipik) atla
            final_url = (probe.url or "").lower()
            if any(skip in final_url for skip in ("login.php", "login.html", "signin", "/auth")):
                self.logger.debug("A03: %s -> login redirect, atlanıyor", url)
                continue
            if method == "GET":
                results.append((url, param, "GET", {}))
            else:
                results.append((url, param, "POST", {param: "test"}))
            self.logger.debug("A03: erişilebilir endpoint eklendi: %s (%s)", url, param)

        # Hâlâ hiç parametre bulunamazsa hedef URL'yi direkt dene
        if not results:
            self.logger.warning(
                "Hedef URL'de GET parametresi veya form bulunamadı. "
                "Doğrudan hedef test edilecek."
            )
            results.append((self.target, "id", "GET", {}))

        return results

    # ------------------------------------------------------------------
    # SQL Injection testleri
    # ------------------------------------------------------------------

    def _run_sqli(
        self,
        url: str,
        param: str,
        method: str,
        base_data: Dict[str, str],
    ) -> None:
        """Belirtilen uç nokta için SQLi payload listesini test eder."""
        self.logger.debug("SQLi test: %s %s [param=%s]", method, url, param)
        responses = self._test_payloads(url, param, _SQLI_PAYLOADS, method, base_data)

        for payload, response in zip(_SQLI_PAYLOADS, responses):
            if response is None:
                continue

            finding = self._analyze_sqli_response(url, param, payload, response)
            if finding:
                self._add_finding(finding)

    def _analyze_sqli_response(
        self,
        url: str,
        param: str,
        payload: str,
        response: requests.Response,
    ) -> Optional[Finding]:
        """
        Yanıtı statik olarak analiz eder.

        Tespit mekanizmaları:
          1. Hata bazlı: bilinen SQL hata desenleri.
          2. Zaman bazlı: response.elapsed süresi eşiği aşıyor mu?
        """
        body = response.text

        # 1) Hata bazlı SQLi
        for pattern in _SQLI_ERROR_PATTERNS:
            match = pattern.search(body)
            if match:
                snippet = self._extract_context(body, match.start())
                return Finding(
                    owasp_id=self.OWASP_ID,
                    title="SQL Injection (Error-Based)",
                    url=url,
                    parameter=param,
                    payload=payload,
                    method=response.request.method if response.request else "GET",
                    response_snippet=snippet,
                    confidence=Confidence.HIGH,
                    severity=Severity.HIGH,
                    raw_details={
                        "pattern_matched": pattern.pattern,
                        "status_code": response.status_code,
                    },
                )

        # 2) Zaman bazlı SQLi (yalnızca SLEEP/WAITFOR payload'ları için)
        if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
            elapsed = response.elapsed.total_seconds()
            if elapsed >= _SQLI_TIME_THRESHOLD:
                return Finding(
                    owasp_id=self.OWASP_ID,
                    title="SQL Injection (Time-Based Blind)",
                    url=url,
                    parameter=param,
                    payload=payload,
                    method=response.request.method if response.request else "GET",
                    response_snippet=f"Yanıt süresi: {elapsed:.2f}s (eşik: {_SQLI_TIME_THRESHOLD}s)",
                    confidence=Confidence.MEDIUM,
                    severity=Severity.HIGH,
                    raw_details={
                        "elapsed_seconds": elapsed,
                        "threshold": _SQLI_TIME_THRESHOLD,
                        "status_code": response.status_code,
                    },
                )

        return None

    # ------------------------------------------------------------------
    # XSS testleri
    # ------------------------------------------------------------------

    def _run_xss(
        self,
        url: str,
        param: str,
        method: str,
        base_data: Dict[str, str],
    ) -> None:
        """Belirtilen uç nokta için XSS payload listesini test eder."""
        self.logger.debug("XSS test: %s %s [param=%s]", method, url, param)
        responses = self._test_payloads(url, param, _XSS_PAYLOADS, method, base_data)

        for payload, response in zip(_XSS_PAYLOADS, responses):
            if response is None:
                continue

            finding = self._analyze_xss_response(url, param, payload, response)
            if finding:
                self._add_finding(finding)

    def _analyze_xss_response(
        self,
        url: str,
        param: str,
        payload: str,
        response: requests.Response,
    ) -> Optional[Finding]:
        """
        Yanıtta payload'ın yansıtılıp yansıtılmadığını kontrol eder.

        Tespit mantığı:
          - Payload birebir yanıtta görünüyorsa → High confidence.
          - Payload'ın kritik parçaları (script, onerror) görünüyorsa → Medium.
        """
        body = response.text
        content_type = response.headers.get("Content-Type", "")

        # HTML olmayan yanıtlarda XSS pratikte mümkün değildir
        if "text/html" not in content_type and "application/xhtml" not in content_type:
            return None

        # Yüksek güven: payload olduğu gibi yansıtıldı
        if payload in body:
            idx = body.find(payload)
            snippet = self._extract_context(body, idx, window=200)
            return Finding(
                owasp_id=self.OWASP_ID,
                title="Cross-Site Scripting (Reflected XSS)",
                url=url,
                parameter=param,
                payload=payload,
                method=response.request.method if response.request else "GET",
                response_snippet=snippet,
                confidence=Confidence.HIGH,
                severity=Severity.HIGH,
                raw_details={
                    "reflected": True,
                    "status_code": response.status_code,
                    "content_type": content_type,
                },
            )

        # Orta güven: payload kodlanmış ama tehlikeli token'lar hâlâ yanıtta
        dangerous_tokens = ["<script", "onerror=", "onload=", "javascript:"]
        for token in dangerous_tokens:
            if token.lower() in body.lower():
                idx = body.lower().find(token.lower())
                snippet = self._extract_context(body, idx, window=200)
                return Finding(
                    owasp_id=self.OWASP_ID,
                    title="Cross-Site Scripting (Reflected – Partial)",
                    url=url,
                    parameter=param,
                    payload=payload,
                    method=response.request.method if response.request else "GET",
                    response_snippet=snippet,
                    confidence=Confidence.MEDIUM,
                    severity=Severity.MEDIUM,
                    raw_details={
                        "token_found": token,
                        "status_code": response.status_code,
                    },
                )

        return None

    # ------------------------------------------------------------------
    # Zorunlu arayüz implementasyonu
    # ------------------------------------------------------------------

    def _test_payloads(
        self,
        url: str,
        param: str,
        payloads: List[str],
        method: str = "GET",
        base_data: Optional[Dict[str, str]] = None,
    ) -> List[Optional[requests.Response]]:
        """
        Her payload için HTTP isteği atar ve yanıt listesi döndürür.

        GET isteklerinde payload sorgu parametresi olarak gönderilir.
        POST isteklerinde form verisi olarak gönderilir.
        """
        responses: List[Optional[requests.Response]] = []
        base = base_data.copy() if base_data else {}

        for payload in payloads:
            response: Optional[requests.Response] = None
            try:
                if method == "POST":
                    data = {**base, param: payload}
                    response = self.http.post(url, data=data)
                else:
                    params = {**{k: v for k, v in base.items() if k != param}, param: payload}
                    response = self.http.get(url, params=params)
            except Exception as exc:
                self.logger.debug(
                    "Payload isteği başarısız [%s=%r]: %s", param, payload[:30], exc
                )
            finally:
                responses.append(response)

        return responses

    # ------------------------------------------------------------------
    # LLM zenginleştirme
    # ------------------------------------------------------------------

    def _enrich_with_llm(self) -> None:
        """Her Finding için LLM analizi çeker ve bulguya ekler."""
        if not self._findings:
            return

        self.logger.info(
            "LLM zenginleştirme başlatılıyor (%d bulgu)...", len(self._findings)
        )
        for finding in self._findings:
            try:
                analysis = self.llm.query(finding.to_dict())
                finding.llm_analysis = analysis
                self.logger.debug(
                    "LLM analizi tamamlandı: %s → risk=%s",
                    finding.title,
                    analysis.get("risk_seviyesi", "?"),
                )
            except Exception as exc:
                self.logger.warning("LLM zenginleştirme başarısız (%s): %s", finding.title, exc)
                finding.llm_analysis = {"llm_hatasi": True, "hata_nedeni": str(exc)}

    # ------------------------------------------------------------------
    # Yardımcı metodlar
    # ------------------------------------------------------------------

    def _extract_context(self, text: str, pos: int, window: int = 150) -> str:
        """Metinden belirli bir konumun çevresindeki bağlam penceresini döndürür."""
        start = max(0, pos - window // 2)
        end = min(len(text), pos + window // 2)
        snippet = text[start:end].strip()
        if start > 0:
            snippet = "…" + snippet
        if end < len(text):
            snippet = snippet + "…"
        return snippet
