"""
modules/A06_VulnerableComponents.py

OWASP A06:2021 – Vulnerable and Outdated Components

Test stratejisi (tamamen statik analiz):
  Sunucu Başlık Analizi:
    - Server, X-Powered-By, X-AspNet-Version başlıklarından versiyon çıkarılır.
    - Bilinen CVE sözlüğüyle eşleştirilir.
  JavaScript Kütüphane Tespiti:
    - HTML'deki <script src="..."> etiketlerinden kütüphane adı ve versiyonu çıkarılır.
    - jQuery, Bootstrap, Angular, React, Vue, Lodash, Moment.js kontrol edilir.
  PHP/CMS Versiyon Tespiti:
    - X-Powered-By, generator meta etiketi ve /readme.html gibi ipucu dosyaları.
  Bilinen Açık CVE Eşleştirmesi:
    - Basit bir yerel CVE sözlüğüyle kritik güvenlik açıkları vurgulanır.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from core.base_module import BaseModule, Finding, Confidence, Severity
from core.http_client import HTTPClient
from core.llm_client import LLMClient

# ---------------------------------------------------------------------------
# Bilinen güvenlik açıklı versiyon sözlüğü
# Format: {bileşen_anahtar: [(maks_güvensiz_versiyon, CVE_id, açıklama, ciddiyet)]}
# ---------------------------------------------------------------------------

_CVE_DB: Dict[str, List[Tuple[str, str, str, Severity]]] = {
    "jquery": [
        ("1.12.4", "CVE-2019-11358", "Prototype Pollution", Severity.HIGH),
        ("3.4.1",  "CVE-2020-11022", "XSS via HTML parsing", Severity.HIGH),
        ("3.4.1",  "CVE-2020-11023", "XSS via passing HTML with option elements", Severity.HIGH),
    ],
    "bootstrap": [
        ("3.4.0", "CVE-2019-8331", "XSS in data-template attribute", Severity.MEDIUM),
        ("4.3.1", "CVE-2019-8331", "XSS in tooltip/popover", Severity.MEDIUM),
    ],
    "angular": [
        ("1.7.9", "CVE-2019-14863", "XSS via ng-attr-srcdoc", Severity.HIGH),
    ],
    "lodash": [
        ("4.17.15", "CVE-2021-23337", "Command Injection", Severity.CRITICAL),
        ("4.17.15", "CVE-2020-8203",  "Prototype Pollution", Severity.HIGH),
    ],
    "moment": [
        ("2.29.1", "CVE-2022-24785", "Path Traversal", Severity.HIGH),
    ],
    "apache": [
        ("2.4.49", "CVE-2021-41773", "Path Traversal & RCE", Severity.CRITICAL),
        ("2.4.50", "CVE-2021-42013", "Path Traversal & RCE (bypass)", Severity.CRITICAL),
    ],
    "nginx": [
        ("1.17.6", "CVE-2019-20372", "HTTP Request Smuggling", Severity.MEDIUM),
    ],
    "php": [
        ("7.4.21", "CVE-2021-21702", "NULL Pointer Dereference", Severity.MEDIUM),
        ("8.0.8",  "CVE-2021-21704", "Multiple Bugs", Severity.MEDIUM),
    ],
}

# JS kütüphane adı tespiti için regex: (anahtar, desen)
_JS_LIB_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("jquery",    re.compile(r"jquery[.-](\d+\.\d+\.?\d*)(\.min)?\.js", re.IGNORECASE)),
    ("bootstrap", re.compile(r"bootstrap[.-](\d+\.\d+\.?\d*)(\.min)?\.(?:js|css)", re.IGNORECASE)),
    ("angular",   re.compile(r"angular[.-](\d+\.\d+\.?\d*)(\.min)?\.js", re.IGNORECASE)),
    ("react",     re.compile(r"react[.-](\d+\.\d+\.?\d*)(\.min)?\.js", re.IGNORECASE)),
    ("vue",       re.compile(r"vue[.-](\d+\.\d+\.?\d*)(\.min)?\.js", re.IGNORECASE)),
    ("lodash",    re.compile(r"lodash[.-](\d+\.\d+\.?\d*)(\.min)?\.js", re.IGNORECASE)),
    ("moment",    re.compile(r"moment[.-](\d+\.\d+\.?\d*)(\.min)?\.js", re.IGNORECASE)),
]

# Sunucu/platform versiyon deseni
_SERVER_VERSION_RE = re.compile(
    r"(apache|nginx|iis|php|tomcat|lighttpd|jetty)[/\s]+([\d]+\.[\d]+\.?[\d]*)",
    re.IGNORECASE,
)


def _version_tuple(v: str) -> Tuple[int, ...]:
    """Versiyon dizesini karşılaştırılabilir tuple'a çevirir."""
    try:
        return tuple(int(x) for x in re.split(r"[.\-]", v) if x.isdigit())
    except Exception:
        return (0,)


def _is_vulnerable(detected: str, max_vuln: str) -> bool:
    """detected versiyon max_vuln veya daha eski ise True döner."""
    return _version_tuple(detected) <= _version_tuple(max_vuln)


class A06VulnerableComponentsModule(BaseModule):
    """OWASP A06:2021 – Vulnerable and Outdated Components tarayıcı modülü."""

    OWASP_ID = "A06"
    TITLE    = "Vulnerable and Outdated Components"

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
        self.logger.info("A06 Vulnerable Components başlatılıyor → %s", self.target)
        resp = self._safe_get(self.target)
        if resp:
            self._check_server_headers(resp)
            self._check_js_libraries(resp)
            self._check_cms_version(resp)
        self._check_disclosure_files()
        if self.enable_llm:
            self._enrich_with_llm()
        self.logger.info("A06 tamamlandı. %d bulgu.", len(self._findings))
        return self.get_findings()

    # ------------------------------------------------------------------
    # Sunucu Başlık Analizi
    # ------------------------------------------------------------------

    def _check_server_headers(self, resp: requests.Response) -> None:
        """Server / X-Powered-By başlıklarından versiyon bilgisi çıkarır."""
        for hdr in ("Server", "X-Powered-By", "X-AspNet-Version"):
            val = resp.headers.get(hdr, "")
            if not val:
                continue

            m = _SERVER_VERSION_RE.search(val)
            if not m:
                # Versiyon yok ama başlık var → bilgilendirici
                self._add_finding(Finding(
                    owasp_id=self.OWASP_ID,
                    title=f"Güvenlik Açıklı Bileşen – Sunucu Bilgisi Sızıntısı ({hdr})",
                    url=self.target,
                    parameter=hdr,
                    payload=val,
                    method="GET",
                    response_snippet=f"{hdr}: {val}",
                    confidence=Confidence.LOW,
                    severity=Severity.INFO,
                    raw_details={"header": hdr, "value": val},
                ))
                continue

            component = m.group(1).lower()
            version   = m.group(2)
            self._match_cve(component, version, self.target, hdr, val)

    # ------------------------------------------------------------------
    # JavaScript Kütüphane Tespiti
    # ------------------------------------------------------------------

    def _check_js_libraries(self, resp: requests.Response) -> None:
        """HTML içindeki script/link src değerlerinden kütüphane versiyonu çıkarır."""
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception:
            return

        # script src ve link href
        srcs: List[str] = []
        for tag in soup.find_all(["script", "link"]):
            src = tag.get("src") or tag.get("href") or ""
            if src:
                srcs.append(src)

        # İnline script içinde version string'leri de ara
        for script in soup.find_all("script"):
            if script.string:
                for lib_key, pat in _JS_LIB_PATTERNS:
                    m = pat.search(script.string)
                    if m:
                        srcs.append(f"inline:{lib_key}-{m.group(1)}.js")

        found_libs: Dict[str, str] = {}
        for src in srcs:
            for lib_key, pat in _JS_LIB_PATTERNS:
                m = pat.search(src)
                if m and lib_key not in found_libs:
                    found_libs[lib_key] = m.group(1)

        for lib_key, version in found_libs.items():
            self._match_cve(lib_key, version, self.target, "script/link src", lib_key)

    # ------------------------------------------------------------------
    # CMS Versiyon Tespiti
    # ------------------------------------------------------------------

    def _check_cms_version(self, resp: requests.Response) -> None:
        """Meta generator ve tipik CMS yollarından versiyon tespiti yapar."""
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            gen = soup.find("meta", attrs={"name": "generator"})
            if gen:
                content = gen.get("content", "")
                m = re.search(r"(WordPress|Drupal|Joomla)[/\s]+([\d.]+)", content, re.IGNORECASE)
                if m:
                    cms     = m.group(1).lower()
                    version = m.group(2)
                    self._add_finding(Finding(
                        owasp_id=self.OWASP_ID,
                        title=f"Güvenlik Açıklı Bileşen – CMS Versiyon Tespiti ({m.group(1)})",
                        url=self.target,
                        parameter="meta[generator]",
                        payload=content,
                        method="GET",
                        response_snippet=f"generator={content}",
                        confidence=Confidence.HIGH,
                        severity=Severity.MEDIUM,
                        raw_details={"cms": cms, "version": version},
                    ))
        except Exception as exc:
            self.logger.debug("CMS tespiti hatası: %s", exc)

    # ------------------------------------------------------------------
    # Versiyon Açıklama Dosyaları
    # ------------------------------------------------------------------

    def _check_disclosure_files(self) -> None:
        """readme.html, CHANGELOG gibi versiyon bilgisi sızdıran dosyaları dener."""
        paths = [
            "/readme.html", "/readme.txt", "/CHANGELOG.md",
            "/CHANGELOG.txt", "/version.txt", "/package.json",
            "/composer.json",
        ]
        for path in paths:
            url = urljoin(self.target + "/", path.lstrip("/"))
            resp = self._safe_get(url)
            if not resp or resp.status_code != 200:
                continue
            body = resp.text[:1000]
            # Basit versiyon deseni ara
            m = re.search(r'(?:version|ver|v)["\s:=]+(\d+\.\d+[\d.]*)', body, re.IGNORECASE)
            if m:
                self._add_finding(Finding(
                    owasp_id=self.OWASP_ID,
                    title=f"Güvenlik Açıklı Bileşen – Versiyon Dosyası Erişilebilir ({path})",
                    url=url,
                    parameter="file",
                    payload=path,
                    method="GET",
                    response_snippet=self._truncate_snippet(body, max_len=200),
                    confidence=Confidence.HIGH,
                    severity=Severity.LOW,
                    raw_details={"version_found": m.group(1), "file": path},
                ))

    # ------------------------------------------------------------------
    # CVE Eşleştirme
    # ------------------------------------------------------------------

    def _match_cve(
        self,
        component: str,
        version: str,
        url: str,
        parameter: str,
        payload: str,
    ) -> None:
        """Bileşen ve versiyonu CVE sözlüğüyle eşleştirir."""
        entries = _CVE_DB.get(component, [])
        for max_vuln_ver, cve_id, description, severity in entries:
            if _is_vulnerable(version, max_vuln_ver):
                self._add_finding(Finding(
                    owasp_id=self.OWASP_ID,
                    title=f"Güvenlik Açıklı Bileşen – {component.title()} {version} ({cve_id})",
                    url=url,
                    parameter=parameter,
                    payload=payload,
                    method="GET",
                    response_snippet=(
                        f"Bileşen: {component} v{version} | "
                        f"CVE: {cve_id} | Açıklama: {description} | "
                        f"Güvenli versiyon: > {max_vuln_ver}"
                    ),
                    confidence=Confidence.HIGH,
                    severity=severity,
                    raw_details={
                        "component": component,
                        "detected_version": version,
                        "max_vulnerable_version": max_vuln_ver,
                        "cve_id": cve_id,
                        "cve_description": description,
                    },
                ))
                break  # Bileşen başına en kritik CVE yeterli

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
        self.logger.info("A06 LLM zenginleştirme (%d bulgu)...", len(self._findings))
        for finding in self._findings:
            try:
                finding.llm_analysis = self.llm.query(finding.to_dict())
            except Exception as exc:
                finding.llm_analysis = {"llm_hatasi": True, "hata_nedeni": str(exc)}

    # ------------------------------------------------------------------
    # Yardımcılar
    # ------------------------------------------------------------------

    def _truncate_snippet(self, text: str, max_len: int = 300) -> str:
        text = text.strip()
        return text[:max_len] + "…" if len(text) > max_len else text
