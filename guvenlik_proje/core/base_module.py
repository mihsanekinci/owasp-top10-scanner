"""
core/base_module.py

Tüm OWASP modüllerinin türetileceği soyut temel sınıf ve Finding veri yapısı.

Tasarım kararları:
  - Finding bir dataclass'tır: tip güvencesi sağlar, to_dict() ile JSON'a dönüşür.
  - BaseModule ABC'dir: __init__, run(), _test_payloads() zorunlu imzaları tanımlar.
  - Modüller statik analiz yapar; LLM çağrısı orchestrator'a bırakılmıştır.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional

import requests

from core.http_client import HTTPClient

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

class Confidence(str, Enum):
    """Statik analiz tarafından atanan güven seviyesi."""
    HIGH   = "High"
    MEDIUM = "Medium"
    LOW    = "Low"
    INFO   = "Info"


class Severity(str, Enum):
    """Zafiyet ciddiyet sınıflandırması (LLM'den önce statik varsayılan)."""
    CRITICAL = "Kritik"
    HIGH     = "Yüksek"
    MEDIUM   = "Orta"
    LOW      = "Düşük"
    INFO     = "Bilgilendirici"


# ---------------------------------------------------------------------------
# Finding veri yapısı
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """
    Bir tespit edilen güvenlik bulgusunu temsil eder.

    Attributes:
        owasp_id         : OWASP Top 10 kimliği (örn. "A03").
        title            : Zafiyet başlığı (örn. "SQL Injection").
        url              : Zafiyetin gözlemlendiği URL.
        parameter        : Etkilenen parametre adı.
        payload          : Tespit için kullanılan payload.
        method           : HTTP metodu ("GET" veya "POST").
        response_snippet : Zafiyeti kanıtlayan yanıt parçası.
        confidence       : Statik analizin güven seviyesi.
        severity         : Ön değerlendirme ciddiyet seviyesi.
        raw_details      : Modüle özgü ek veriler.
        llm_analysis     : Tek LLM modundan dönen analiz (geriye dönük uyumluluk).
        llm_analyses     : Çoklu LLM modunda her modelin analizi
                           {"llama3": {...}, "qwen2.5:7b": {...}}.
        llm_comparison   : Çoklu LLM modunda özet karşılaştırma
                           (risk_consensus, risk_votes, ...).
        rag_used         : Bu bulguda RAG bağlamı kullanıldı mı?
        rag_sources      : Kullanılan knowledge base chunk kaynaklarının listesi.
    """
    owasp_id: str
    title: str
    url: str
    parameter: str
    payload: str
    method: str = "GET"
    response_snippet: str = ""
    confidence: Confidence = Confidence.MEDIUM
    severity: Severity = Severity.MEDIUM
    raw_details: Dict[str, Any] = field(default_factory=dict)
    llm_analysis: Optional[Dict[str, Any]] = field(default=None, repr=False)
    llm_analyses: Optional[Dict[str, Dict[str, Any]]] = field(default=None, repr=False)
    llm_comparison: Optional[Dict[str, Any]] = field(default=None, repr=False)
    rag_used: bool = False
    rag_sources: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Finding'i JSON-serileştirilebilir bir sözlüğe dönüştürür."""
        d = asdict(self)
        d["confidence"] = self.confidence.value
        d["severity"] = self.severity.value
        return d

    def summary(self) -> str:
        """Kısa okunabilir özet (loglama ve CLI çıktısı için)."""
        return (
            f"[{self.owasp_id}] {self.title} | "
            f"{self.method} {self.url} | "
            f"param={self.parameter!r} | "
            f"confidence={self.confidence.value}"
        )


# ---------------------------------------------------------------------------
# Soyut temel modül
# ---------------------------------------------------------------------------

class BaseModule(ABC):
    """
    Her OWASP modülünün uygulayacağı arayüz.

    Alt sınıflar:
      - __init__: target, http_client, shared_data parametrelerini alır.
      - run()   : Tüm testleri yürütür, Finding listesi döndürür.
      - _test_payloads(): Tek parametre için payload listesini test eder.

    Paylaşılan veriler (shared_data):
      Crawler çıktısı olan URL'ler, formlar ve parametreler bu sözlük
      üzerinden modüller arasında aktarılır.
    """

    # Alt sınıfın tanımlaması gereken sınıf sabitleri
    OWASP_ID: str = ""
    TITLE: str = ""

    def __init__(
        self,
        target: str,
        http_client: HTTPClient,
        shared_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Args:
            target     : Taranacak kök URL (örn. "http://localhost/dvwa").
            http_client: Paylaşılan HTTPClient örneği.
            shared_data: Crawler'dan gelen URL, form ve parametre verileri.
        """
        self.target = target.rstrip("/")
        self.http = http_client
        self.shared_data: Dict[str, Any] = shared_data or {}
        self._findings: List[Finding] = []
        self.logger = logging.getLogger(
            f"{self.__class__.__module__}.{self.__class__.__name__}"
        )

    # ------------------------------------------------------------------
    # Zorunlu arayüz (alt sınıflar implement eder)
    # ------------------------------------------------------------------

    @abstractmethod
    def run(self) -> List[Finding]:
        """
        Modüle ait tüm statik testleri çalıştırır.

        Returns:
            Tespit edilen Finding nesnelerinin listesi.
        """

    @abstractmethod
    def _test_payloads(
        self,
        url: str,
        param: str,
        payloads: List[str],
        method: str = "GET",
        base_data: Optional[Dict[str, str]] = None,
    ) -> List[requests.Response]:
        """
        Belirtilen URL ve parametre için payload listesini test eder.

        Args:
            url      : İstek gönderilecek endpoint.
            param    : Payload'ın enjekte edileceği parametre adı.
            payloads : Test edilecek payload dizeleri.
            method   : "GET" veya "POST".
            base_data: POST için temel form verisi (payload eklenmeden önce).

        Returns:
            Her payload için alınan Response nesnelerinin listesi.
        """

    # ------------------------------------------------------------------
    # Ortak yardımcı metodlar (alt sınıflar kullanabilir)
    # ------------------------------------------------------------------

    def _add_finding(self, finding: Finding) -> None:
        """Bulguyu iç listeye ekler ve loglar."""
        self._findings.append(finding)
        self.logger.info("Bulgu tespit edildi: %s", finding.summary())

    def _safe_get(self, url: str, params: Optional[Dict[str, Any]] = None) -> Optional[requests.Response]:
        """Hata yönetimli GET; exception fırlatmak yerine None döndürür."""
        try:
            return self.http.get(url, params=params)
        except Exception as exc:
            self.logger.debug("GET başarısız %s: %s", url, exc)
            return None

    def _safe_post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Optional[requests.Response]:
        """Hata yönetimli POST; exception fırlatmak yerine None döndürür."""
        try:
            return self.http.post(url, data=data)
        except Exception as exc:
            self.logger.debug("POST başarısız %s: %s", url, exc)
            return None

    def _truncate_snippet(self, text: str, max_len: int = 300) -> str:
        """Yanıt snippet'ini rapor için kırpar."""
        text = text.strip()
        return text[:max_len] + "…" if len(text) > max_len else text

    def get_findings(self) -> List[Finding]:
        """run() çağrısından sonra biriktirilen bulguları döndürür."""
        return list(self._findings)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(target={self.target!r})"
