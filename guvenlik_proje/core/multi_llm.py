"""
core/multi_llm.py

Çoklu LLM orkestratörü.

Sorumluluklar:
  - Birden fazla Ollama modelini paralel olarak sorgulamak.
  - Her bulgu için her modelin yorumunu toplayıp tek bir dict olarak döndürmek.
  - Modellerden biri erişilemezse veya hata verirse, diğerlerini etkilememek.
  - Opsiyonel RAG bağlamını her modele tutarlı şekilde geçirmek.

Tasarım kararları:
  - ThreadPoolExecutor kullanıldı: Ollama I/O bound (network bekleme), GIL sorun değil.
  - Her model için ayrı LLMClient instance tutulur (timeout, base_url paylaşılır).
  - Modellerin healthcheck'i bir kez yapılır, başarısız olanlar listeden çıkarılır.
  - Yanıtlar `{model_adi: yorum_dict}` formatında dönülür.
"""

from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

import requests

from core.llm_client import LLMClient

logger = logging.getLogger(__name__)

_OLLAMA_BASE_URL = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
_DEFAULT_TIMEOUT = 180       # CPU'da llama3 + RAG context ~60-120s sürebiliyor
_DEFAULT_MAX_WORKERS = 2     # Aynı anda en fazla N model sorgusu (CPU boğmasın)


class MultiLLMClient:
    """
    Birden fazla Ollama modelini yöneten istemci.

    Kullanım:
        multi = MultiLLMClient(["llama3", "qwen2.5:7b", "mistral"])
        sonuc = multi.query_all(finding, rag_context="...")
        # sonuc == {"llama3": {...}, "qwen2.5:7b": {...}, "mistral": {...}}

    Attributes:
        models     : İstenen model adlarının listesi.
        clients    : Erişilebilir modeller için LLMClient sözlüğü.
        base_url   : Ollama sunucusu.
        max_workers: Paralel sorgu sayısı.
    """

    def __init__(
        self,
        models: List[str],
        base_url: str = _OLLAMA_BASE_URL,
        timeout: int = _DEFAULT_TIMEOUT,
        max_workers: int = _DEFAULT_MAX_WORKERS,
        skip_unavailable: bool = True,
    ) -> None:
        """
        Args:
            models           : Sorgulanacak Ollama model adları.
            base_url         : Ollama API URL'si.
            timeout          : Her model için sorgu zaman aşımı.
            max_workers      : Aynı anda kaç model sorgulanacak.
            skip_unavailable : True ise erişilemeyen modeller sessizce atlanır.
        """
        self.models = models
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_workers = max(1, min(max_workers, len(models)))
        self.skip_unavailable = skip_unavailable

        self.clients: Dict[str, LLMClient] = {}
        self._initialize_clients()

    # ------------------------------------------------------------------
    # İstemci kurulumu
    # ------------------------------------------------------------------

    def _initialize_clients(self) -> None:
        """Her model için LLMClient kurar, erişilemeyenleri atlar."""
        available = self._list_available_models()

        for model in self.models:
            # Ollama bazen "llama3" ile "llama3:latest"i farklı listeleyebilir
            if available and not self._is_model_available(model, available):
                if self.skip_unavailable:
                    logger.warning(
                        "Model '%s' Ollama'da bulunamadı, atlanıyor. "
                        "Kurulum: `ollama pull %s`",
                        model,
                        model,
                    )
                    continue
                else:
                    logger.warning(
                        "Model '%s' Ollama'da yok ama yine de denenecek.", model
                    )
            self.clients[model] = LLMClient(
                model=model,
                base_url=self.base_url,
                timeout=self.timeout,
            )

        if not self.clients:
            logger.warning(
                "Hiçbir LLM modeli erişilebilir değil. MultiLLM devre dışı kalacak."
            )

    def _list_available_models(self) -> List[str]:
        """Ollama'da yüklü model adlarını döndürür. Erişilemezse boş liste."""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=5)
            resp.raise_for_status()
            return [m.get("name", "") for m in resp.json().get("models", [])]
        except requests.exceptions.RequestException as exc:
            logger.warning("Ollama model listesi alınamadı: %s", exc)
            return []

    @staticmethod
    def _is_model_available(requested: str, available: List[str]) -> bool:
        """
        'llama3' istendiğinde 'llama3:latest' de eşleşmeli;
        'qwen2.5:7b' istendiğinde tam eşleşme aranmalı.
        """
        if requested in available:
            return True
        # Tag belirtilmediyse :latest ile de eşleşebilir
        if ":" not in requested:
            return any(name.split(":")[0] == requested for name in available)
        return False

    # ------------------------------------------------------------------
    # Durum
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """En az bir model kullanılabilir mi?"""
        return len(self.clients) > 0

    def active_models(self) -> List[str]:
        """Sorgulanabilen modellerin listesi."""
        return list(self.clients.keys())

    # ------------------------------------------------------------------
    # Sorgulama
    # ------------------------------------------------------------------

    def query_all(
        self,
        finding: Dict[str, Any],
        rag_context: str = "",
    ) -> Dict[str, Dict[str, Any]]:
        """
        Tüm aktif modelleri paralel olarak sorgular.

        Args:
            finding    : Finding.to_dict() çıktısı.
            rag_context: LLMClient.query()'ye geçilecek bağlam metni.

        Returns:
            {model_adi: llm_yanit_dict} sözlüğü. Hata veren modellerin
            yanıtlarında `llm_hatasi: True` olur (LLMClient güvenli varsayılanı).
        """
        if not self.is_available():
            return {}

        results: Dict[str, Dict[str, Any]] = {}

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_model = {
                executor.submit(
                    self._safe_query, model, client, finding, rag_context
                ): model
                for model, client in self.clients.items()
            }
            for future in as_completed(future_to_model):
                model = future_to_model[future]
                try:
                    results[model] = future.result()
                except Exception as exc:
                    logger.error("Model %s sorgusunda hata: %s", model, exc)
                    results[model] = {
                        "risk_seviyesi": "Bilinmiyor",
                        "teknik_aciklama": f"Model sorgusu başarısız: {exc}",
                        "kod_duzeltme": "—",
                        "genel_onlemler": [],
                        "llm_guven": "Düşük",
                        "llm_hatasi": True,
                        "hata_nedeni": str(exc),
                    }

        return results

    @staticmethod
    def _safe_query(
        model: str,
        client: LLMClient,
        finding: Dict[str, Any],
        rag_context: str,
    ) -> Dict[str, Any]:
        """LLMClient.query çağrısını sarar (worker thread içinde)."""
        logger.debug("Model sorgulanıyor: %s", model)
        # LLMClient.query'nin rag_context parametresini destekleyip desteklemediğini kontrol et
        # (Aşama 4'te eklenecek; şimdilik try/except ile geriye dönük uyumluluk)
        try:
            return client.query(finding, rag_context=rag_context)  # type: ignore[call-arg]
        except TypeError:
            # Eski LLMClient imzası (rag_context parametresi yok)
            return client.query(finding)

    # ------------------------------------------------------------------
    # Yardımcı: özet karşılaştırma
    # ------------------------------------------------------------------

    @staticmethod
    def summarize_comparison(
        analyses: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Çoklu LLM yanıtlarından özet karşılaştırma üretir.

        Returns:
            {
              "models_queried": ["llama3", ...],
              "risk_consensus": "Yüksek" | "Belirsiz",  (çoğunluk oyu)
              "risk_votes": {"Yüksek": 2, "Orta": 1},
              "all_risks": {"llama3": "Yüksek", ...},
              "error_count": 0,
            }
        """
        if not analyses:
            return {"models_queried": [], "risk_consensus": "Bilinmiyor"}

        risk_votes: Dict[str, int] = {}
        all_risks: Dict[str, str] = {}
        error_count = 0

        for model, analysis in analyses.items():
            risk = analysis.get("risk_seviyesi", "Bilinmiyor")
            all_risks[model] = risk
            if analysis.get("llm_hatasi"):
                error_count += 1
                continue
            risk_votes[risk] = risk_votes.get(risk, 0) + 1

        if risk_votes:
            consensus = max(risk_votes.items(), key=lambda x: x[1])[0]
        else:
            consensus = "Belirsiz"

        return {
            "models_queried": list(analyses.keys()),
            "risk_consensus": consensus,
            "risk_votes": risk_votes,
            "all_risks": all_risks,
            "error_count": error_count,
        }

    def __repr__(self) -> str:
        return (
            f"MultiLLMClient(models={list(self.clients.keys())}, "
            f"base_url={self.base_url!r})"
        )


# ---------------------------------------------------------------------------
# Modül seviyesi yardımcı: Ollama'daki tüm yüklü modelleri listele
# ---------------------------------------------------------------------------

def list_ollama_models(base_url: str = _OLLAMA_BASE_URL) -> List[Dict[str, Any]]:
    """
    Ollama'da yüklü tüm modellerin meta bilgilerini döndürür.
    Web UI'nin dropdown'unu doldurmak için kullanılır.

    Returns:
        [{"name": "llama3:latest", "size": 4661211808, "modified_at": "..."}]
    """
    try:
        resp = requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=5)
        resp.raise_for_status()
        models = resp.json().get("models", [])
        return [
            {
                "name": m.get("name", ""),
                "size": m.get("size", 0),
                "modified_at": m.get("modified_at", ""),
            }
            for m in models
        ]
    except requests.exceptions.RequestException as exc:
        logger.warning("Ollama modelleri listelenemedi: %s", exc)
        return []
