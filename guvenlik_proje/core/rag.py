"""
core/rag.py

Retrieval-Augmented Generation (RAG) bilgi tabanı.

Sorumluluklar:
  - knowledge/*.md dosyalarını başlık bazlı chunk'lara böler.
  - Her chunk için Ollama'nın `nomic-embed-text` modeli ile embedding üretir.
  - ChromaDB persistent collection'a kaydeder.
  - Bir Finding verildiğinde en alakalı K chunk'ı geri döndürür.

Tasarım kararları:
  - Embedding modeli olarak `nomic-embed-text` (Ollama) seçildi: yerel, ücretsiz,
    çok dilli (Türkçe + İngilizce kod örnekleriyle iyi çalışıyor).
  - Chunk stratejisi: markdown ## başlıklarına göre böl, çok uzun olanı 800 token civarı
    parçalara ayır. Başlık her chunk'a prefix olarak eklenir → embedding zenginleşir.
  - Persistence: ./rag_db dizininde tutulur, ikinci çalıştırmadan itibaren indexleme atlanır.
  - Hash-based change detection: dosyalar değişmemişse re-index yok.

LLM'i bu bilgilerle besleyerek model, bulguya özel önlem önerileri ve CWE eşlemeleri
yapabilir hale gelir.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

_OLLAMA_BASE_URL = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
_DEFAULT_EMBED_MODEL = "nomic-embed-text"
_DEFAULT_COLLECTION = "owasp_knowledge"
_DEFAULT_DB_PATH = "./rag_db"
_MAX_CHUNK_CHARS = 2000  # ~500 token; başlık + içerik
_MIN_CHUNK_CHARS = 80    # bu kadar küçük chunk'ları atla


# ---------------------------------------------------------------------------
# Veri yapıları
# ---------------------------------------------------------------------------

@dataclass
class Chunk:
    """Knowledge base'deki bir parçayı temsil eder."""
    id: str
    text: str
    source: str       # dosya adı (örn. "A03_injection.md")
    owasp_id: str     # "A03" gibi
    section: str      # "Önlemler", "Güvenli Kod Örnekleri" gibi


# ---------------------------------------------------------------------------
# Ollama embedding istemcisi
# ---------------------------------------------------------------------------

class OllamaEmbedder:
    """Ollama /api/embeddings endpoint'i ile embedding üretir."""

    def __init__(
        self,
        model: str = _DEFAULT_EMBED_MODEL,
        base_url: str = _OLLAMA_BASE_URL,
        timeout: int = 30,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._url = f"{self.base_url}/api/embeddings"

    def embed(self, text: str) -> Optional[List[float]]:
        """Tek bir metin için embedding döndürür. Hata durumunda None."""
        try:
            response = requests.post(
                self._url,
                json={"model": self.model, "prompt": text},
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()
            embedding = data.get("embedding")
            if not embedding:
                logger.warning("Ollama embedding boş döndü.")
                return None
            return embedding
        except requests.exceptions.RequestException as exc:
            logger.warning("Ollama embedding hatası: %s", exc)
            return None

    def embed_batch(self, texts: List[str]) -> List[Optional[List[float]]]:
        """Sırayla embedding üretir (Ollama batch desteklemiyor)."""
        return [self.embed(t) for t in texts]

    def health_check(self) -> bool:
        """Embedding modelinin yüklü ve erişilebilir olduğunu doğrular."""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=3)
            if resp.status_code != 200:
                return False
            models = [m.get("name", "") for m in resp.json().get("models", [])]
            # "nomic-embed-text" veya "nomic-embed-text:latest" gibi eşleşmeler
            return any(self.model in name for name in models)
        except requests.exceptions.RequestException:
            return False


# ---------------------------------------------------------------------------
# Markdown chunk'lama
# ---------------------------------------------------------------------------

def chunk_markdown(text: str, source_file: str, owasp_id: str) -> List[Chunk]:
    """
    Markdown'u ## başlıklarına göre böler. Uzun bölümleri _MAX_CHUNK_CHARS'a göre
    paragraf sınırından alt-chunk'lara ayırır. Her chunk başlığı kendi metnine
    ön ek olarak alır (embedding kalitesini artırır).
    """
    # Önce H2 (##) başlıklarına göre böl
    sections = re.split(r"\n(?=##\s)", text)
    chunks: List[Chunk] = []
    chunk_counter = 0

    for section in sections:
        section = section.strip()
        if len(section) < _MIN_CHUNK_CHARS:
            continue

        # Başlığı çıkar
        first_line = section.split("\n", 1)[0]
        section_title = re.sub(r"^#+\s*", "", first_line).strip()

        # Çok uzunsa paragraf sınırlarından böl
        if len(section) <= _MAX_CHUNK_CHARS:
            sub_texts = [section]
        else:
            sub_texts = _split_long_section(section, _MAX_CHUNK_CHARS)

        for sub in sub_texts:
            chunk_id = f"{owasp_id}_{chunk_counter:03d}"
            # Embedding kalitesi için OWASP ID ve bölüm başlığını metne ekle
            enriched = f"[{owasp_id} – {section_title}]\n{sub}"
            chunks.append(
                Chunk(
                    id=chunk_id,
                    text=enriched,
                    source=source_file,
                    owasp_id=owasp_id,
                    section=section_title,
                )
            )
            chunk_counter += 1

    return chunks


def _split_long_section(text: str, max_chars: int) -> List[str]:
    """Uzun bölümü paragraf sınırlarından böler."""
    paragraphs = text.split("\n\n")
    chunks: List[str] = []
    current: List[str] = []
    current_len = 0

    for para in paragraphs:
        para_len = len(para) + 2  # +2 newline
        if current_len + para_len > max_chars and current:
            chunks.append("\n\n".join(current))
            current = [para]
            current_len = para_len
        else:
            current.append(para)
            current_len += para_len

    if current:
        chunks.append("\n\n".join(current))
    return chunks


# ---------------------------------------------------------------------------
# Knowledge base
# ---------------------------------------------------------------------------

class KnowledgeBase:
    """
    OWASP knowledge base'i indexleyen ve sorgulanabilir hale getiren sınıf.

    Kullanım:
        kb = KnowledgeBase(knowledge_dir="./knowledge")
        if kb.is_available():
            chunks = kb.retrieve("SQL injection in login form", k=3)
            for c in chunks:
                print(c.text)
    """

    def __init__(
        self,
        knowledge_dir: str = "./knowledge",
        db_path: str = _DEFAULT_DB_PATH,
        collection_name: str = _DEFAULT_COLLECTION,
        embedder: Optional[OllamaEmbedder] = None,
    ) -> None:
        self.knowledge_dir = Path(knowledge_dir)
        self.db_path = Path(db_path)
        self.collection_name = collection_name
        self.embedder = embedder or OllamaEmbedder()
        self._client: Any = None
        self._collection: Any = None
        self._available = False
        self._init_chroma()

    # ------------------------------------------------------------------
    # Başlatma
    # ------------------------------------------------------------------

    def _init_chroma(self) -> None:
        """ChromaDB persistent client'ı kurar ve indexlemeyi başlatır."""
        try:
            import chromadb  # type: ignore
            from chromadb.config import Settings  # type: ignore
        except ImportError:
            logger.warning(
                "chromadb kurulu değil. RAG devre dışı. "
                "Kurulum: pip install chromadb"
            )
            return

        if not self.embedder.health_check():
            logger.warning(
                "Embedding modeli (%s) Ollama'da bulunamadı. "
                "Kurulum: `ollama pull %s`. RAG devre dışı.",
                self.embedder.model,
                self.embedder.model,
            )
            return

        self.db_path.mkdir(parents=True, exist_ok=True)
        try:
            self._client = chromadb.PersistentClient(
                path=str(self.db_path),
                settings=Settings(anonymized_telemetry=False),
            )
            self._collection = self._client.get_or_create_collection(
                name=self.collection_name,
                metadata={"description": "OWASP Top 10 knowledge base"},
            )
            self._available = True
        except Exception as exc:
            logger.warning("ChromaDB başlatılamadı: %s. RAG devre dışı.", exc)
            return

        # Knowledge dizininin durumunu kontrol et; değişiklik varsa re-index
        if self._needs_reindex():
            self.index()
        else:
            logger.info(
                "RAG hazır — knowledge base güncel (%d chunk).",
                self._collection.count(),
            )

    def is_available(self) -> bool:
        """RAG kullanılabilir mi (ChromaDB + embedder + index hazır mı)?"""
        return self._available and self._collection is not None

    # ------------------------------------------------------------------
    # Re-index gerekiyor mu? (basit hash kontrolü)
    # ------------------------------------------------------------------

    def _knowledge_fingerprint(self) -> str:
        """Tüm knowledge dosyalarının içeriğinin tek hash'i."""
        if not self.knowledge_dir.exists():
            return ""
        hasher = hashlib.sha256()
        for md_file in sorted(self.knowledge_dir.glob("*.md")):
            hasher.update(md_file.name.encode())
            hasher.update(md_file.read_bytes())
        return hasher.hexdigest()

    def _fingerprint_path(self) -> Path:
        return self.db_path / ".knowledge_fingerprint"

    def _needs_reindex(self) -> bool:
        current = self._knowledge_fingerprint()
        if not current:
            return False  # knowledge dizini yok, indexlenecek bir şey de yok
        if self._collection.count() == 0:
            return True
        fp_file = self._fingerprint_path()
        if not fp_file.exists():
            return True
        stored = fp_file.read_text(encoding="utf-8").strip()
        return stored != current

    def _save_fingerprint(self) -> None:
        self._fingerprint_path().write_text(
            self._knowledge_fingerprint(), encoding="utf-8"
        )

    # ------------------------------------------------------------------
    # Indexleme
    # ------------------------------------------------------------------

    def index(self) -> int:
        """
        knowledge/ dizinindeki tüm .md dosyalarını indexler.
        Returns: indexlenen chunk sayısı.
        """
        if not self.is_available_for_index():
            return 0

        if not self.knowledge_dir.exists():
            logger.warning("Knowledge dizini bulunamadı: %s", self.knowledge_dir)
            return 0

        # Mevcut koleksiyonu temizle (re-index için)
        try:
            existing_ids = self._collection.get()["ids"]
            if existing_ids:
                self._collection.delete(ids=existing_ids)
        except Exception as exc:
            logger.warning("Mevcut chunk'lar temizlenirken hata: %s", exc)

        all_chunks: List[Chunk] = []
        for md_file in sorted(self.knowledge_dir.glob("*.md")):
            owasp_id = self._extract_owasp_id(md_file.name)
            content = md_file.read_text(encoding="utf-8")
            chunks = chunk_markdown(content, md_file.name, owasp_id)
            all_chunks.extend(chunks)
            logger.debug("%s → %d chunk", md_file.name, len(chunks))

        if not all_chunks:
            logger.warning("Indexlenecek chunk bulunamadı.")
            return 0

        logger.info(
            "RAG indexleme başladı: %d chunk, embedding modeli: %s",
            len(all_chunks),
            self.embedder.model,
        )

        # Embedding'leri tek tek üret (Ollama batch desteklemiyor)
        embeddings: List[List[float]] = []
        valid_chunks: List[Chunk] = []
        for i, chunk in enumerate(all_chunks, 1):
            emb = self.embedder.embed(chunk.text)
            if emb is None:
                logger.warning("Chunk %s için embedding üretilemedi, atlanıyor.", chunk.id)
                continue
            embeddings.append(emb)
            valid_chunks.append(chunk)
            if i % 10 == 0:
                logger.info("  Embedding ilerlemesi: %d/%d", i, len(all_chunks))

        if not valid_chunks:
            logger.error("Hiç embedding üretilemedi. RAG indexleme başarısız.")
            return 0

        # ChromaDB'ye yükle
        self._collection.add(
            ids=[c.id for c in valid_chunks],
            embeddings=embeddings,
            documents=[c.text for c in valid_chunks],
            metadatas=[
                {"source": c.source, "owasp_id": c.owasp_id, "section": c.section}
                for c in valid_chunks
            ],
        )

        self._save_fingerprint()
        logger.info("RAG indexleme tamamlandı: %d chunk kaydedildi.", len(valid_chunks))
        return len(valid_chunks)

    def is_available_for_index(self) -> bool:
        """Indexleme için minimum koşullar (collection ve embedder hazır mı)."""
        return self._collection is not None and self.embedder.health_check()

    @staticmethod
    def _extract_owasp_id(filename: str) -> str:
        """`A03_injection.md` → `A03`."""
        m = re.match(r"(A\d{2})", filename)
        return m.group(1) if m else "UNKNOWN"

    # ------------------------------------------------------------------
    # Sorgulama
    # ------------------------------------------------------------------

    def retrieve(
        self,
        query: str,
        k: int = 3,
        owasp_filter: Optional[str] = None,
    ) -> List[Chunk]:
        """
        Sorguya en yakın K chunk'ı döndürür.

        Args:
            query: Arama metni (genelde finding'in başlığı + payload + snippet).
            k: Kaç chunk döndürülecek.
            owasp_filter: Sadece bu OWASP ID'sine ait chunk'lar (örn. "A03").

        Returns:
            Chunk listesi. RAG kullanılamıyorsa boş liste.
        """
        if not self.is_available():
            return []

        query_emb = self.embedder.embed(query)
        if query_emb is None:
            return []

        where = {"owasp_id": owasp_filter} if owasp_filter else None
        try:
            results = self._collection.query(
                query_embeddings=[query_emb],
                n_results=k,
                where=where,
            )
        except Exception as exc:
            logger.warning("RAG sorgu hatası: %s", exc)
            return []

        ids = results.get("ids", [[]])[0]
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]

        chunks: List[Chunk] = []
        for cid, doc, meta in zip(ids, docs, metas):
            chunks.append(
                Chunk(
                    id=cid,
                    text=doc,
                    source=meta.get("source", ""),
                    owasp_id=meta.get("owasp_id", ""),
                    section=meta.get("section", ""),
                )
            )
        return chunks

    def retrieve_for_finding(
        self,
        finding: Dict[str, Any],
        k: int = 3,
        prefer_same_owasp: bool = True,
    ) -> List[Chunk]:
        """
        Bir bulgu (Finding.to_dict() çıktısı) için en alakalı chunk'ları çeker.

        Sorgu metni: title + parameter + payload + response_snippet birleşimi.
        Önce aynı OWASP kategorisinde arar; sonuç boşsa kategori filtresini kaldırır.
        """
        if not self.is_available():
            return []

        query_parts = [
            finding.get("title", ""),
            f"parameter: {finding.get('parameter', '')}",
            f"payload: {finding.get('payload', '')}",
            finding.get("response_snippet", "")[:300],
        ]
        query = "\n".join(p for p in query_parts if p and p.strip() not in ("—", "parameter: —", "payload: —"))

        owasp_id = finding.get("owasp_id") if prefer_same_owasp else None
        chunks = self.retrieve(query, k=k, owasp_filter=owasp_id)

        # Aynı kategoride sonuç yoksa filtresiz dene
        if not chunks and owasp_id:
            chunks = self.retrieve(query, k=k)
        return chunks

    # ------------------------------------------------------------------
    # Yardımcı: prompt için context formatı
    # ------------------------------------------------------------------

    @staticmethod
    def format_for_prompt(chunks: List[Chunk]) -> str:
        """LLM prompt'una enjekte edilecek REFERANS BİLGİ bloğunu formatlar."""
        if not chunks:
            return ""
        parts: List[str] = []
        for i, c in enumerate(chunks, 1):
            parts.append(
                f"--- Referans {i} ({c.owasp_id} / {c.section}, kaynak: {c.source}) ---\n"
                f"{c.text}"
            )
        return "\n\n".join(parts)

    def stats(self) -> Dict[str, Any]:
        """Index durumu hakkında özet bilgi."""
        if not self.is_available():
            return {"available": False}
        return {
            "available": True,
            "collection": self.collection_name,
            "chunk_count": self._collection.count(),
            "db_path": str(self.db_path),
            "knowledge_dir": str(self.knowledge_dir),
            "embed_model": self.embedder.model,
        }

    def __repr__(self) -> str:
        status = "ready" if self.is_available() else "unavailable"
        return f"KnowledgeBase(status={status}, knowledge_dir={self.knowledge_dir})"
