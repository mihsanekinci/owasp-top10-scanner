FROM python:3.11-slim

WORKDIR /app

# ChromaDB sqlite3 wheel'i için minimal build araçları
# (Python 3.11-slim'de chromadb wheel'leri çoğu mimaride hazır, ama
#  ARM veya alternatif glibc'de fallback için gerekli olabilir.)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY guvenlik_proje/ ./guvenlik_proje/
RUN pip install --no-cache-dir -r guvenlik_proje/requirements.txt

COPY web/requirements.txt ./web/requirements.txt
RUN pip install --no-cache-dir -r web/requirements.txt

COPY web/ ./web/

# Tarama raporları + RAG vektör veritabanı dizinleri
RUN mkdir -p /tmp/scans /app/guvenlik_proje/rag_db

# RAG knowledge base ve DB dizinleri — main.py ve web bunları okur
ENV KNOWLEDGE_DIR=/app/guvenlik_proje/knowledge \
    RAG_DB_PATH=/app/guvenlik_proje/rag_db \
    PYTHONUNBUFFERED=1

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["web"]
