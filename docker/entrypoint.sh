#!/bin/sh
set -e

# Ollama hazır olana kadar bekle (init container kullanılmıyorsa)
if [ -n "$OLLAMA_HOST" ] && [ "$WAIT_FOR_OLLAMA" != "0" ]; then
    echo "[entrypoint] Ollama bekleniyor: $OLLAMA_HOST"
    i=0
    while [ $i -lt 30 ]; do
        if wget -q -O- "$OLLAMA_HOST/api/tags" >/dev/null 2>&1; then
            echo "[entrypoint] Ollama hazır."
            break
        fi
        i=$((i + 1))
        sleep 2
    done
fi

# RAG knowledge base'i indexle (Ollama'da nomic-embed-text varsa otomatik çalışır;
# yoksa is_available=False döner ve atlanır — ana akışı bozmaz).
# Sadece ilk build'de veya knowledge/ değiştiğinde gerçekten indexler.
if [ "$SKIP_RAG_INDEX" != "1" ] && [ -d "${KNOWLEDGE_DIR:-/app/guvenlik_proje/knowledge}" ]; then
    echo "[entrypoint] RAG knowledge base hazırlanıyor (gerekiyorsa indexlenecek)..."
    cd /app/guvenlik_proje && python -c "
from core.rag import KnowledgeBase
import os
kb = KnowledgeBase(
    knowledge_dir=os.environ.get('KNOWLEDGE_DIR', './knowledge'),
    db_path=os.environ.get('RAG_DB_PATH', './rag_db'),
)
if kb.is_available():
    s = kb.stats()
    print(f\"[RAG] Hazır — {s.get('chunk_count', 0)} chunk\")
else:
    print('[RAG] Devre dışı (chromadb veya nomic-embed-text eksik). Tarama RAG kullanmadan devam edecek.')
" || echo "[entrypoint] RAG init başarısız, devam ediliyor."
    cd /app
fi

if [ "$1" = "web" ]; then
    exec uvicorn web.app:app --host 0.0.0.0 --port 8000
else
    exec python /app/guvenlik_proje/main.py "$@"
fi
