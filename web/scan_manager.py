"""
web/scan_manager.py

Tarama işlerini yöneten modül. main.py'yi subprocess olarak çalıştırır,
stdout'u satır satır okuyarak WebSocket event'lerine dönüştürür.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "3"))
LOG_BUFFER_SIZE = 500


def _resolve_main_py() -> tuple[str, str]:
    """
    main.py'nin yolunu ve çalışma dizinini çözer.

    Öncelik sırası:
      1. SCANNER_MAIN_PY env var (mutlak yol)
      2. Docker konteyner yolu (/app/guvenlik_proje/main.py) varsa
      3. Repo köküne göre türetilen yol (web/'in kardeşi guvenlik_proje/)
    """
    env_path = os.environ.get("SCANNER_MAIN_PY")
    if env_path:
        p = Path(env_path).resolve()
        return str(p), str(p.parent)

    docker_path = Path("/app/guvenlik_proje/main.py")
    if docker_path.exists():
        return str(docker_path), str(docker_path.parent)

    # web/scan_manager.py → repo_root/guvenlik_proje/main.py
    repo_root = Path(__file__).resolve().parent.parent
    local_path = repo_root / "guvenlik_proje" / "main.py"
    return str(local_path), str(local_path.parent)


def _resolve_scans_dir() -> str:
    """
    Rapor JSON'larının yazılacağı dizini çözer.

    Öncelik: SCANS_DIR env var → Docker /tmp/scans → sistem temp.
    """
    env_dir = os.environ.get("SCANS_DIR")
    if env_dir:
        Path(env_dir).mkdir(parents=True, exist_ok=True)
        return env_dir
    if sys.platform != "win32" and Path("/tmp").is_dir():
        d = "/tmp/scans"
    else:
        d = str(Path(tempfile.gettempdir()) / "guvenlik_proje_scans")
    Path(d).mkdir(parents=True, exist_ok=True)
    return d


MAIN_PY_PATH, MAIN_PY_CWD = _resolve_main_py()
SCANS_DIR = _resolve_scans_dir()
PYTHON_EXECUTABLE = os.environ.get("SCANNER_PYTHON", sys.executable)

ALL_MODULES = ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]

MODULE_DESCRIPTIONS = {
    "A01": "Broken Access Control taranıyor...",
    "A02": "Cryptographic Failures taranıyor...",
    "A03": "Injection (SQLi + XSS) taranıyor...",
    "A04": "Insecure Design taranıyor...",
    "A05": "Security Misconfiguration taranıyor...",
    "A06": "Vulnerable Components taranıyor...",
    "A07": "Identification & Auth Failures taranıyor...",
    "A08": "Software & Data Integrity taranıyor...",
    "A09": "Logging & Monitoring taranıyor...",
    "A10": "SSRF taranıyor...",
}

_RE_MODULE_BEGIN = re.compile(r"Modül başlatılıyor[:\s]+([A-Z]\d{2})", re.IGNORECASE)
_RE_MODULE_DONE = re.compile(
    r"Modül tamamlandı[:\s]+([A-Z]\d{2})[^\d]*(\d+)\s*bulgu", re.IGNORECASE
)
_RE_FINDING_READY = re.compile(r"^\[FINDING_READY\]\s+(.+)$")


@dataclass
class ScanJob:
    scan_id: str
    status: str  # queued | running | done | cancelled | error
    target: str
    modules: List[str]
    started_at: float
    finished_at: Optional[float] = None
    process: Optional[asyncio.subprocess.Process] = None
    report: Optional[Dict[str, Any]] = None
    log_buffer: List[str] = field(default_factory=list)
    task: Optional[asyncio.Task] = None


_jobs: Dict[str, ScanJob] = {}
_connections: Dict[str, List[Any]] = {}  # scan_id → list[WebSocket]


def get_job(scan_id: str) -> Optional[ScanJob]:
    return _jobs.get(scan_id)


def list_jobs(limit: int = 20) -> List[ScanJob]:
    jobs = sorted(_jobs.values(), key=lambda j: j.started_at, reverse=True)
    return jobs[:limit]


def running_count() -> int:
    return sum(1 for j in _jobs.values() if j.status == "running")


def register_ws(scan_id: str, ws: Any) -> None:
    _connections.setdefault(scan_id, []).append(ws)


def unregister_ws(scan_id: str, ws: Any) -> None:
    conns = _connections.get(scan_id, [])
    if ws in conns:
        conns.remove(ws)


async def _broadcast(scan_id: str, event: Dict[str, Any]) -> None:
    conns = _connections.get(scan_id, [])
    dead = []
    for ws in conns:
        try:
            await ws.send_json(event)
        except Exception:
            dead.append(ws)
    for ws in dead:
        conns.remove(ws)


def _buffer_log(job: ScanJob, message: str) -> None:
    job.log_buffer.append(message)
    if len(job.log_buffer) > LOG_BUFFER_SIZE:
        job.log_buffer.pop(0)


async def start_scan(
    target: str,
    modules: Optional[List[str]] = None,
    no_llm: bool = False,
    cookie: Optional[str] = None,
    timeout: int = 5,
    llm_model: Optional[str] = None,
    llm_models: Optional[List[str]] = None,
    use_rag: bool = True,
) -> str:
    """
    Yeni bir tarama işi başlatır.

    Args:
        target     : Hedef URL.
        modules    : Çalıştırılacak modül ID'leri.
        no_llm     : True ise LLM analizi yapılmaz.
        cookie     : Oturum çerezleri.
        timeout    : HTTP istek zaman aşımı.
        llm_model  : Tek-model modu için Ollama model adı.
        llm_models : Çoklu LLM modu için model adı listesi. Verildiyse
                     llm_model yok sayılır.
        use_rag    : True ise OWASP knowledge base ile zenginleştirme.
    """
    if running_count() >= MAX_CONCURRENT_SCANS:
        raise RuntimeError("too_many_scans")

    scan_id = uuid.uuid4().hex
    mods = modules if modules else ALL_MODULES

    job = ScanJob(
        scan_id=scan_id,
        status="queued",
        target=target,
        modules=mods,
        started_at=time.time(),
    )
    _jobs[scan_id] = job

    job.task = asyncio.create_task(
        _run_scan(job, no_llm, cookie, timeout, llm_model, llm_models, use_rag)
    )
    return scan_id


async def cancel_scan(scan_id: str) -> bool:
    job = _jobs.get(scan_id)
    if not job or job.status not in ("queued", "running"):
        return False

    if job.process:
        try:
            job.process.terminate()
        except Exception:
            pass

    if job.task:
        job.task.cancel()

    job.status = "cancelled"
    job.finished_at = time.time()
    await _broadcast(scan_id, {"type": "scan_cancelled", "scan_id": scan_id})
    return True


async def _run_scan(
    job: ScanJob,
    no_llm: bool,
    cookie: Optional[str],
    timeout: int,
    llm_model: Optional[str] = None,
    llm_models: Optional[List[str]] = None,
    use_rag: bool = True,
) -> None:
    scan_id = job.scan_id
    report_path = str(Path(SCANS_DIR) / f"{scan_id}.json")

    cmd = [
        PYTHON_EXECUTABLE, MAIN_PY_PATH,
        "-u", job.target,
        "-o", report_path,
        "--modules", ",".join(job.modules),
        "--timeout", str(timeout),
    ]
    if no_llm:
        cmd.append("--no-llm")
    else:
        # Çoklu LLM modu tek-model'i geçersiz kılar
        if llm_models:
            cmd += ["--llm-models", ",".join(llm_models)]
        elif llm_model:
            cmd += ["--llm-model", llm_model]
        # RAG: varsayılan açık, kapatmak için bayrak gerekiyor
        if not use_rag:
            cmd.append("--no-rag")
    if cookie:
        cmd += ["--cookie", cookie]

    job.status = "running"
    await _broadcast(scan_id, {
        "type": "scan_started",
        "scan_id": scan_id,
        "target": job.target,
        "modules": job.modules,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=MAIN_PY_CWD,
        )
        job.process = proc

        async for raw_line in proc.stdout:
            line = raw_line.decode("utf-8", errors="replace").rstrip()
            _buffer_log(job, line)
            event = _parse_line(line)
            await _broadcast(scan_id, event)

        exit_code = await proc.wait()

    except asyncio.CancelledError:
        return
    except Exception as exc:
        logger.exception("Tarama hatası: %s", scan_id)
        job.status = "error"
        job.finished_at = time.time()
        await _broadcast(scan_id, {"type": "scan_error", "message": str(exc)})
        return

    job.finished_at = time.time()
    duration = round(job.finished_at - job.started_at, 2)

    report = None
    if os.path.exists(report_path):
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                report = json.load(f)
            job.report = report
        except Exception as exc:
            logger.warning("Rapor okunamadı: %s", exc)

    total_findings = report["summary"]["total_findings"] if report else 0

    job.status = "done" if exit_code in (0, 2) else "error"
    await _broadcast(scan_id, {
        "type": "scan_complete",
        "exit_code": exit_code,
        "duration": duration,
        "total_findings": total_findings,
        "report_id": scan_id,
        "report": report,
    })


def _parse_line(line: str) -> Dict[str, Any]:
    m = _RE_FINDING_READY.match(line)
    if m:
        try:
            finding = json.loads(m.group(1))
            return {"type": "finding_enriched", "finding": finding}
        except json.JSONDecodeError:
            pass

    m = _RE_MODULE_BEGIN.search(line)
    if m:
        mod = m.group(1).upper()
        return {
            "type": "module_begin",
            "module": mod,
            "description": MODULE_DESCRIPTIONS.get(mod, f"{mod} taranıyor..."),
        }

    m = _RE_MODULE_DONE.search(line)
    if m:
        return {
            "type": "module_done",
            "module": m.group(1).upper(),
            "finding_count": int(m.group(2)),
        }

    level = "INFO"
    lower = line.lower()
    if "error" in lower or "hata" in lower:
        level = "ERROR"
    elif "warning" in lower or "uyarı" in lower:
        level = "WARNING"

    return {"type": "log", "level": level, "message": line}
