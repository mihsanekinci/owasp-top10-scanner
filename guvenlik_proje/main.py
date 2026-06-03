"""
main.py

AI Destekli Web Zafiyet Tarayıcısı – Ana Orkestratör

Kullanım:
  python main.py -u http://localhost/dvwa -o rapor.json
  python main.py -u http://localhost/dvwa --modules A03 --no-llm
  python main.py -u http://localhost/dvwa --llm-model llama3 --timeout 10

  # Çoklu LLM karşılaştırması:
  python main.py -u http://localhost/dvwa --llm-models llama3,qwen2.5:7b,mistral

  # RAG ile (varsayılan açık, kapatmak için --no-rag):
  python main.py -u http://localhost/dvwa --llm-models llama3,mistral --rag

  # Cookie ile (DVWA için):
  python main.py -u http://localhost/dvwa --cookie "PHPSESSID=abc123; security=low"

Argümanlar:
  -u / --url       : Hedef web uygulaması URL'si (zorunlu)
  -o / --output    : Rapor çıktı dosyası (varsayılan: rapor.json)
  --modules        : Virgülle ayrılmış modül ID'leri veya "all"
  --llm-model      : Tek Ollama model adı (varsayılan: llama3)
  --llm-models     : Çoklu model karşılaştırması (virgülle ayrılmış)
  --no-llm         : LLM analizini devre dışı bırak
  --rag / --no-rag : OWASP knowledge base RAG zenginleştirmesi (varsayılan: açık)
  --knowledge-dir  : Knowledge base dizini (varsayılan: ./knowledge)
  --rag-db-path    : RAG vektör DB dizini (varsayılan: ./rag_db)
  --rag-top-k      : RAG'dan çekilecek chunk sayısı (varsayılan: 3)
  --timeout        : HTTP istek zaman aşımı saniye (varsayılan: 5)
  --proxy          : Proxy URL'si
  --cookie         : Oturum çerezleri
  --verbose        : Ayrıntılı log çıktısı
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.http_client import HTTPClient
from core.llm_client import LLMClient
from core.multi_llm import MultiLLMClient
from core.rag import KnowledgeBase
from core.base_module import Finding
from modules.A01_BrokenAccessControl      import A01BrokenAccessControlModule
from modules.A02_CryptographicFailures    import A02CryptographicFailuresModule
from modules.A03_Injection                import A03InjectionModule
from modules.A04_InsecureDesign           import A04InsecureDesignModule
from modules.A05_SecurityMisconfiguration import A05SecurityMisconfigurationModule
from modules.A06_VulnerableComponents     import A06VulnerableComponentsModule
from modules.A07_IdentificationAuthFailures import A07IdentificationAuthFailuresModule
from modules.A08_DataIntegrity            import A08DataIntegrityModule
from modules.A09_LoggingMonitoring        import A09LoggingMonitoringModule
from modules.A10_SSRF                     import A10SSRFModule

# ---------------------------------------------------------------------------
# Kayıtlı modüller
# ---------------------------------------------------------------------------

_MODULE_REGISTRY: Dict[str, type] = {
    "A01": A01BrokenAccessControlModule,
    "A02": A02CryptographicFailuresModule,
    "A03": A03InjectionModule,
    "A04": A04InsecureDesignModule,
    "A05": A05SecurityMisconfigurationModule,
    "A06": A06VulnerableComponentsModule,
    "A07": A07IdentificationAuthFailuresModule,
    "A08": A08DataIntegrityModule,
    "A09": A09LoggingMonitoringModule,
    "A10": A10SSRFModule,
}

_ALL_MODULES = list(_MODULE_REGISTRY.keys())


def setup_logging(verbose: bool) -> None:
    """Konsol log formatını yapılandırır."""
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s – %(message)s"
    logging.basicConfig(
        level=level,
        format=fmt,
        datefmt="%H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    # ChromaDB gürültüsü
    logging.getLogger("chromadb").setLevel(logging.WARNING)


def parse_cookie_string(cookie_str: str) -> Dict[str, str]:
    """Tarayıcı formatındaki çerez dizesini sözlüğe çevirir."""
    cookies: Dict[str, str] = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            cookies[key.strip()] = value.strip()
    return cookies


def parse_args() -> argparse.Namespace:
    """CLI argümanlarını ayrıştırır."""
    parser = argparse.ArgumentParser(
        prog="zafiyet-tarayici",
        description="AI Destekli Web Zafiyet Tarayıcısı (OWASP Top 10)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument("-u", "--url", required=True, metavar="URL",
                        help="Hedef web uygulamasının kök URL'si")
    parser.add_argument("-o", "--output", default="rapor.json", metavar="DOSYA",
                        help="Rapor çıktı dosyası")
    parser.add_argument("--modules", default="all", metavar="MODÜLLER",
                        help=f"Modüller: all veya virgülle ayrılmış {_ALL_MODULES}")

    # LLM seçimi
    parser.add_argument("--llm-model", default="llama3", metavar="MODEL",
                        help="Tek Ollama model adı (varsayılan: llama3)")
    parser.add_argument("--llm-models", default=None, metavar="MODELLER",
                        help="Çoklu model karşılaştırması: virgülle ayrılmış model adları")
    parser.add_argument("--no-llm", action="store_true",
                        help="LLM analizini devre dışı bırak")

    # RAG
    parser.add_argument("--rag", dest="rag", action="store_true", default=True,
                        help="RAG knowledge base'i etkinleştir (varsayılan: açık)")
    parser.add_argument("--no-rag", dest="rag", action="store_false",
                        help="RAG'ı devre dışı bırak")
    parser.add_argument("--knowledge-dir", default="./knowledge",
                        help="Knowledge markdown dosyalarının dizini")
    parser.add_argument("--rag-db-path", default="./rag_db",
                        help="RAG vektör veritabanı persistence dizini")
    parser.add_argument("--rag-top-k", type=int, default=3,
                        help="Her bulgu için kaç chunk çekilecek (varsayılan: 3)")

    # HTTP
    parser.add_argument("--timeout", type=int, default=5, metavar="SANIYE",
                        help="HTTP istek zaman aşımı")
    parser.add_argument("--proxy", default=None, metavar="URL",
                        help="Proxy URL'si")
    parser.add_argument("--cookie", default=None, metavar="ÇEREZ",
                        help='Oturum çerezleri (örn. "PHPSESSID=abc; security=low")')

    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Ayrıntılı log çıktısı (DEBUG)")

    args = parser.parse_args()

    # Modül doğrulama
    if args.modules.lower() != "all":
        requested = [m.strip().upper() for m in args.modules.split(",")]
        unknown = [m for m in requested if m not in _MODULE_REGISTRY]
        if unknown:
            parser.error(f"Bilinmeyen modüller: {unknown}. Mevcut: {_ALL_MODULES}")
        args.modules = requested
    else:
        args.modules = _ALL_MODULES

    # --llm-models ayrıştır
    if args.llm_models:
        args.llm_models = [m.strip() for m in args.llm_models.split(",") if m.strip()]

    return args


def resolve_modules(module_ids: List[str]) -> List[type]:
    return [_MODULE_REGISTRY[mid] for mid in module_ids if mid in _MODULE_REGISTRY]


# ---------------------------------------------------------------------------
# Tarama orkestrasyonu
# ---------------------------------------------------------------------------

def run_modules(
    target: str,
    module_classes: List[type],
    http_client: HTTPClient,
) -> List[Finding]:
    """
    Tüm modülleri sırayla çalıştırır ve bulguları toplar.
    LLM zenginleştirmesi BU FONKSİYONDA YAPILMAZ — orkestratör seviyesinde
    yapılır (bkz. enrich_findings).
    """
    all_findings: List[Finding] = []
    log = logging.getLogger("orchestrator")

    for ModuleClass in module_classes:
        module_name = getattr(ModuleClass, "OWASP_ID", ModuleClass.__name__)
        log.info("━" * 50)
        log.info("Modül başlatılıyor: %s", module_name)

        try:
            init_kwargs: Dict[str, Any] = {
                "target": target,
                "http_client": http_client,
                "shared_data": {},
            }
            # A03 hala llm_client/enable_llm bekliyor; None geçerek
            # modül içi LLM çağrısını devre dışı bırakıyoruz — orkestratör hepsini yapacak.
            if ModuleClass is A03InjectionModule:
                init_kwargs["llm_client"] = None
                init_kwargs["enable_llm"] = False

            module = ModuleClass(**init_kwargs)
            findings = module.run()
            all_findings.extend(findings)
            log.info("Modül tamamlandı: %s → %d bulgu", module_name, len(findings))

        except Exception as exc:
            log.error("Modül %s hata verdi: %s", module_name, exc, exc_info=True)

    return all_findings


def enrich_findings(
    findings: List[Finding],
    llm_client: Optional[LLMClient],
    multi_llm: Optional[MultiLLMClient],
    knowledge_base: Optional[KnowledgeBase],
    rag_top_k: int,
) -> None:
    """
    Her bulgu için LLM zenginleştirmesi yapar (in-place).

    Akış:
      1. RAG açıksa → bulguya en yakın chunk'ları çek, context oluştur.
      2. MultiLLM varsa → tüm modellere paralel sor → finding.llm_analyses.
         Yoksa LLM varsa → tek sorgu → finding.llm_analysis.
      3. Hiçbiri yoksa → atla.
    """
    if not findings:
        return

    log = logging.getLogger("orchestrator")
    use_rag = knowledge_base is not None and knowledge_base.is_available()
    use_multi = multi_llm is not None and multi_llm.is_available()
    use_single = llm_client is not None and not use_multi

    if not (use_single or use_multi):
        log.info("LLM zenginleştirmesi devre dışı — bulgular ham bırakıldı.")
        return

    log.info("━" * 50)
    log.info(
        "LLM zenginleştirme başladı (%d bulgu, RAG: %s, Çoklu LLM: %s)",
        len(findings),
        "açık" if use_rag else "kapalı",
        "açık" if use_multi else "kapalı",
    )

    for i, finding in enumerate(findings, 1):
        # 1) RAG context
        rag_context = ""
        rag_sources: List[str] = []
        if use_rag:
            chunks = knowledge_base.retrieve_for_finding(
                finding.to_dict(), k=rag_top_k
            )
            if chunks:
                rag_context = KnowledgeBase.format_for_prompt(chunks)
                rag_sources = list({c.source for c in chunks})
                finding.rag_used = True
                finding.rag_sources = rag_sources
                log.debug(
                    "  Bulgu %d RAG: %d chunk, kaynaklar: %s",
                    i, len(chunks), rag_sources
                )

        # 2) LLM çağrısı
        finding_dict = finding.to_dict()
        if use_multi:
            analyses = multi_llm.query_all(finding_dict, rag_context=rag_context)
            finding.llm_analyses = analyses
            finding.llm_comparison = MultiLLMClient.summarize_comparison(analyses)
            log.info(
                "  [%d/%d] %s → %d model yanıtı (konsensüs: %s)",
                i, len(findings), finding.title,
                len(analyses),
                finding.llm_comparison.get("risk_consensus", "?"),
            )
        else:  # use_single
            analysis = llm_client.query(finding_dict, rag_context=rag_context)
            finding.llm_analysis = analysis
            log.info(
                "  [%d/%d] %s → risk: %s",
                i, len(findings), finding.title,
                analysis.get("risk_seviyesi", "?"),
            )

        print(f"[FINDING_READY] {json.dumps(finding.to_dict(), ensure_ascii=False)}", flush=True)


# ---------------------------------------------------------------------------
# Rapor üretimi
# ---------------------------------------------------------------------------

def build_report(
    target: str,
    findings: List[Finding],
    modules_run: List[str],
    scan_duration: float,
    llm_enabled: bool,
    llm_models: List[str],
    rag_enabled: bool,
    rag_stats: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Tüm bulgulardan JSON raporunu oluşturur."""
    severity_counts: Dict[str, int] = {}
    for f in findings:
        sev = f.severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "scan_info": {
            "target": target,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "duration_seconds": round(scan_duration, 2),
            "modules_run": modules_run,
            "llm_enabled": llm_enabled,
            "llm_models": llm_models,
            "rag_enabled": rag_enabled,
            "rag_stats": rag_stats,
            "tool": "AI-Destekli Web Zafiyet Tarayıcısı v1.1",
        },
        "summary": {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
        },
        "findings": [f.to_dict() for f in findings],
    }


def save_report(report: Dict[str, Any], output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)


def print_summary(findings: List[Finding]) -> None:
    log = logging.getLogger("orchestrator")
    log.info("━" * 50)
    log.info("TARAMA ÖZETI")
    log.info("━" * 50)

    if not findings:
        log.info("Hiçbir bulgu tespit edilmedi.")
        return

    for i, f in enumerate(findings, 1):
        extra = ""
        if f.llm_comparison:
            extra = f" | Konsensüs: {f.llm_comparison.get('risk_consensus', '?')}"
        elif f.llm_analysis and not f.llm_analysis.get("llm_hatasi"):
            extra = f" | LLM Risk: {f.llm_analysis.get('risk_seviyesi', '?')}"
        log.info("[%d] %s | %s | %s%s",
                 i, f.owasp_id, f.title, f.confidence.value, extra)


# ---------------------------------------------------------------------------
# Ana giriş noktası
# ---------------------------------------------------------------------------

def main() -> int:
    args = parse_args()
    setup_logging(args.verbose)
    log = logging.getLogger("orchestrator")

    llm_models_label = (
        "Devre dışı" if args.no_llm
        else (",".join(args.llm_models) if args.llm_models else args.llm_model)
    )

    log.info("=" * 60)
    log.info("AI Destekli Web Zafiyet Tarayıcısı")
    log.info("Hedef    : %s", args.url)
    log.info("Modüller : %s", ", ".join(args.modules))
    log.info("LLM      : %s", llm_models_label)
    log.info("RAG      : %s", "Açık" if (args.rag and not args.no_llm) else "Kapalı")
    log.info("Oturum   : %s", "Çerez sağlandı" if args.cookie else "Anonim")
    log.info("=" * 60)

    # Çerezleri ayrıştır
    session_cookies: Dict[str, str] = {}
    if args.cookie:
        session_cookies = parse_cookie_string(args.cookie)
        if session_cookies:
            log.info("Oturum çerezleri: %s", list(session_cookies.keys()))

    # HTTP client
    http_client = HTTPClient(
        timeout=args.timeout,
        proxy=args.proxy,
        cookies=session_cookies or None,
    )

    # ----- LLM istemcileri kur -----
    llm_client: Optional[LLMClient] = None
    multi_llm: Optional[MultiLLMClient] = None
    active_models: List[str] = []

    if not args.no_llm:
        if args.llm_models:
            multi_llm = MultiLLMClient(models=args.llm_models)
            if multi_llm.is_available():
                active_models = multi_llm.active_models()
                log.info("Çoklu LLM aktif modeller: %s", active_models)
            else:
                log.warning("Hiçbir LLM modeli erişilemiyor. LLM atlanacak.")
                multi_llm = None
        else:
            llm_client = LLMClient(model=args.llm_model)
            if llm_client.health_check():
                active_models = [args.llm_model]
            else:
                log.warning("Ollama erişilemiyor. LLM atlanacak.")
                llm_client = None

    # ----- RAG knowledge base -----
    knowledge_base: Optional[KnowledgeBase] = None
    rag_stats: Optional[Dict[str, Any]] = None
    if args.rag and not args.no_llm and (llm_client or multi_llm):
        log.info("RAG knowledge base başlatılıyor...")
        knowledge_base = KnowledgeBase(
            knowledge_dir=args.knowledge_dir,
            db_path=args.rag_db_path,
        )
        if knowledge_base.is_available():
            rag_stats = knowledge_base.stats()
            log.info(
                "RAG hazır: %d chunk, model: %s",
                rag_stats.get("chunk_count", 0),
                rag_stats.get("embed_model"),
            )
        else:
            log.warning(
                "RAG kullanılamıyor — chromadb veya nomic-embed-text eksik olabilir. "
                "Devam ediliyor (RAG'sız)."
            )
            knowledge_base = None

    # ----- Modülleri çöz -----
    module_classes = resolve_modules(args.modules)
    if not module_classes:
        log.error("Çalıştırılacak modül bulunamadı.")
        return 1

    # ----- Taramayı yürüt -----
    start_time = time.monotonic()
    try:
        findings = run_modules(args.url, module_classes, http_client)
        enrich_findings(findings, llm_client, multi_llm, knowledge_base, args.rag_top_k)
    except KeyboardInterrupt:
        log.warning("Tarama kullanıcı tarafından durduruldu.")
        return 1
    finally:
        http_client.close()

    duration = time.monotonic() - start_time

    print_summary(findings)

    report = build_report(
        target=args.url,
        findings=findings,
        modules_run=args.modules,
        scan_duration=duration,
        llm_enabled=not args.no_llm and bool(active_models),
        llm_models=active_models,
        rag_enabled=knowledge_base is not None and knowledge_base.is_available(),
        rag_stats=rag_stats,
    )
    save_report(report, args.output)
    log.info("Rapor kaydedildi: %s", args.output)
    log.info("Toplam süre: %.2fs", duration)

    return 2 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
