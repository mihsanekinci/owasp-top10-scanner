"""
core/llm_client.py

Ollama yerel LLM API'siyle haberleşen istemci.

Sorumluluklar:
  - Ham bulgu sözlüğünü insan-okunur bir prompt'a dönüştürmek.
  - Ollama /api/generate endpoint'ine POST atmak.
  - Yanıtı ayrıştırıp standart bir dict döndürmek.
  - Ollama erişilemez olduğunda graceful hata yönetimi sağlamak.

NOT: Bu modül ASLA zafiyet tespiti yapmaz. Yalnızca tespit sonrası
     doğrulama, risk analizi ve düzeltme önerisi üretir.
"""

from __future__ import annotations

import json
import logging
import os
import re
import textwrap
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)

_OLLAMA_BASE_URL = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
_DEFAULT_MODEL = "llama3"
_DEFAULT_TIMEOUT = 180  # CPU'da llama3 + RAG context için yeterli süre

# Desteklenmeyen format durumunda döndürülecek güvenli varsayılan
_LLM_UNAVAILABLE: Dict[str, Any] = {
    "risk_seviyesi": "Bilinmiyor",
    "teknik_aciklama": "LLM yanıt vermedi veya erişilemez durumda.",
    "kod_duzeltme": "LLM erişilemez.",
    "genel_onlemler": [],
    "llm_guven": "Düşük",
    "llm_hatasi": True,
}


class LLMClient:
    """
    Ollama API istemcisi.

    Attributes:
        model: Ollama'da yüklü model adı (örn. "llama3.2:3b").
        base_url: Ollama sunucusunun temel URL'si.
        timeout: API çağrısı için saniye cinsinden bekleme süresi.
    """

    def __init__(
        self,
        model: str = _DEFAULT_MODEL,
        base_url: str = _OLLAMA_BASE_URL,
        timeout: int = _DEFAULT_TIMEOUT,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._generate_url = f"{self.base_url}/api/generate"

    # ------------------------------------------------------------------
    # Prompt oluşturma
    # ------------------------------------------------------------------

    def _build_prompt(self, finding: Dict[str, Any], rag_context: str = "") -> str:
        """
        Finding sözlüğünden yapılandırılmış bir analiz prompt'u üretir.

        Args:
            finding    : Bulgu sözlüğü (Finding.to_dict() çıktısı).
            rag_context: Knowledge base'den çekilmiş referans bilgi bloğu.
                         Boş ise prompt'a eklenmez (RAG kapalı modu).

        Llama 3 gibi sohbet modelleri talimat verilmezse markdown bloğu
        veya açıklama metni ekler. Prompt; modeli saf JSON üretmeye
        zorlamak için şu teknikleri birlikte kullanır:
          1. "SYSTEM:" rolü bildirimi — model sohbet değil araç gibi davransın.
          2. Açık yasaklar — markdown, ``` blokları, açıklama metni yasak.
          3. Yanıtı doğrudan açan brace { ile başlama talimatı.
          4. Doldurulmuş şema örneği — modelin kopyalaması yeterli.
          5. RAG context: Varsa OWASP knowledge base'den çekilmiş referans
             metin model bilgisini güçlendirir ve halüsinasyonu azaltır.
        """
        owasp_id   = finding.get("owasp_id",        "Bilinmiyor")
        title      = finding.get("title",            "Bilinmiyor")
        url        = finding.get("url",              "—")
        parameter  = finding.get("parameter",        "—")
        payload    = finding.get("payload",          "—")
        snippet    = finding.get("response_snippet", "—")
        confidence = finding.get("confidence",       "—")

        # RAG context bloğu (varsa)
        rag_block = ""
        if rag_context and rag_context.strip():
            rag_block = textwrap.dedent(f"""\

                REFERENCE KNOWLEDGE (use this to enrich your analysis — cite specific
                mitigations and CWE IDs when relevant; do NOT copy verbatim):
                {rag_context}
            """)

        prompt = textwrap.dedent(f"""\
            SYSTEM: Sen bir web güvenlik analiz uzmanısın ve sadece JSON nesnesi
            döndüren bir API endpoint'isin. Yanıtların TÜRKÇE olacak.

            KATI KURALLAR (ihlal sistem hatasına yol açar):
              - JSON nesnesinden önce veya sonra HİÇBİR metin yazma.
              - Markdown, code fence (```), backtick KULLANMA.
              - Selamlama, açıklama, yorum YAPMA.
              - Diziyle sarmalama (array içine ALMA).
              - Yanıt {{ ile başlayıp }} ile bitsin.
              - Aşağıdaki örnekteki yer tutucuları (placeholder) ASLA olduğu gibi
                kopyalama — gerçek INPUT için anlamlı, spesifik içerik üret.

            RİSK SEVİYESİ KURALI (önemli):
              - Kritik       : Doğrudan RCE, tam DB sızıntısı, auth atlama (örn. SQLi, RCE, deserialization)
              - Yüksek       : Veri sızıntısı veya hesap ele geçirme yolu açan (örn. XSS, IDOR, eski CVE)
              - Orta         : Saldırı zincirinin parçası ama tek başına sınırlı (örn. HSTS yok, brute-force yok)
              - Düşük        : Bilgi sızıntısı veya defense-in-depth eksikliği (örn. Server header, Referrer-Policy)
              - Bilgilendirici: Sadece keşif değeri (örn. robots.txt içeriği, public dosya listesi)
            HER ŞEYE 'Kritik' DEME — bulgunun gerçek etkisini değerlendir.

            ÖRNEK 1 — Kritik risk (SQL Injection):
            INPUT: A03 — SQL Injection, /login.php, param=username,
                   payload="' OR 1=1--", confidence=High
            OUTPUT:
            {{
              "risk_seviyesi": "Kritik",
              "teknik_aciklama": "Kullanıcı girdisi SQL sorgusuna doğrudan birleştirildiği için saldırgan UNION SELECT ile veritabanından veri çekebilir veya kimlik doğrulamayı atlayabilir. Bu açık tam veri sızıntısına yol açar.",
              "kod_duzeltme": "cursor.execute('SELECT * FROM users WHERE username=%s', (username,)) — parametreli sorgu kullanın; ORM (SQLAlchemy) tercih edin; raw SQL'den kaçının.",
              "genel_onlemler": ["Tüm DB sorgularında parametreli (prepared) statement kullanın", "Allowlist tabanlı input validation uygulayın", "Uygulama DB kullanıcısına least-privilege yetkisi verin", "WAF'ta SQLi pattern'leri için kural tanımlayın"],
              "llm_guven": "Yüksek"
            }}

            ÖRNEK 2 — Düşük risk (defense-in-depth eksikliği):
            INPUT: A05 — Sunucu Versiyon Sızıntısı, http://target/,
                   param=Server, payload="Apache/2.4.25", confidence=High
            OUTPUT:
            {{
              "risk_seviyesi": "Düşük",
              "teknik_aciklama": "Server yanıt başlığı tam sürüm bilgisini açığa çıkarıyor. Bu tek başına bir zafiyet değil ama saldırganın bilinen CVE'lere doğrudan hedeflemesini kolaylaştırır — defense-in-depth ihlali.",
              "kod_duzeltme": "Apache: 'ServerTokens Prod' ve 'ServerSignature Off' yönergelerini httpd.conf'a ekle. Nginx: 'server_tokens off;' http bloğuna ekle.",
              "genel_onlemler": ["Tüm sürüm bilgisi sızdıran başlıkları (Server, X-Powered-By) kapatın", "Yüklü bileşenleri düzenli yamalayın", "Bilinen CVE'ler için periyodik tarama yapın"],
              "llm_guven": "Yüksek"
            }}
            {rag_block}
            ŞİMDİ BU GERÇEK INPUT'U ANALİZ ET:
            OWASP Category   : {owasp_id} — {title}
            Target URL       : {url}
            Parameter        : {parameter}
            Payload used     : {payload}
            Detection conf   : {confidence}
            Response snippet : {snippet}

            ÇIKTI ŞEMASI (her alanı YUKARıDAKİ GERÇEK INPUT'A ÖZGÜ doldur):
              - risk_seviyesi  : Kritik | Yüksek | Orta | Düşük | Bilgilendirici
              - teknik_aciklama: 2-3 cümle; bulguya özgü teknik açıklama
              - kod_duzeltme   : Spesifik kod örneği veya yapılandırma satırı
              - genel_onlemler : 3-5 maddelik liste; her madde uygulanabilir öneri
              - llm_guven      : Yüksek | Orta | Düşük

            Sadece JSON nesnesini döndür, başka hiçbir şey yazma:\
        """)

        return prompt

    # ------------------------------------------------------------------
    # API çağrısı
    # ------------------------------------------------------------------

    def query(
        self,
        finding: Dict[str, Any],
        rag_context: str = "",
    ) -> Dict[str, Any]:
        """
        Bir Finding için Ollama'ya analiz isteği atar.

        Args:
            finding    : base_module.Finding'den türetilmiş sözlük.
            rag_context: Knowledge base'den çekilmiş referans bilgi (opsiyonel).
                         Boş ise klasik prompt kullanılır.

        Returns:
            LLM'den gelen ayrıştırılmış JSON yanıtı.
            Ollama erişilemezse _LLM_UNAVAILABLE sabiti döner.
        """
        prompt = self._build_prompt(finding, rag_context=rag_context)
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.2,  # Tutarlı, düşük yaratıcılıklı yanıt
                "num_predict": 512,
            },
        }

        try:
            logger.debug("LLM sorgusu gönderiliyor: model=%s, url=%s", self.model, self._generate_url)
            response = requests.post(
                self._generate_url,
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return self._parse_response(response.json())

        except requests.exceptions.ConnectionError:
            logger.warning(
                "Ollama'ya bağlanılamadı (%s). LLM analizi atlanıyor.", self._generate_url
            )
            return {**_LLM_UNAVAILABLE, "hata_nedeni": "Bağlantı hatası"}

        except requests.exceptions.Timeout:
            logger.warning("Ollama yanıt zaman aşımı (%ds).", self.timeout)
            return {**_LLM_UNAVAILABLE, "hata_nedeni": "Zaman aşımı"}

        except requests.exceptions.HTTPError as exc:
            logger.error("Ollama HTTP hatası: %s", exc)
            return {**_LLM_UNAVAILABLE, "hata_nedeni": str(exc)}

        except Exception as exc:  # noqa: BLE001
            logger.error("LLM sorgusunda beklenmeyen hata: %s", exc)
            return {**_LLM_UNAVAILABLE, "hata_nedeni": str(exc)}

    # ------------------------------------------------------------------
    # Yanıt ayrıştırma
    # ------------------------------------------------------------------

    def _parse_response(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ollama'nın ham yanıt zarfını açar ve içindeki JSON nesnesini döndürür.

        Ollama zarfı:
          {"model": "...", "response": "<model_çıktısı>", "done": true, ...}

        Model çıktısı; konuşma metni, markdown blokları veya saf JSON
        içerebilir. _extract_json() bu üç durumu sırayla dener.
        """
        response_text: str = raw.get("response", "")
        logger.debug("Ham LLM yanıtı (ilk 300 kar): %.300s", response_text)

        parsed = self._extract_json(response_text)
        if parsed is not None:
            parsed["llm_hatasi"] = False
            return parsed

        # Hiçbir strateji başarılı olmadı
        logger.warning(
            "LLM yanıtından JSON çıkarılamadı. Ham yanıt: %.300s", response_text
        )
        return {
            **_LLM_UNAVAILABLE,
            "hata_nedeni": "Geçersiz JSON yanıtı",
            "ham_yanit": response_text[:500],
        }

    def _extract_json(self, text: str) -> Optional[Dict[str, Any]]:
        """
        Serbest biçimli model çıktısından JSON nesnesini çıkarmak için
        dört stratejiyi sırayla dener; ilk başarılıda döner.

        Strateji 1 — Doğrudan ayrıştırma:
            Model kurala uydu ve saf JSON döndürdü.
        Strateji 2 — Markdown code fence soyma:
            ```json ... ``` veya ``` ... ``` bloğu içindeki metni al.
        Strateji 3 — Brace çıkarma (regex):
            Metindeki ilk { ile son } arasındaki alt dizeyi bul.
            Bu, "Here is the JSON:\n{...}" kalıplarını çözer.
        Strateji 4 — Satır satır tarama:
            { ile başlayan ilk satırı bul, oradan itibaren biriktir.
        """
        text = text.strip()

        # ---- Strateji 1: doğrudan ----------------------------------------
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # ---- Strateji 2: markdown code fence --------------------------------
        # ```json\n{...}\n```  veya  ```\n{...}\n```
        fence_match = re.search(
            r"```(?:json)?\s*(\{.*?\})\s*```",
            text,
            re.DOTALL | re.IGNORECASE,
        )
        if fence_match:
            candidate = fence_match.group(1).strip()
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass

        # ---- Strateji 3: ilk { … son } brace çıkarma ----------------------
        brace_match = re.search(r"\{.*\}", text, re.DOTALL)
        if brace_match:
            candidate = brace_match.group(0).strip()
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                # Brace eşleşmesi bulundu ama geçersiz JSON → yine de dene
                # (iç içe braces için greedy yerine en dış kapanışı bul)
                candidate = self._extract_outermost_braces(text)
                if candidate:
                    try:
                        return json.loads(candidate)
                    except json.JSONDecodeError:
                        pass

        # ---- Strateji 4: { ile başlayan satırdan itibaren biriktir ----------
        lines = text.splitlines()
        collecting = False
        buffer: list[str] = []
        depth = 0
        for line in lines:
            if not collecting and line.lstrip().startswith("{"):
                collecting = True
            if collecting:
                buffer.append(line)
                depth += line.count("{") - line.count("}")
                if depth <= 0:
                    break
        if buffer:
            candidate = "\n".join(buffer).strip()
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass

        return None  # Tüm stratejiler başarısız

    @staticmethod
    def _extract_outermost_braces(text: str) -> Optional[str]:
        """
        Metinde ilk açılan { ile ona karşılık gelen } arasındaki
        alt dizeyi karakter sayacıyla bulur.
        İç içe geçmiş brace'leri doğru işler.
        """
        start = text.find("{")
        if start == -1:
            return None
        depth = 0
        for i, ch in enumerate(text[start:], start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start: i + 1]
        return None

    # ------------------------------------------------------------------
    # Sağlık kontrolü
    # ------------------------------------------------------------------

    def health_check(self) -> bool:
        """Ollama sunucusunun ayakta olduğunu doğrular."""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=3)
            return resp.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def __repr__(self) -> str:
        return f"LLMClient(model={self.model!r}, base_url={self.base_url!r})"
