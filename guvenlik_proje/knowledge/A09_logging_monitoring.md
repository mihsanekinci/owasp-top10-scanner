# A09:2021 - Güvenlik Loglama ve İzleme Hataları (Security Logging and Monitoring Failures)

## Tanım
Saldırıların ve güvenlik olaylarının tespit edilmesi, müdahale edilmesi ve adli analiz yapılabilmesi için gerekli loglama ve izlemenin **eksik veya yetersiz** olması. OWASP 2021'de **9. sırada**.

## Yaygın Zafiyet Türleri

### Eksik Loglama
- Login başarı/başarısızlık olayları kaydedilmiyor.
- Yetkilendirme ihlalleri (403'ler) loglanmıyor.
- Yüksek değerli işlemler (transfer, parola değişimi, admin aksiyonları) loglanmıyor.
- Input validation hatalarının loglanmaması.

### Yetersiz Log Detayı
- Sadece "hata oluştu" — kullanıcı, IP, timestamp, request ID yok.
- Hata kodu var ama bağlam yok.
- Timestamp UTC değil veya format tutarsız.

### Loglarda Hassas Veri Sızıntısı
- Parolaların loglara düşmesi.
- Kredi kartı, SSN, sağlık verisi loglara yazılması.
- Session token / API key loglara düşüyor.
- KVKK/GDPR ihlali riski.

### Logların Güvensiz Saklanması
- Log dosyalarının dünya-okunabilir olması (`chmod 777`).
- Logların merkezi bir SIEM'e gönderilmemesi.
- Log retention politikası yok (çok kısa veya çok uzun).
- Logların değiştirilebilir olması (append-only değil).

### Gerçek Zamanlı Tespit Eksikliği
- Brute force, SQLi denemesi gibi pattern'lerin anında tespit edilmemesi.
- Alarm sistemi yok veya alarm yorgunluğu (alert fatigue) var.
- SIEM/SOAR entegrasyonu yok.

### Log Injection
Kullanıcı girdisinin doğrudan log'a yazılması — log parsing'i karıştırabilir veya XSS (log viewer'ında).
```
log.info(f"User login: {request.form['username']}")
# Saldırgan: username="admin\n[INFO] User login: victim"
```

### Olay Müdahale Planının Olmaması
- IR (Incident Response) playbook yok.
- Görev ve sorumluluklar belirsiz.
- Tatbikat yapılmıyor.

## Önlemler

1. **Loglanması gereken olaylar (minimum):**
   - Login: başarı, başarısızlık, hesap kilitlenmesi
   - Yetkilendirme: 403'ler, yetki yükseltme denemeleri
   - Yüksek değerli işlemler: ödeme, transfer, kullanıcı yönetimi
   - Input validation hataları
   - Server-side hatalar (5xx)
   - Admin paneli erişimleri
2. **Log içeriği (her olay için):**
   - Timestamp (ISO 8601, UTC)
   - User ID + session ID (anonim ise IP)
   - Source IP, user agent
   - HTTP method, endpoint
   - Olay türü (auth_fail, perm_denied vs.)
   - Sonuç (success/fail)
   - Request ID (trace için)
3. **Hassas veri loglamasını engelle:**
   - Parola, token, kart bilgisi log filter'larında maskelenmeli.
   - PII redaction.
4. **Yapılandırılmış loglama:** JSON formatı, parse edilebilir.
5. **Merkezi log yönetimi:** ELK, Splunk, Graylog, Datadog, CloudWatch.
6. **Tamper-proof loglar:** Append-only, ayrı sunucu, write-once medya, log shipping.
7. **Gerçek zamanlı izleme:**
   - Brute force pattern (1 dk içinde 10+ login fail)
   - SQLi / XSS pattern'leri WAF/IDS'te
   - Anormal trafik
   - Privilege escalation denemeleri
8. **Alarm tasarımı:**
   - Tier-based (info/warning/critical)
   - Alert fatigue önlemek için tuning
   - On-call rotation
9. **Log injection koruması:** Kullanıcı girdisini log'a yazmadan escape et veya yapılandırılmış log kullan.
10. **Incident Response playbook:** Detection → containment → eradication → recovery → lessons learned.

## Güvenli Kod Örnekleri

### Yapılandırılmış Loglama (Python)
```python
import logging
import json

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "user_id": getattr(record, "user_id", None),
            "request_id": getattr(record, "request_id", None),
            "source_ip": getattr(record, "source_ip", None),
        }
        return json.dumps(log)

logger.info(
    "login_attempt",
    extra={
        "user_id": user.id,
        "source_ip": request.remote_addr,
        "request_id": g.request_id,
        "success": False,
        "reason": "wrong_password",
    }
)
```

### Hassas Veri Maskeleme
```python
import re

def mask_sensitive(text: str) -> str:
    # Kredi kartı
    text = re.sub(r'\b\d{13,19}\b', '[CARD]', text)
    # Email
    text = re.sub(r'[\w\.-]+@[\w\.-]+', '[EMAIL]', text)
    # Authorization header
    text = re.sub(r'Bearer\s+[\w\.-]+', 'Bearer [REDACTED]', text)
    return text

class RedactFilter(logging.Filter):
    def filter(self, record):
        record.msg = mask_sensitive(str(record.msg))
        return True
```

### Brute Force Tespiti
```python
def detect_brute_force(user_email: str) -> bool:
    key = f"login_fail:{user_email}"
    count = redis.incr(key)
    redis.expire(key, 300)  # 5 dk pencere
    if count > 10:
        send_alert(f"Brute force suspected: {user_email}")
        return True
    return False
```

## İlgili CWE'ler
- CWE-117: Improper Output Neutralization for Logs (Log Injection)
- CWE-223: Omission of Security-relevant Information
- CWE-532: Insertion of Sensitive Information into Log File
- CWE-778: Insufficient Logging

## Test Edilebilir İmzalar
- Login fail sonrası `Set-Cookie`, response header veya body'de log referansı olmaması
- Yanıtta detaylı server-side hatanın olması ama log dosyasına yansıyıp yansımadığını kara kutu testinde doğrulamak zor (heuristik)
- API yanıtında `X-Request-ID` veya `X-Trace-ID` header'larının yokluğu (correlation eksikliği göstergesi)
- 500 hatasında jenerik mesaj yerine stack trace (paradoxal: hem A05 hem A09 imzası)
- Sürekli başarısız login denemelerine rağmen hesap kilitleme yok (engelleme ≠ loglama ama korelasyonlu)
