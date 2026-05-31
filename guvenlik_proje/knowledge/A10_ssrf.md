# A10:2021 - Server-Side Request Forgery (SSRF)

## Tanım
Uygulamanın, kullanıcının kontrolü altındaki bir URL'e **sunucu tarafından istek göndermesi**. Saldırgan bu mekanizmayı kullanarak iç ağa, cloud metadata servislerine veya hassas endpoint'lere erişebilir. OWASP 2021'de yeni eklenen kategori, **10. sırada**. Modern bulut mimarileriyle birlikte ciddi etkiye sahip.

## Yaygın Saldırı Senaryoları

### İç Ağ Tarama
- `http://192.168.1.1`, `http://10.0.0.1`, `http://localhost:8080`
- Saldırgan iç servisleri, admin panellerini, veritabanı arayüzlerini keşfedebilir.

### Cloud Metadata Servisi (En Kritik!)
- **AWS:** `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- **GCP:** `http://metadata.google.internal/computeMetadata/v1/`
- **Azure:** `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
- Bu endpoint'lerden IAM credential'ları, instance bilgileri, API key'ler çekilebilir.

### Dosya Okuma (file://)
- `file:///etc/passwd`, `file:///proc/self/environ`
- URL fetcher'lar genelde file:// şemasını da destekler.

### Port Tarama
- `http://internal-host:22`, `http://internal-host:6379` (Redis)
- Yanıt süresinden veya hata mesajından port durumu çıkarılabilir.

### Protocol Smuggling
- `gopher://` ile SMTP/Redis/Memcached gibi text protocol'lere komut enjeksiyonu.
- `dict://`, `ftp://`, `ldap://` şemalarıyla farklı servislere erişim.

### Blind SSRF
- Yanıt görünmüyor ama dış sistemde etki var.
- Out-of-band: kontrolün doğrulanması için collaborator (Burp) kullanılır.

### Yaygın Açık Endpoint'ler
- URL preview / link unfurling özellikleri (Slack, Discord benzeri)
- Webhook URL doğrulaması
- "URL'den dosya import" özellikleri
- PDF generator'larda harici resim yükleme
- XML/SVG parser'lar (XXE ile birleşik)
- OAuth callback URL'leri

## Filter Bypass Teknikleri (Bilmek için)

### IP Encoding
- `127.0.0.1` → `127.1`, `0177.0.0.1` (octal), `2130706433` (decimal)
- IPv6: `[::1]`, `[::ffff:127.0.0.1]`

### DNS Rebinding
- Saldırgan domain'i bir an public IP, sonra `127.0.0.1` çözer.

### URL Parser Karışıklıkları
- `http://allowed-domain.com@evil.com/` → bazı parser'lar `evil.com`'a gider.
- `http://evil.com#allowed.com` veya `?allowed.com`.

### Redirect Chains
- Saldırgan domain'i 302 ile internal IP'ye yönlendirir.

## Önlemler

1. **Allowlist (whitelist) yaklaşımı:**
   - Sadece izin verilen domain/IP listesine istek at.
   - Blocklist (denylist) yetersiz — bypass kolay.
2. **DNS rebinding koruması:**
   - Hostname çöz, sonra çözülen IP'yi kontrol et, **aynı IP ile bağlantı kur** (TOCTOU önle).
3. **İç ağ ve metadata adreslerini engelle:**
   - `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
   - `169.254.0.0/16` (link-local, AWS/GCP/Azure metadata)
   - `::1`, `fc00::/7`, `fe80::/10`
   - `0.0.0.0`, `224.0.0.0/4` (multicast)
4. **Şema kısıtlaması:** Sadece `http` ve `https` izin ver. `file`, `gopher`, `dict`, `ftp` ASLA.
5. **Port kısıtlaması:** Sadece 80/443. Diğer portlar reddedilsin.
6. **Redirect takibini kapat veya kontrol et:** Manuel redirect handling, her hop'ta IP doğrula.
7. **Network segmentation:** Uygulama sunucusu metadata servisine erişememeli (security group/firewall).
8. **Cloud-specific:**
   - **AWS IMDSv2 zorunlu:** Session token gerektirir, SSRF büyük ölçüde engellenir.
   - GCP: `Metadata-Flavor: Google` header zorunluluğu.
9. **Response sanitization:** Hata mesajları ve yanıt body'si saldırgana iç bilgi sızdırmasın.
10. **Timeout ve retry kısıtı:** Brute force / scanning'i yavaşlat.

## Güvenli Kod Örnekleri

### Güvensiz
```python
import requests

@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    r = requests.get(url)  # SSRF açığı
    return r.text
```

### Güvenli — Allowlist
```python
import socket
import ipaddress
from urllib.parse import urlparse
import requests

ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}
BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # Cloud metadata
    ipaddress.ip_network("0.0.0.0/8"),
]

def is_safe_url(url: str) -> bool:
    parsed = urlparse(url)
    # Şema kontrolü
    if parsed.scheme not in ("http", "https"):
        return False
    # Allowlist
    if parsed.hostname not in ALLOWED_HOSTS:
        return False
    # IP çöz ve kontrol et
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    except Exception:
        return False
    for net in BLOCKED_NETWORKS:
        if ip in net:
            return False
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return False
    return True

@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    if not is_safe_url(url):
        return "URL not allowed", 403
    r = requests.get(url, timeout=5, allow_redirects=False)
    return r.text
```

### AWS IMDSv2 Konfigürasyonu
```bash
# Instance metadata service v2'yi zorla
aws ec2 modify-instance-metadata-options \
    --instance-id i-1234567890abcdef0 \
    --http-tokens required \
    --http-put-response-hop-limit 1
```

## İlgili CWE'ler
- CWE-918: Server-Side Request Forgery (SSRF)
- CWE-441: Unintended Proxy or Intermediary
- CWE-611: Improper Restriction of XML External Entity (XXE ile birleşik SSRF)

## Test Edilebilir İmzalar
- URL parametresi (`url=`, `target=`, `host=`, `dest=`, `redirect=`, `fetch=`, `image=`) ile dış istek tetikleme.
- `http://127.0.0.1`, `http://localhost`, `http://169.254.169.254` payload'larında 200 yanıtı veya iç servis cevabı.
- `file:///etc/passwd` payload'unda `root:x:0:0` içeren yanıt.
- `http://[::1]/`, `http://0/`, `http://2130706433/` gibi encoded localhost payload'ları için 200.
- Out-of-band: payload `http://attacker-controlled-domain.com/` → DNS log'da hit (Burp Collaborator).
- Time-based blind SSRF: `http://valid-host:81/` (kapalı port) → uzun timeout vs hızlı reset.
