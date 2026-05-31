# A05:2021 - Güvenlik Yanlış Yapılandırması (Security Misconfiguration)

## Tanım
Uygulama, sunucu, framework, veritabanı veya bulut servislerinin **güvensiz varsayılan ayarlarla** veya eksik yapılandırmayla bırakılması. OWASP 2021'de **5. sırada**. XML External Entity (XXE) bu kategoriye dahil edilmiştir.

## Yaygın Zafiyet Türleri

### Varsayılan Kimlik Bilgileri
- `admin:admin`, `root:root`, `tomcat:tomcat`, `guest:guest`
- Yönetici paneli erişilebilir ve şifresi değiştirilmemiş.

### Açık Olan Gereksiz Özellikler
- Production'da debug mode (`DEBUG=True` Flask/Django'da)
- Stack trace yansıması (500 hata sayfasında dosya yolları, sürümler)
- Directory listing aktif (Apache `Options +Indexes`)
- HTTP TRACE/OPTIONS metodları açık

### Eksik Güvenlik Başlıkları
- `X-Frame-Options` (clickjacking)
- `X-Content-Type-Options: nosniff`
- `Content-Security-Policy`
- `Strict-Transport-Security`
- `Referrer-Policy`
- `Permissions-Policy`

### Açık Yönetim Arayüzleri
- `/phpmyadmin`, `/admin`, `/wp-admin`, `/.git`, `/.env` public erişilebilir.
- Cloud bucket'ların (S3, GCS) public okunabilir/yazılabilir olması.

### Eskimiş Yazılım Sürümleri
- Patch'lenmemiş framework, kütüphane, OS.
- `Server: Apache/2.2.15` gibi sürüm bilgisi sızıntısı.

### XML External Entity (XXE)
XML parser'ın dış varlık (external entity) referanslarını işlemesi:
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

### CORS Yanlış Yapılandırması
`Access-Control-Allow-Origin: *` ile birlikte hassas API'ler.

## Önlemler

1. **Sıkı baseline yapılandırma:** Tüm ortamlar (dev/staging/prod) için aynı sıkı template.
2. **Minimal platform:** Kullanılmayan özellikleri/portları/servisleri kapat.
3. **Varsayılan parolalar değiştirilsin:** Kurulumdan sonra ilk adım.
4. **Güvenlik başlıkları zorla:**
   ```
   Strict-Transport-Security: max-age=31536000; includeSubDomains
   X-Frame-Options: DENY
   X-Content-Type-Options: nosniff
   Content-Security-Policy: default-src 'self'
   Referrer-Policy: strict-origin-when-cross-origin
   ```
5. **Debug ve verbose hata mesajları production'da KAPALI.** Genel "Bir hata oluştu" mesajı yeterli; detay log'a yazılsın.
6. **Otomatik yapılandırma denetimi:** Trivy, Checkov, OpenSCAP, CIS benchmarks.
7. **XML parser'da DTD ve external entity'leri devre dışı bırak:**
   ```python
   from defusedxml import ElementTree as ET  # Güvenli parser
   ```
8. **Yama yönetimi:** Düzenli güncelleme + güvenlik bültenleri takibi.
9. **Cloud güvenlik:** Bucket policy'ler, IAM least privilege, public access block.

## Güvenli Kod / Yapılandırma Örnekleri

### Flask — Güvenli Üretim Ayarı
```python
app.config.update(
    DEBUG=False,                    # ASLA production'da True
    TESTING=False,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
)

@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

### Güvensiz XML — XXE Açığı
```python
import xml.etree.ElementTree as ET
tree = ET.parse(user_supplied_xml)  # XXE'ye açık
```

### Güvenli XML
```python
from defusedxml import ElementTree as ET
tree = ET.parse(user_supplied_xml)  # XXE engellendi
```

## İlgili CWE'ler
- CWE-2: 7PK - Environment
- CWE-11: ASP.NET Misconfiguration
- CWE-13: ASP.NET Misconfiguration: Password in Configuration File
- CWE-15: External Control of System or Configuration Setting
- CWE-16: Configuration
- CWE-260: Password in Configuration File
- CWE-611: Improper Restriction of XML External Entity (XXE)
- CWE-614: Sensitive Cookie Without Secure Flag

## Test Edilebilir İmzalar
- Yanıt header'larında `X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security` eksikliği
- Yanıt body'sinde stack trace (`Traceback`, `at java.`, `File "/`, line number'lar)
- `/.git/config`, `/.env`, `/admin`, `/phpmyadmin` path'lerine 200 dönüşü
- `Server:` veya `X-Powered-By:` header'larında detaylı sürüm bilgisi
- Directory listing göstergesi: `Index of /`, `<title>Index of`
- Default credential ile login denemesinin başarılı olması
