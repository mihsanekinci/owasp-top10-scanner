# A06:2021 - Zafiyetli ve Eskimiş Bileşenler (Vulnerable and Outdated Components)

## Tanım
Uygulamanın kullandığı kütüphane, framework, runtime veya bileşenlerin **bilinen güvenlik açıklarına sahip sürümlerinin** kullanılması. OWASP 2021'de **6. sırada**.

## Yaygın Zafiyet Türleri

### Eskimiş Frontend Kütüphaneler
- jQuery <3.5.0 (XSS), AngularJS, eski Bootstrap sürümleri.
- Sürüm bilgisi HTML kaynağında veya `/static/js/jquery-1.x.x.js` gibi dosya adlarında.

### Eskimiş Backend Framework / Dil
- Django <3.2, Flask <2.0, Express <4.17, Spring Boot eski sürümler.
- PHP 5.x, Python 2.x, Node 12.x gibi EOL (End of Life) sürümler.

### CMS ve Eklenti Zafiyetleri
- WordPress core veya plugin'lerin patch'lenmemiş sürümleri.
- Drupal "Drupalgeddon" benzeri kritik CVE'ler.
- Joomla, Magento eski sürümler.

### Web Sunucu / Runtime
- Apache <2.4.49 (CVE-2021-41773 path traversal), Nginx eski sürümler.
- Tomcat, IIS, OpenSSL eskimiş sürümler.

### İstemci Tarafı CDN Riskleri
- Subresource Integrity (SRI) olmadan dış kaynaktan yüklenen JS.
- CDN'in kompromize olması durumunda supply-chain saldırısı.

### Tanınmış CVE Örnekleri
- **Log4Shell (CVE-2021-44228):** Log4j 2.x RCE.
- **Spring4Shell (CVE-2022-22965):** Spring Framework RCE.
- **Heartbleed (CVE-2014-0160):** OpenSSL bellek sızıntısı.
- **Shellshock (CVE-2014-6271):** Bash uzaktan kod çalıştırma.
- **CVE-2021-41773:** Apache HTTP Server path traversal.

## Önlemler

1. **Yazılım envanteri (SBOM) tut:** Tüm bağımlılıkların sürüm listesi.
2. **Otomatik bağımlılık tarama:** Snyk, Dependabot, OWASP Dependency-Check, Trivy, Grype.
3. **Sürüm pinning:** `requirements.txt` ve `package-lock.json` ile sürümleri sabitle.
4. **Düzenli güncelleme:** Patch'ler ayda en az bir kez gözden geçirilsin; kritik CVE'ler için hot-fix.
5. **Sadece resmi kaynaklardan indir:** Tipo-squatting (yanlış paket adı) saldırılarına dikkat.
6. **Kullanılmayan bağımlılıkları kaldır:** Saldırı yüzeyini azaltır.
7. **CDN'lerden gelen kaynaklar için SRI:**
   ```html
   <script src="https://cdn.example.com/lib.js"
           integrity="sha384-...."
           crossorigin="anonymous"></script>
   ```
8. **Sürüm bilgisini gizle:** `Server` ve `X-Powered-By` header'larını kaldır.
9. **EOL bileşenleri yükselt:** Üreticinin desteklemediği yazılım = ileride patch'lenmeyecek zafiyet.

## Güvenli Yapılandırma Örnekleri

### Python `requirements.txt` — Güvenli
```
# Sürümleri pinle
flask==2.3.3
requests==2.31.0
sqlalchemy==2.0.25

# Otomatik tarama: pip-audit veya safety
# $ pip-audit
# $ safety check
```

### Node.js — Güvenli
```bash
# Audit
npm audit
npm audit fix

# package.json'da exact sürüm
"dependencies": {
  "express": "4.18.2",     # ^ veya ~ yerine sabit
  "lodash": "4.17.21"
}
```

### Docker — Güvenli
```dockerfile
# YANLIŞ
FROM python:latest        # 'latest' tag'i belirsiz

# DOĞRU
FROM python:3.12.1-slim   # Spesifik sürüm
RUN pip install --no-cache-dir -r requirements.txt
```

## İlgili CWE'ler
- CWE-937: Using Components with Known Vulnerabilities
- CWE-1035: OWASP Top Ten 2017 Category A9
- CWE-1104: Use of Unmaintained Third Party Components

## Test Edilebilir İmzalar
- `Server: Apache/2.2.15 (CentOS)` gibi spesifik eski sürüm
- HTML kaynak: `<script src="/js/jquery-1.7.2.min.js">` veya `jquery-3.4.0.js`
- `X-Powered-By: PHP/5.4.16` veya `X-AspNet-Version: 2.0.50727`
- Meta tag: `<meta name="generator" content="WordPress 4.7">`
- `/wp-includes/`, `/sites/all/modules/` gibi CMS imzaları + sürüm bilgisi
- `npm`/`pip` bağımlılık taramasında "X vulnerabilities found"
