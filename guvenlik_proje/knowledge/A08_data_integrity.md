# A08:2021 - Yazılım ve Veri Bütünlüğü Hataları (Software and Data Integrity Failures)

## Tanım
Yazılım güncellemeleri, kritik veriler ve CI/CD pipeline'larında **bütünlük doğrulamasının eksik olması**. OWASP 2021'de yeni eklenen bir kategori, **8. sırada**. Insecure Deserialization bu kategoriye dahil edilmiştir.

## Yaygın Zafiyet Türleri

### Güvensiz Deserialization
Sunucuya gönderilen serileştirilmiş nesnenin doğrulanmadan deserialize edilmesi:
- **Python `pickle`:** Saldırgan kontrolündeki pickle verisi RCE'ye yol açar.
- **Java `ObjectInputStream.readObject()`:** Gadget chain'lerle RCE.
- **PHP `unserialize()`:** Magic method'larla (`__wakeup`, `__destruct`) RCE.
- **.NET BinaryFormatter / SoapFormatter:** RCE.

### İmzalanmamış / Doğrulanmamış Güncellemeler
- Auto-update mekanizmasının imza doğrulaması yapmaması.
- HTTPS olmayan kanaldan güncelleme indirme.
- Paket repository'sinin (npm, PyPI, Docker Hub) doğrulanmaması.

### CI/CD Pipeline Güvensizliği
- GitHub Actions secret'larının PR'larda sızdırılması.
- Build sürecinde dış kaynaktan rastgele script çalıştırma (`curl ... | bash`).
- Container image imzasız çekme.
- Pipeline değişikliklerinin code review'sız uygulanması.

### Güvensiz JWT Pattern'leri
- `alg: none` saldırısı: Token'ı imzasız hale getirme.
- Algorithm confusion: RS256 → HS256 saldırısı (public key'i HMAC anahtarı olarak kullanma).
- Zayıf HMAC secret'ı (sözlük saldırısına açık).

### Client-Side Trust
- Sepet toplamı, fiyat gibi kritik verilerin client'a güvenilerek alınması.
- Hidden form alanlarına güvenmek (`<input type="hidden" name="price" value="100">`).

### Subresource Integrity (SRI) Eksikliği
CDN'den yüklenen JS/CSS için integrity hash yok — CDN kompromize olursa supply-chain saldırısı.

### Tip Saldırı (Type Juggling) — PHP
`==` operatörü ile tip dönüştürme: `"0e123" == "0e456"` → true (scientific notation).

## Önlemler

1. **Güvenli deserialization:**
   - Pickle, BinaryFormatter, Java serialization gibi tehlikeli formatlardan kaçın.
   - **JSON tercih et:** Veri formatı için, kod çalıştırma yeteneği yok.
   - Zorunluysa imzalı veri kullan (HMAC ile bütünlük).
2. **Dijital imza:** Tüm yazılım güncellemeleri, paketler, kritik veriler imzalı olsun.
3. **Tedarik zinciri güvenliği:**
   - SBOM (Software Bill of Materials) tut.
   - Bağımlılık imzalarını doğrula (`pip install --require-hashes`).
   - Container image scanning (Trivy, Grype).
   - Sigstore / Cosign ile image imzalama.
4. **CI/CD koruması:**
   - Pipeline değişiklikleri code review'a tabi.
   - Secret'lar vault'ta, plaintext config'de değil.
   - Least privilege CI runner.
   - PR'lardan secret erişimini kısıtla.
5. **JWT için:**
   - `alg` header'ını sunucuda zorla; client'tan kabul etme.
   - Güçlü HMAC secret (≥32 byte random).
   - RS256/ES256 tercih et (asymmetric).
6. **SRI kullan:** CDN scriptleri için integrity hash zorunlu.
7. **Server-side kritik veri doğrulaması:** Fiyat, indirim, kullanıcı ID server'dan oku.
8. **Audit log:** Tüm CI/CD ve güncelleme işlemleri loglu.

## Güvenli Kod Örnekleri

### Pickle — Güvensiz
```python
import pickle
data = pickle.loads(request.body)  # RCE açığı
```

### JSON — Güvenli
```python
import json
data = json.loads(request.body)  # Sadece veri, kod yok
```

### JWT — Güvenli (Python)
```python
import jwt

# YANLIŞ: algoritma client'tan kabul ediliyor
decoded = jwt.decode(token, secret, algorithms=None)

# DOĞRU: sunucu algoritmayı zorlar
decoded = jwt.decode(
    token,
    public_key,
    algorithms=["RS256"]   # Açıkça liste, "none" asla
)
```

### SRI ile CDN — Güvenli
```html
<script
  src="https://cdn.example.com/jquery-3.7.0.min.js"
  integrity="sha384-NXgwF8Kv9SS1n0lF4i7ZHfYpHJOrh3JpHJOrh3JpHJOrh3JpHJOrh3JpHJOrh3Jp"
  crossorigin="anonymous">
</script>
```

### Pip Hash Doğrulama
```
# requirements.txt
flask==2.3.3 \
    --hash=sha256:09c347a92aa7ff4a8e7f3206795f30d826654baf38b873d0744cd571ca609efc

# Kurulum:
pip install --require-hashes -r requirements.txt
```

## İlgili CWE'ler
- CWE-345: Insufficient Verification of Data Authenticity
- CWE-353: Missing Support for Integrity Check
- CWE-426: Untrusted Search Path
- CWE-494: Download of Code Without Integrity Check
- CWE-502: Deserialization of Untrusted Data
- CWE-565: Reliance on Cookies without Validation and Integrity Checking
- CWE-784: Reliance on Cookies without Validation and Integrity Checking in a Security Decision
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere

## Test Edilebilir İmzalar
- Yanıt body'sinde Python pickle imzası (`\x80\x04`, `cposix\nsystem`)
- Java serialized object imzası (`\xac\xed\x00\x05`)
- JWT token'ında `alg: none` veya `alg: HS256` (RS256 olması gereken yerde)
- HTML'de `<script src="https://cdn..." >` etiketinde `integrity` yokluğu
- Form'da `<input type="hidden" name="price">` veya `name="amount">` gibi kritik alan
- `__wakeup`, `__destruct` içeren PHP serialized data
