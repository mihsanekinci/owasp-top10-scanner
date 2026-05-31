# A04:2021 - Güvensiz Tasarım (Insecure Design)

## Tanım
Uygulamanın **tasarım aşamasında** güvenlik gereksinimlerinin atlanması veya yanlış kurgulanması. Bu kategori implementasyon hatası değil — kod doğru yazılmış olsa bile mimari/iş mantığı güvenliği sağlamıyor. OWASP 2021'de yeni eklenen bir kategori, **4. sırada**.

## Yaygın Zafiyet Türleri

### İş Mantığı Zafiyetleri (Business Logic Flaws)
- Negatif miktarla alışveriş: `quantity = -5` → bakiye artıyor.
- Çoklu indirim kuponu uygulanması (race condition).
- Para transferinde aynı işlemin iki kez gönderilmesi (idempotency yok).

### Eksik Rate Limiting / Brute Force Koruması
- Login endpoint'inde sınırsız deneme hakkı.
- OTP/SMS doğrulama kodlarının kısıtsız denenmesi.
- Parola sıfırlama token'ının brute-forceable olması.

### Eksik İş Akışı Doğrulaması
- Ödeme adımı atlanarak doğrudan "sipariş onayı" sayfasına gidilebilmesi.
- Çok adımlı form'da ara adımların atlanabilmesi.

### Güvensiz Parola Kurtarma
- "Annenizin kızlık soyadı" gibi tahmin edilebilir güvenlik soruları.
- Parola sıfırlama mailindeki token'ın URL'den sızması (Referer header).
- Yeni parolanın mail ile düz metin gönderilmesi.

### Eksik Threat Modeling
- Kritik fonksiyonların threat model'inin yapılmaması.
- Güvensiz varsayılan ayarlar (default deny yerine default allow).

## Önlemler

1. **Threat modeling yap:** STRIDE, PASTA gibi metodolojilerle her özellik için.
2. **Secure SDLC:** Tasarım aşamasında güvenlik mimar incelemesi.
3. **Misuse case'leri yaz:** Kullanım senaryoları yanında kötüye kullanım senaryolarını da modelle.
4. **Rate limiting katmanı:** API gateway veya middleware seviyesinde.
5. **Tier-based segmentation:** Kullanıcı / iş ortağı / admin için farklı katmanlar.
6. **İş mantığı testleri:** Birim testlerde negatif/uç senaryoları kapsa.
7. **Defense in depth:** Tek katmana güvenme — kontrolleri tekrarla.
8. **Idempotency key:** Kritik işlemlerde duplicate request koruması.
9. **Captcha / device fingerprinting:** Otomatize saldırılara karşı.

## Güvenli Kod Örneği

### Güvensiz (Rate Limit Yok)
```python
@app.route('/login', methods=['POST'])
def login():
    user = User.query.filter_by(email=request.form['email']).first()
    if user and user.check_password(request.form['password']):
        login_user(user)
        return redirect('/')
    return "Hatalı giriş", 401
```

### Güvenli
```python
from flask_limiter import Limiter

limiter = Limiter(get_remote_address, app=app)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Rate limit
def login():
    email = request.form['email']
    if is_account_locked(email):
        return "Hesap geçici olarak kilitli", 423
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(request.form['password']):
        reset_failed_attempts(email)
        login_user(user)
        return redirect('/')
    record_failed_attempt(email)
    return "Hatalı giriş", 401
```

## İlgili CWE'ler
- CWE-209: Information Exposure Through Error Message
- CWE-256: Plaintext Storage of Password
- CWE-501: Trust Boundary Violation
- CWE-522: Insufficiently Protected Credentials
- CWE-840: Business Logic Errors
- CWE-1021: Improper Restriction of Rendered UI Layers

## Test Edilebilir İmzalar
- Login endpoint'inde 50+ ardışık başarısız denemenin engellenmemesi
- Negatif sayı / aşırı büyük sayı parametrelerinin kabul edilmesi
- Aynı işlemin (transfer, sipariş) tekrar gönderilmesinin engellenmemesi
- Form adımlarının atlanabilmesi (URL doğrudan ileri adıma gitme)
- "Forgot password" akışında token'ın 24+ saat geçerli kalması
