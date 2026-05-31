# A07:2021 - Kimlik Doğrulama ve Oturum Hataları (Identification and Authentication Failures)

## Tanım
Kullanıcı kimliğinin doğrulanmasında, oturum yönetiminde veya kimlik bilgilerinin korunmasında yapılan hatalar. Eski adıyla "Broken Authentication". OWASP 2021'de **7. sırada**.

## Yaygın Zafiyet Türleri

### Zayıf Parola Politikaları
- `123456`, `password`, `qwerty` gibi yaygın parolaların kabul edilmesi.
- Minimum uzunluk yok veya çok kısa (<8).
- Karmaşıklık zorunluluğu yok.

### Brute Force ve Credential Stuffing'e Açık
- Login endpoint'inde rate limit yok.
- Hesap kilitleme mekanizması yok.
- CAPTCHA yok.

### Zayıf Oturum Yönetimi
- Tahmin edilebilir session ID (artımlı sayılar, timestamp).
- Session ID URL'de (`?sessionid=abc`) — Referer ile sızıntı.
- Çıkışta session sunucuda invalidate edilmiyor.
- Session fixation: saldırgan bilinen bir session ID'yi kurbana atayabiliyor.

### Çok Faktörlü Kimlik Doğrulama Eksikliği
- Kritik işlemlerde (transfer, parola değiştirme) sadece tek faktörle doğrulama.

### Güvensiz Parola Kurtarma
- "Annenizin kızlık soyadı" gibi tahmin edilebilir güvenlik soruları.
- Sıfırlama token'ı brute-force'a açık (kısa, tahmin edilebilir).
- Token expiration yok veya çok uzun.
- Yeni parolanın email ile düz metin gönderilmesi.

### Düz Metin / Zayıf Parola Saklama
- Veritabanında parolaların düz metin tutulması.
- MD5/SHA1/SHA256 ile hashlenmesi (adaptif hash değil).
- Salt kullanılmaması.

### Username Enumeration
- "Kullanıcı bulunamadı" vs "Parola hatalı" gibi farklı mesajlar.
- Yanıt süresi farkı (var olan kullanıcı için hash hesaplaması, olmayan için anında dönüş).

### Remember-Me Token Güvensizliği
- Token uzun ömürlü ve revoke edilemiyor.
- Token tahmin edilebilir veya çalınabilir formatta.

## Önlemler

1. **MFA uygula:** Özellikle admin hesapları ve kritik işlemler için.
2. **Adaptif hash algoritması:** Argon2id, bcrypt (cost ≥12), scrypt, PBKDF2 (≥600k iterasyon).
3. **Parola politikası:**
   - Minimum 12 karakter (NIST SP 800-63B önerisi).
   - Bilinen sızdırılmış parolaları engelle (HaveIBeenPwned API).
   - Karmaşıklık yerine uzunluk önceliği.
4. **Rate limiting + hesap kilitleme:**
   - IP başına dakikada 5 deneme.
   - Hesap başına 10 başarısız → geçici kilit.
5. **Güvenli session yönetimi:**
   - Kriptografik random session ID (≥128 bit entropi).
   - `Secure; HttpOnly; SameSite=Strict` cookie bayrakları.
   - Sunucu tarafında session invalidation (logout, parola değişimi sonrası).
   - Idle timeout (15-30 dk), absolute timeout (8-24 saat).
6. **Session fixation koruması:** Login sonrası session ID yenile.
7. **Parola kurtarma:**
   - Tek kullanımlık, kısa ömürlü (15 dk) token.
   - Kriptografik güvenli random token (≥32 byte).
   - Token kullanıldığında geçersizleştir.
   - "Eğer kullanıcı varsa email gönderildi" jenerik mesaj (enumeration koruması).
8. **Generic error messages:** "Email veya parola hatalı" — hangisinin yanlış olduğunu söyleme.
9. **Timing attack koruması:** Constant-time comparison; var olmayan kullanıcı için bile hash hesaplaması yap.

## Güvenli Kod Örnekleri

### Parola Hashleme — Güvenli
```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher(
    time_cost=3, memory_cost=65536, parallelism=4
)

# Kayıt
hash = ph.hash(password)

# Doğrulama (constant-time)
try:
    ph.verify(stored_hash, input_password)
    if ph.check_needs_rehash(stored_hash):
        new_hash = ph.hash(input_password)  # Parametreler güncellendi, yeniden hash
except VerifyMismatchError:
    return False
```

### Login — Güvenli (Username Enumeration Koruması)
```python
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    email = request.form['email']
    password = request.form['password']

    user = User.query.filter_by(email=email).first()

    # Constant-time: kullanıcı yoksa bile hash hesapla
    if user:
        valid = ph.verify(user.password_hash, password)
    else:
        ph.verify(DUMMY_HASH, password)  # Timing attack koruması
        valid = False

    if not valid:
        return "Email veya parola hatalı", 401  # Generic mesaj

    session.regenerate_id()  # Session fixation koruması
    login_user(user)
    return redirect('/')
```

### Session Token — Güvenli
```python
import secrets
session_token = secrets.token_urlsafe(32)  # 256-bit entropi

response.set_cookie(
    'session',
    session_token,
    secure=True,
    httponly=True,
    samesite='Strict',
    max_age=3600
)
```

## İlgili CWE'ler
- CWE-256: Plaintext Storage of a Password
- CWE-287: Improper Authentication
- CWE-297: Improper Validation of Certificate with Host Mismatch
- CWE-307: Improper Restriction of Excessive Authentication Attempts
- CWE-384: Session Fixation
- CWE-521: Weak Password Requirements
- CWE-613: Insufficient Session Expiration
- CWE-620: Unverified Password Change

## Test Edilebilir İmzalar
- Login endpoint'inde 100+ ardışık başarısız denemenin engellenmemesi
- Var olan / olmayan kullanıcı için farklı yanıt mesajı veya süresi
- Session cookie'sinde `Secure` veya `HttpOnly` eksikliği
- Çıkış sonrası eski session token ile başarılı istek
- Login sonrası session ID'nin değişmemesi (fixation göstergesi)
- Parola sıfırlama token'ının kısa (8 karakterden az) veya tahmin edilebilir formatta olması
- `Set-Cookie` header'ında `SameSite` atribütü olmaması
