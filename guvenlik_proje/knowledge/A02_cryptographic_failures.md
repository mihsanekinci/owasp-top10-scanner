# A02:2021 - Kriptografik Hatalar (Cryptographic Failures)

## Tanım
Hassas verilerin (parolalar, kredi kartı numaraları, sağlık bilgileri, kişisel veriler) ya hiç şifrelenmemesi ya da zayıf/eskimiş algoritmalarla şifrelenmesi sonucu açığa çıkması. Eski adıyla "Sensitive Data Exposure". OWASP 2021'de **2. sırada**.

## Yaygın Zafiyet Türleri

### Düz Metin İletim (Cleartext Transmission)
HTTP üzerinden parola, token, kişisel veri gönderimi.
- Tespit ipucu: HTTPS olmayan login formu, `http://` URL'lerinde `Authorization` header'ı.

### Zayıf TLS / SSL Yapılandırması
- TLS 1.0/1.1, SSLv3 desteği
- Zayıf cipher suite'ler (RC4, DES, 3DES, NULL, EXPORT)
- Eksik HSTS header'ı (`Strict-Transport-Security`)
- Geçersiz/self-signed sertifika

### Eskimiş Hash Algoritmaları
- **MD5, SHA1:** Parola hashleme veya bütünlük için kullanılmamalı.
- **Salt'sız hash:** Aynı parola her zaman aynı hash'i üretir → rainbow table saldırısı.
- **Düz SHA-256:** Hızlı olduğu için parola için yetersiz (GPU brute-force).

### Sabit Anahtarlar (Hardcoded Secrets)
Kaynak kodda, repo'da, config dosyalarında API key, parola, özel anahtar.

### Zayıf Rastgelelik
`Math.random()`, `rand()` gibi kriptografik olmayan PRNG'lerin token/secret üretiminde kullanılması.

### Çerez Güvenliği Eksikliği
Session cookie'lerinde `Secure`, `HttpOnly`, `SameSite` bayraklarının eksik olması.

### Hassas Verinin Önbelleğe Alınması
`Cache-Control: public` ile hassas yanıtların proxy/CDN'lerde önbelleklenmesi.

## Önlemler

1. **Tüm iletimleri TLS ile şifrele** — HTTP'yi tamamen kapat, HSTS uygula.
2. **TLS 1.2+ zorunlu**, tercihen TLS 1.3. Zayıf cipher'ları devre dışı bırak.
3. **Parolalar için adaptif hash:** Argon2id (önerilen), bcrypt, scrypt veya PBKDF2 (yeterli iterasyonla).
4. **Salt + pepper kullan:** Her parola için benzersiz salt, ortak pepper sunucu tarafında.
5. **Simetrik şifreleme için AES-GCM veya ChaCha20-Poly1305** (AEAD modları).
6. **Anahtarları kod dışında tut:** Vault, AWS KMS, env değişkenleri, secret manager.
7. **Kriptografik güvenli rastgelelik:** Python `secrets`, Node `crypto.randomBytes`, Java `SecureRandom`.
8. **Çerezler:** `Secure; HttpOnly; SameSite=Strict` (oturum için).
9. **Hassas yanıtlar için:** `Cache-Control: no-store`.
10. **Eski algoritmaları yasakla:** MD5, SHA1, DES, 3DES, RC4, ECB modu, MD4.

## Güvenli Kod Örnekleri (Python)

### Parola Hashleme — Güvenli
```python
from argon2 import PasswordHasher

ph = PasswordHasher()
hash = ph.hash(password)         # Kayıt sırasında
ph.verify(hash, input_password)  # Giriş sırasında (exception fırlatır)
```

### Parola Hashleme — YANLIŞ
```python
import hashlib
hash = hashlib.md5(password.encode()).hexdigest()  # ASLA YAPMA
hash = hashlib.sha256(password.encode()).hexdigest()  # Parola için yetersiz
```

### Token Üretimi — Güvenli
```python
import secrets
token = secrets.token_urlsafe(32)  # Kriptografik güvenli
```

### AES-GCM Şifreleme
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)
nonce = secrets.token_bytes(12)
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
```

## İlgili CWE'ler
- CWE-259: Hardcoded Password
- CWE-261: Weak Encoding for Password
- CWE-310: Cryptographic Issues
- CWE-319: Cleartext Transmission of Sensitive Information
- CWE-321: Use of Hard-coded Cryptographic Key
- CWE-326: Inadequate Encryption Strength
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- CWE-331: Insufficient Entropy
- CWE-916: Use of Password Hash With Insufficient Computational Effort

## Test Edilebilir İmzalar
- `http://` üzerinden login formu sunumu
- Yanıt başlığında `Strict-Transport-Security` yokluğu
- Çerezlerde `Secure` veya `HttpOnly` eksikliği
- TLS handshake'te zayıf cipher (test: `nmap --script ssl-enum-ciphers`)
- API yanıtında MD5/SHA1 görünen hash pattern'i (32 hex / 40 hex karakter)
