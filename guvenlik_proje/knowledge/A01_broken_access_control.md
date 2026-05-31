# A01:2021 - Bozuk Erişim Kontrolü (Broken Access Control)

## Tanım
Erişim kontrolü, kullanıcıların yalnızca yetkili oldukları kaynaklara ve işlemlere erişebilmesini sağlayan güvenlik mekanizmasıdır. Bu kontrolün eksik veya hatalı uygulanması, saldırganların yetkisiz veri okumasına, değiştirmesine veya silmesine yol açar. OWASP 2021 sıralamasında **1. sıradadır**.

## Yaygın Zafiyet Türleri

### IDOR (Insecure Direct Object Reference)
URL veya parametrelerdeki nesne ID'lerinin değiştirilerek başka kullanıcıların verilerine erişilmesi.
- Örnek: `GET /api/user/123/profile` → `GET /api/user/124/profile` ile başka kullanıcı profili açılabiliyor.
- Tespit ipucu: ID parametresi değiştiğinde HTTP 200 yanıtı dönüyor ve farklı kullanıcının verisi geliyor.

### Yetkisiz Fonksiyon Erişimi (Forced Browsing)
Admin paneli, gizli endpoint'ler ve yönetici işlemlerine doğrudan URL ile erişilmesi.
- Örnek: Normal kullanıcı `/admin/users/delete?id=5` URL'sini açabiliyor.

### Dikey Yetki Yükseltme (Vertical Privilege Escalation)
Normal kullanıcının admin yetkilerini kullanması (rol kontrolü eksik).

### Yatay Yetki Yükseltme (Horizontal Privilege Escalation)
Bir kullanıcının aynı seviyedeki başka bir kullanıcının kaynaklarına erişmesi.

### CORS Yanlış Yapılandırması
`Access-Control-Allow-Origin: *` ile birlikte `Allow-Credentials: true` gibi tehlikeli kombinasyonlar.

### JWT/Token Manipülasyonu
- `alg: none` saldırısı, zayıf imza anahtarı, token replay.

## Önlemler

1. **Varsayılan: erişim engelli (deny by default).** Açıkça izin verilmeyen her şey reddedilmelidir.
2. **Merkezi yetkilendirme mekanizması** kullanın — her endpoint'te tekrar tekrar kontrol yazmayın.
3. **Server-side yetki kontrolü zorunlu.** Client-side gizleme (UI'da butonu saklama) güvenlik değildir.
4. **Sahiplik (ownership) kontrolü:** Bir kaynağa erişilmeden önce kullanıcının o kaynağın sahibi/yetkilisi olduğu doğrulanmalı.
5. **Oturum yönetimi:** Çıkıştan sonra token'lar sunucuda da geçersiz kılınmalı.
6. **Rate limiting:** API ve login endpoint'leri için.
7. **JWT için:** Güçlü algoritma (RS256/ES256), kısa expiration, `alg` başlığı sunucuda zorlanmalı.
8. **Log ve izleme:** Başarısız erişim denemeleri loglanmalı, anormal pattern'ler alarm üretmeli.

## Güvenli Kod Örneği (Python/Flask)

### Güvensiz
```python
@app.route('/api/document/<int:doc_id>')
def get_document(doc_id):
    doc = Document.query.get(doc_id)  # YANLIŞ: sahip kontrolü yok
    return jsonify(doc.to_dict())
```

### Güvenli
```python
@app.route('/api/document/<int:doc_id>')
@login_required
def get_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if doc.owner_id != current_user.id and not current_user.is_admin:
        abort(403)  # Sahip kontrolü
    return jsonify(doc.to_dict())
```

## İlgili CWE'ler
- CWE-22: Path Traversal
- CWE-284: Improper Access Control
- CWE-285: Improper Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)
- CWE-862: Missing Authorization
- CWE-863: Incorrect Authorization

## Test Edilebilir İmzalar
- Farklı kullanıcı oturumlarıyla aynı kaynak ID'sine erişim → aynı sonuç dönüyorsa IDOR şüphesi.
- Çıkış sonrası eski token ile istek → 200 dönüyorsa oturum geçersizleştirme eksik.
- `/admin`, `/api/internal`, `/debug` gibi path'lere yetkisiz erişim → 200/403 ayrımı kritik.
