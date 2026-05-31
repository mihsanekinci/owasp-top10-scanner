# A03:2021 - Injection (Enjeksiyon)

## Tanım
Saldırgan tarafından kontrol edilen verinin, bir yorumlayıcıya (SQL motoru, OS shell, LDAP, XPath, tarayıcı DOM'u) **kod olarak** gönderilmesi. Uygulama girdiyi doğru ayrıştırmadığında saldırgan komut ekleyebilir. OWASP 2021'de **3. sırada**. XSS bu kategoriye dahil edilmiştir.

## Alt Türler

### SQL Injection (SQLi)
Kullanıcı girdisinin SQL sorgusuna doğrudan birleştirilmesi.

**Türleri:**
- **In-band (Classic):** Hata mesajı veya UNION ile veri doğrudan dönüş.
- **Blind Boolean:** Yanıt farkından (true/false) bilgi çıkarımı.
- **Blind Time-based:** `SLEEP(5)` gibi gecikme ile çıkarım.
- **Out-of-band:** DNS/HTTP üzerinden veri sızdırma.

**Tespit imzaları:**
- Yanıtta `SQL syntax`, `mysql_fetch`, `ORA-`, `PostgreSQL`, `SQLSTATE`, `unclosed quotation mark` hata metinleri.
- Tek tırnak (`'`) gönderildiğinde 500 hatası veya farklı yanıt.
- `' OR '1'='1` ile login bypass.

### Cross-Site Scripting (XSS)
Saldırganın tarayıcıda JavaScript çalıştırması.

**Türleri:**
- **Reflected XSS:** Payload URL/form üzerinden gelir, yanıtta yansır.
- **Stored XSS:** Payload veritabanına kaydedilir, sonradan başka kullanıcılara servis edilir.
- **DOM-based XSS:** Tamamen client-side, sunucuya hiç gitmeyebilir.

**Tespit imzaları:**
- `<script>alert(1)</script>` veya `"><svg onload=alert(1)>` payload'unun yanıtta encode edilmeden görünmesi.
- `Content-Type: text/html` yanıtında kullanıcı girdisinin filtresiz yer alması.

### Command Injection (OS Command)
Girdi shell komutuna birleştirilir: `os.system(f"ping {user_input}")`.
- İmzalar: `; ls`, `| cat /etc/passwd`, `` `whoami` ``, `$(id)`.

### LDAP / XPath / NoSQL Injection
- LDAP: `*)(uid=*))(|(uid=*` ile auth bypass.
- NoSQL (MongoDB): `{"$ne": null}`, `{"$gt": ""}` ile sorgu manipülasyonu.

## Önlemler

### SQL Injection
1. **Parametreli sorgular (prepared statements) kullan.** En etkili savunma.
2. ORM kullanıyorsan raw SQL'den kaçın; ORM API'lerine sadık kal.
3. **Stored procedure'lar** içinde dinamik SQL yapmaktan kaçın.
4. **Allowlist input validation:** Sayı bekleniyorsa sayı olduğunu doğrula.
5. **Least privilege DB user:** Uygulama DB kullanıcısı sadece gerekli tablolara erişebilsin.
6. **WAF:** Tek başına yeterli değil ama defense-in-depth katmanı.

### XSS
1. **Context-aware output encoding:**
   - HTML body → HTML entity encode (`&lt;`, `&gt;`, `&amp;`, `&quot;`)
   - HTML attribute → attribute encode
   - JavaScript context → JS string escape
   - URL context → URL encode
2. **Template engine'in auto-escape özelliğini kullan** (Jinja2, React JSX, Vue).
3. **Content Security Policy (CSP):** `script-src 'self'` ile inline script'leri yasakla.
4. **`HttpOnly` çerez:** XSS ile session cookie çalınmasını engeller.
5. **`innerHTML` yerine `textContent` kullan** (JavaScript).
6. **`X-XSS-Protection` (eskidi)** yerine CSP'ye güven.

### Command Injection
1. Mümkünse shell komutu çağırma; dil API'lerini kullan (`Path` modülü, `shutil`).
2. `subprocess.run([cmd, arg1, arg2], shell=False)` — argüman listesi, asla `shell=True`.
3. Girdiyi allowlist ile doğrula.

## Güvenli Kod Örnekleri

### SQL — Güvensiz
```python
query = f"SELECT * FROM users WHERE id = {user_id}"  # SQLi açığı
cursor.execute(query)
```

### SQL — Güvenli
```python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
# ORM:
User.query.filter_by(id=user_id).first()
```

### XSS — Güvensiz (Flask Jinja2)
```python
return f"<div>Merhaba {request.args['name']}</div>"  # XSS açığı
# Jinja2'de:
{{ name|safe }}  # YANLIŞ — escape'i devre dışı bırakır
```

### XSS — Güvenli
```python
# Flask: render_template auto-escape açıktır
return render_template("greet.html", name=request.args['name'])
# Jinja2'de:
{{ name }}  # Otomatik escape
```

### Command Injection — Güvenli
```python
import subprocess
subprocess.run(["ping", "-c", "1", host], shell=False, check=True)
# host allowlist kontrolünden geçirilmiş olmalı
```

## İlgili CWE'ler
- CWE-77: Command Injection
- CWE-78: OS Command Injection
- CWE-79: Cross-site Scripting (XSS)
- CWE-89: SQL Injection
- CWE-90: LDAP Injection
- CWE-91: XML Injection
- CWE-94: Code Injection
- CWE-643: XPath Injection

## Test Edilebilir İmzalar
- Tek tırnak `'` payload'unda yanıtta SQL hata mesajı
- `' OR 1=1--` payload'unda farklı (genelde daha çok satırlı) yanıt
- `SLEEP(5)` payload'unda 5+ saniyelik yanıt gecikmesi
- `<script>alert(1)</script>` payload'unun yanıtta aynen yer alması (encode edilmeden)
- `<svg onload=alert(1)>` payload'unun HTML olarak yansıması
