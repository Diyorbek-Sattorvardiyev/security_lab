# 🔐 Web Security Lab – Attack & Defense Platform

> **Mini OWASP WebGoat** — SQL Injection, XSS, CSRF simulyatsiyasi bilan to'liq security lab platforma.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green)
![SQLite](https://img.shields.io/badge/SQLite-3-blue)
![Security](https://img.shields.io/badge/OWASP-Top10-red)

---

## 📸 Platformada nima bor?

| Modul | Hujum | Himoya |
|-------|-------|--------|
| SQL Injection Lab | `' OR '1'='1'--` | Parameterized Queries |
| XSS Lab | `<script>alert('XSS')</script>` | HTML Escaping |
| CSRF Lab | Cross-origin forged request | CSRF Token |
| Security Dashboard | Real-time attack logs | Attack statistics |
| Vulnerability Scanner | Input risk analysis | Risk scoring |

---

## 🚀 O'rnatish va ishga tushirish

### 1. Talablar
- Python 3.10+
- pip

### 2. Virtual muhit yaratish
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

### 3. Kutubxonalarni o'rnatish
```bash
pip install -r requirements.txt
```

### 4. Serverni ishga tushirish
```bash
cd security_lab
python main.py
```

Yoki:
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 5. Brauzerda ochish
```
http://localhost:8000
```

---

## 👤 Demo foydalanuvchilar

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | admin |
| diyorbek | user123 | user |

---

## 📁 Loyiha strukturasi

```
security_lab/
│
├── main.py              # FastAPI application
├── database.py          # SQLite setup & init
├── schemas.py           # Pydantic models
├── requirements.txt     # Dependencies
│
├── routers/
│   ├── auth.py          # Register, Login, Logout
│   ├── lab_sql.py       # SQL Injection lab
│   ├── lab_xss.py       # XSS lab
│   ├── lab_csrf.py      # CSRF lab
│   └── dashboard.py     # Stats, scanner, logs
│
├── security/
│   ├── sql_injection_detector.py  # SQLi pattern detection
│   ├── xss_filter.py              # XSS sanitization
│   ├── csrf_protection.py         # Token management
│   └── attack_logger.py           # Log to database
│
├── templates/
│   └── index.html       # FastAPI Jinja2 template
│
└── static/
    ├── css/
    │   └── main.css     # Dark cyberpunk design
    ├── js/
    │   ├── main.js      # Shared auth logic
    │   ├── sql_lab.js   # SQL lab interactions
    │   ├── xss_lab.js   # XSS lab interactions
    │   ├── csrf_lab.js  # CSRF lab interactions
    │   └── dashboard.js # Dashboard & scanner
    ├── sql_lab.html
    ├── xss_lab.html
    ├── csrf_lab.html
    └── dashboard.html
```

---

## 🧪 Lab qo'llanmasi

### SQL Injection Lab
1. `/static/sql_lab.html` sahifasini oching
2. **VULNERABLE** panelda `' OR '1'='1'--` kiriting
3. "Attempt SQL Injection" bosing — login bypass bo'ladi
4. **SECURE** panelga o'ting — bir xil payload bloklanadi
5. Pastda attack log ko'rishingiz mumkin

### XSS Lab
1. `/static/xss_lab.html` sahifasini oching
2. **VULNERABLE** panelda `<script>alert('XSS!')</script>` kiriting
3. Script brauzerda ishlaydi!
4. **SECURE** panelda — HTML escape qilinadi, script ishlamaydi

### CSRF Lab
1. `/static/csrf_lab.html` sahifasini oching
2. "Launch CSRF Attack" — boshqa saytdan kelgan request qabul qilinadi
3. "Secure Update" — CSRF token bilan himoyalanadi
4. "Forge Token" — soxta token rad etiladi

### Dashboard
1. `/static/dashboard.html` sahifasini oching
2. Barcha hujumlar real-time statistikada ko'rinadi
3. **Vulnerability Scanner** — har qanday inputni tekshiring
4. Attack logs jadvalida barcha hujumlar saqlanadi

---

## 🛡️ Xavfsizlik texnologiyalari

| Texnologiya | Maqsad |
|-------------|--------|
| `bcrypt` | Password hashing |
| `parameterized queries` | SQL Injection himoyasi |
| `html.escape()` | XSS himoyasi |
| `secrets.token_hex()` | CSRF token generatsiyasi |
| `httponly cookies` | Session himoyasi |

---

## 🎓 O'quv maqsadi

Bu loyiha quyidagilar uchun ideal:

- ✅ **Cybersecurity portfolio** proyekti
- ✅ **Universitet kurs ishi** yoki diplom ishi
- ✅ **GitHub** showcase proyekti
- ✅ **OWASP Top 10** o'rganish uchun amaliy platforma
- ✅ **Junior Security Engineer** intervyuga tayyorgarlik

---

## ⚠️ Muhim eslatma

> Bu platforma **faqat ta'lim maqsadida** yaratilgan.
> Real serverlarga qarshi hujumlarni amalga oshirish **qonunga xilof**.
> Faqat o'z tizimingizda yoki ruxsat berilgan muhitda ishlating.

---

## 👨‍💻 Muallif

**Diyorbek** — Web Security Lab 2024

---

*Mini OWASP WebGoat ilhomlangan loyiha* 🔐
