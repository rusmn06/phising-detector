# 🛡️ Email Phishing Scanner

Aplikasi web untuk mendeteksi email phishing secara otomatis. Upload file `.eml` atau langsung scan URL untuk mengetahui apakah email/tautan tersebut mengandung ancaman phishing.

![Tech Stack](https://img.shields.io/badge/Backend-FastAPI-009688?style=flat-square&logo=fastapi)
![Tech Stack](https://img.shields.io/badge/Frontend-React%20%2B%20Vite-61DAFB?style=flat-square&logo=react)
![Tech Stack](https://img.shields.io/badge/Database-SQLite-003B57?style=flat-square&logo=sqlite)
![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?style=flat-square&logo=python)

---

## 📋 Daftar Isi

1. [Fitur Utama](#-fitur-utama)
2. [Tech Stack](#-tech-stack)
3. [Struktur Folder](#-struktur-folder)
4. [Prasyarat](#-prasyarat)
5. [Instalasi & Menjalankan](#-instalasi--menjalankan)
6. [Konfigurasi Environment Variables](#-konfigurasi-environment-variables)
7. [API Endpoints](#-api-endpoints)
8. [Cara Kerja Scoring](#-cara-kerja-scoring)
9. [Struktur Modul Backend](#-struktur-modul-backend)

---

## ✨ Fitur Utama

- **Scan Email (.eml)** — Upload file email dan dapatkan analisis lengkap:
  - Verifikasi otentikasi pengirim (SPF, DKIM, DMARC)
  - Deteksi URL berbahaya di dalam isi email
  - Skor risiko dan verdict otomatis (*safe / suspicious / phishing*)
- **Scan URL Langsung** — Cek sebuah URL tanpa perlu file email
- **Riwayat Scan** — Semua hasil scan tersimpan di database dengan fitur filter & pencarian
- **Dashboard Statistik** — Ringkasan total scan, breakdown verdict, dan aktivitas terkini
- **Rate Limiting** — Perlindungan terhadap penyalahgunaan API
- **Sanitasi HTML** — Output HTML dari email di-sanitize untuk mencegah XSS

---

## 🛠️ Tech Stack

### Backend
| Komponen | Teknologi |
|----------|-----------|
| Framework | FastAPI 0.135 |
| Runtime | Python 3.12+ |
| ORM / Database | SQLAlchemy 2.0 + SQLite |
| Validasi | Pydantic v2 |
| DNS & DMARC | dnspython, checkdmarc |
| Email Parsing | mail-parser |
| URL Threat Detection | Google Safe Browsing API / VirusTotal API v3 |
| Sanitasi HTML | bleach |
| File Validation | python-magic-bin |
| Server | Uvicorn |

### Frontend
| Komponen | Teknologi |
|----------|-----------|
| Framework | React 19 |
| Build Tool | Vite 8 |
| Styling | Tailwind CSS 4 |
| HTTP Client | Axios |
| Routing | React Router DOM v7 |
| File Upload | react-dropzone |
| Icons | lucide-react |

---

## 📁 Struktur Folder

```
phishing-detector-2/
│
├── backend/                        # FastAPI Application
│   ├── core/                       # Business Logic Utama
│   │   ├── analysis.py             # Analisis SPF/DKIM/DMARC + Scoring
│   │   ├── dns_resolver.py         # DNS Resolver dengan timeout control
│   │   ├── email_parser.py         # Parsing file .eml
│   │   ├── rate_limiter.py         # Quota manager per provider
│   │   ├── safe_browsing.py        # Adapter Google Safe Browsing API
│   │   ├── threat_detector.py      # Factory: pilih provider deteksi URL
│   │   ├── url_extractor.py        # Ekstraksi URL dari isi email
│   │   └── virustotal.py           # Adapter VirusTotal API v3
│   │
│   ├── routes/                     # API Routers
│   │   └── history.py              # Endpoint riwayat & statistik
│   │
│   ├── utils/                      # Utility Functions
│   │   ├── file_validator.py       # Validasi Magic Bytes & ukuran file
│   │   └── sanitizer.py            # Sanitasi HTML output (bleach)
│   │
│   ├── data/                       # SQLite database (auto-generated)
│   ├── config.py                   # Konfigurasi via Pydantic Settings
│   ├── database.py                 # Init DB, model ORM, cleanup
│   ├── main.py                     # Entry point & endpoint utama
│   ├── models.py                   # Pydantic schema request/response
│   └── requirements.txt            # Python dependencies
│
├── frontend/                       # React Application
│   ├── src/
│   │   ├── components/             # UI Components
│   │   │   ├── Dashboard.jsx       # Halaman statistik overview
│   │   │   ├── ScanEmail.jsx       # Halaman scan file .eml
│   │   │   ├── ScanURL.jsx         # Halaman scan URL langsung
│   │   │   ├── History.jsx         # Halaman riwayat scan
│   │   │   └── Layout.jsx          # Layout utama dengan navigasi
│   │   ├── services/
│   │   │   └── api.js              # Axios instance & API calls
│   │   ├── App.jsx                 # Root component & routing
│   │   └── main.jsx                # Entry point React
│   ├── package.json
│   └── vite.config.js
│
├── .env.example                    # Template environment variables
├── .gitignore
├── start-dev.bat                   # Script dev untuk Windows
└── README.md
```

---

## 📦 Prasyarat

- **Python 3.12+** dan `pip`
- **Node.js 18+** dan `npm`
- API Key dari salah satu (atau keduanya):
  - [VirusTotal](https://www.virustotal.com/gui/my-apikey)
  - [Google Safe Browsing](https://console.cloud.google.com/apis/credentials)

---

## 🚀 Instalasi & Menjalankan

### Cara Cepat (Windows)

```bash
# Jalankan script dev (membuka backend & frontend sekaligus)
start-dev.bat
```

### Manual

#### 1. Clone & Setup Environment Variables
```bash
cp .env.example .env
# Lalu edit .env dan isi API key yang diperlukan
```

#### 2. Setup Backend
```bash
cd backend
python -m venv .venv

# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

uvicorn main:app --reload
# Backend berjalan di http://localhost:8000
```

#### 3. Setup Frontend
```bash
cd frontend
npm install
npm run dev
# Frontend berjalan di http://localhost:5173
```

---

## ⚙️ Konfigurasi Environment Variables

Salin `.env.example` ke `.env` dan sesuaikan nilainya:

```env
# === Application ===
APP_ENV=development
API_V1_STR=/api/v1
PROJECT_NAME=Email Phishing Scanner

# === API Keys (wajib diisi salah satu atau keduanya) ===
# Dapatkan di: https://console.cloud.google.com/apis/credentials
GOOGLE_SAFE_BROWSING_API_KEY=your_google_api_key_here

# Dapatkan di: https://www.virustotal.com/gui/my-apikey
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# === URL Threat Detection Provider ===
# Pilihan: "google_safe_browsing" | "virustotal" | "both"
URL_THREAT_PROVIDER=virustotal

# === Rate Limiting ===
RATE_LIMIT=5/minute

# === DNS ===
DNS_TIMEOUT=10.0
DNS_NAMESERVERS=8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1

# === Database ===
DATABASE_URL=sqlite:///./backend/data/scan_history.db
HISTORY_RETENTION_DAYS=30

# === Server ===
UVICORN_HOST=0.0.0.0
UVICORN_PORT=8000
CORS_ORIGINS=http://localhost:5173,http://localhost:3000
```

---

## 🔌 API Endpoints

Base URL: `http://localhost:8000/api/v1`

| Method | Endpoint | Deskripsi |
|--------|----------|-----------|
| `GET` | `/health` | Health check aplikasi |
| `GET` | `/quota-status` | Status kuota API (VirusTotal & Google) |
| `POST` | `/scan` | Scan file email `.eml` |
| `POST` | `/scan-url` | Scan URL secara langsung |
| `GET` | `/history` | Daftar riwayat scan (dengan filter & pagination) |
| `GET` | `/history/{id}` | Detail hasil scan berdasarkan ID |
| `DELETE` | `/history/{id}` | Hapus record scan |
| `POST` | `/history/cleanup` | Hapus record lama secara manual |
| `GET` | `/dashboard/stats` | Statistik untuk halaman dashboard |
| `GET` | `/history/cleanup/logs` | Log aktivitas cleanup |

> 📖 Dokumentasi interaktif tersedia di: `http://localhost:8000/api/v1/docs`

### Contoh Request: Scan Email

```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -F "file=@contoh-email.eml"
```

### Contoh Response: Scan Email

```json
{
  "verdict": "phishing",
  "risk_score": 90,
  "scan_id": 42,
  "scanned_at": "2026-04-14T04:00:00",
  "risk_factors": [
    "DMARC verification failed",
    "2 URL berbahaya terdeteksi oleh VirusTotal"
  ],
  "details": {
    "from_domain": "fake-bank.com",
    "subject": "Konfirmasi Akun Anda Segera",
    "authentication": { "spf": {...}, "dkim": {...}, "dmarc": {...} },
    "url_analysis": { "threatening_urls": 2 },
    "urls_found": 3
  },
  "email_subject": "Konfirmasi Akun Anda Segera",
  "from_domain": "fake-bank.com"
}
```

---

## 📊 Cara Kerja Scoring

Skor risiko dihitung secara kumulatif dari beberapa faktor:

| Faktor | Penambahan Skor |
|--------|-----------------|
| DMARC gagal (`fail`) | +40 |
| SPF gagal (`fail`) | +30 |
| DKIM tidak dikonfigurasi | +20 |
| Error saat cek otentikasi | +25 |
| URL berbahaya terdeteksi | +60 |
| Error saat cek URL | +15 |

**Verdict berdasarkan total skor:**

| Skor | Verdict |
|------|---------|
| 0 – 39 | ✅ `safe` |
| 40 – 69 | ⚠️ `suspicious` |
| 70 – 100 | 🚨 `phishing` |

---

## 🧩 Struktur Modul Backend

| Modul | Fungsi Utama |
|-------|-------------|
| `main.py` | Entry point, definisi endpoint API, middleware CORS |
| `config.py` | Manajemen konfigurasi via Pydantic Settings (membaca `.env`) |
| `database.py` | Inisialisasi DB, model ORM `ScanHistory`, fungsi cleanup |
| `models.py` | Schema validasi request/response via Pydantic |
| `core/analysis.py` | Logika scoring risiko berdasarkan SPF, DMARC, dan URL |
| `core/dns_resolver.py` | DNS resolver dengan timeout ketat (anti-hanging) |
| `core/email_parser.py` | Parsing file `.eml` menggunakan mail-parser |
| `core/threat_detector.py` | Factory Pattern: memilih adapter provider deteksi URL |
| `core/virustotal.py` | Adapter untuk VirusTotal API v3 |
| `core/safe_browsing.py` | Adapter untuk Google Safe Browsing API |
| `core/rate_limiter.py` | Quota manager untuk membatasi penggunaan API eksternal |
| `utils/file_validator.py` | Validasi Magic Bytes (`message/rfc822`) + batas 10 MB |
| `utils/sanitizer.py` | Sanitasi HTML output via `bleach` (pencegahan XSS) |
| `routes/history.py` | Router CRUD riwayat scan & endpoint statistik dashboard |
