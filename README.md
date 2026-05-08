# 🛡️ Email Phishing Scanner

Aplikasi internal berbasis web untuk mendeteksi email phishing secara otomatis. Upload file `.eml`, sistem akan menganalisis keaslian domain pengirim (SPF/DMARC), memeriksa URL berbahaya, dan memberikan **skor risiko 0–100** beserta verdict.

---

## Fitur Utama

- **Scan Email (.eml)** — Upload file email, analisis lengkap SPF, DMARC, dan URL
- **Scan URL** — Cek link mencurigakan langsung tanpa perlu upload email
- **Skor Risiko** — Sistem scoring 0–100 dengan verdict *safe / suspicious / phishing*
- **Dashboard** — Overview statistik scan dan aktivitas terbaru
- **History** — Riwayat semua scan dengan filter, search, dan pagination
- **Rate Limit Protection** — Manajemen quota API VirusTotal & Google Safe Browsing otomatis
- **Sanitasi HTML** — Konten email disanitasi dengan `bleach` sebelum ditampilkan (anti-XSS)
- **Validasi File** — Cek magic bytes (bukan hanya ekstensi) + batas 10MB

---

## Tech Stack

| Layer | Teknologi |
|---|---|
| **Backend** | FastAPI (Python 3.12), Uvicorn |
| **Frontend** | React 19, Vite 8, Tailwind CSS 4 |
| **Database** | SQLite (via SQLAlchemy) |
| **Auth Email** | checkdmarc (SPF/DMARC), dnspython |
| **URL Scanner** | VirusTotal API v3, Google Safe Browsing API v4 |
| **HTTP Client** | httpx (async), Axios |
| **HTML Security** | bleach (sanitasi), python-magic (validasi file) |
| **Routing** | React Router v7 |
| **Icons** | Lucide React |

---

## Struktur Proyek

```
email-phishing-scanner/
│
├── backend/
│   ├── core/
│   │   ├── analysis.py          # Scoring SPF/DMARC + logika risiko
│   │   ├── dns_resolver.py      # DNS resolver dengan timeout
│   │   ├── email_parser.py      # Parsing .eml (mailparser)
│   │   ├── rate_limiter.py      # Manajemen quota API
│   │   ├── safe_browsing.py     # Adapter Google Safe Browsing
│   │   ├── threat_detector.py   # Factory pattern untuk provider URL
│   │   ├── url_extractor.py     # Ekstraksi URL dari konten email
│   │   └── virustotal.py        # Adapter VirusTotal API v3
│   │
│   ├── routes/
│   │   └── history.py           # Endpoint history, stats, cleanup
│   │
│   ├── utils/
│   │   ├── file_validator.py    # Validasi magic bytes + ukuran file
│   │   └── sanitizer.py        # Sanitasi HTML & URL
│   │
│   ├── data/                    # SQLite database & quota cache
│   ├── config.py                # Konfigurasi via Pydantic Settings
│   ├── database.py              # Model SQLAlchemy & helper DB
│   ├── main.py                  # Entry point FastAPI
│   ├── models.py                # Schema Pydantic request/response
│   └── requirements.txt
│
├── frontend/
│   └── src/
│       ├── components/
│       │   ├── Dashboard.jsx
│       │   ├── History.jsx
│       │   ├── Layout.jsx
│       │   ├── LoadingSpinner.jsx
│       │   ├── ScanEmail.jsx
│       │   ├── ScanURL.jsx
│       │   └── VerdictBadge.jsx
│       └── services/
│           └── api.js           # Axios instance + interceptors
│
├── .env.example                 # Template environment variables
├── .gitignore
├── README.md                    # File ini
├── DEPLOY_AZURE.md              # Panduan deploy ke Azure Ubuntu 24
└── start-dev.bat                # Shortcut jalankan dev (Windows)
```

---

## Setup Lokal (Development)

### Prasyarat

- Python **3.12+**
- Node.js **20+**
- API key **VirusTotal** — [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)
- API key **Google Safe Browsing** — [console.cloud.google.com](https://console.cloud.google.com/apis/credentials)

---

### 1 — Clone & Konfigurasi Environment

```bash
git clone https://github.com/<username>/email-phishing-scanner.git
cd email-phishing-scanner

# Salin template environment
cp .env.example .env
```

Edit `.env` dan isi minimal dua API key berikut:

```env
GOOGLE_SAFE_BROWSING_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
SECRET_KEY=random_string_32_chars
URL_THREAT_PROVIDER=virustotal   # atau: google_safe_browsing / both
```

---

### 2 — Setup Backend

```bash
cd backend

# Buat dan aktifkan virtual environment
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Buat folder database
mkdir -p data

# Jalankan server
uvicorn main:app --reload --port 8000
```

Backend berjalan di: `http://localhost:8000`
API docs tersedia di: `http://localhost:8000/api/v1/docs`

---

### 3 — Setup Frontend

```bash
# Di terminal baru
cd frontend

npm install
npm run dev
```

Frontend berjalan di: `http://localhost:5173`

---

### Windows Shortcut

Untuk menjalankan keduanya sekaligus di Windows:

```bat
start-dev.bat
```

---

## API Endpoints

### Scanning

| Method | Endpoint | Deskripsi |
|---|---|---|
| `POST` | `/api/v1/scan` | Scan file `.eml` (multipart/form-data) |
| `POST` | `/api/v1/scan-url` | Scan URL langsung |

### History

| Method | Endpoint | Deskripsi |
|---|---|---|
| `GET` | `/api/v1/history` | List history dengan filter & pagination |
| `GET` | `/api/v1/history/{id}` | Detail scan by ID |
| `DELETE` | `/api/v1/history/{id}` | Hapus record scan |
| `POST` | `/api/v1/history/cleanup` | Trigger cleanup record lama |
| `GET` | `/api/v1/history/cleanup/logs` | Log cleanup job |

### Dashboard & Monitoring

| Method | Endpoint | Deskripsi |
|---|---|---|
| `GET` | `/api/v1/dashboard/stats` | Statistik total scan, verdict breakdown |
| `GET` | `/api/v1/quota-status` | Status sisa quota API |
| `GET` | `/api/v1/health` | Health check |

---

## Cara Kerja Scan Email

```
Upload .eml
    │
    ▼
[1] Validasi File
    ├── Magic bytes check (message/rfc822)
    └── Ukuran ≤ 10 MB

    │
    ▼
[2] Parse Email
    ├── Ekstrak header (From, Subject)
    ├── Ekstrak body (text + HTML)
    └── Ekstrak semua URL

    │
    ▼
[3] Analisis Otentikasi (parallel)
    ├── SPF check via checkdmarc
    └── DMARC check via checkdmarc

    │
    ▼
[4] Analisis URL
    └── Google Safe Browsing / VirusTotal / both

    │
    ▼
[5] Hitung Skor Risiko
    ├── DMARC fail  → +40
    ├── SPF fail    → +30
    ├── DKIM tidak dikonfigurasi → +20
    ├── URL berbahaya terdeteksi → +60
    └── Error check URL → +15

    │
    ▼
[6] Verdict
    ├── Score ≥ 70 → PHISHING
    ├── Score ≥ 40 → SUSPICIOUS
    └── Score < 40 → SAFE
```

---

## Konfigurasi Environment Variables

| Variable | Default | Keterangan |
|---|---|---|
| `APP_ENV` | `development` | Mode aplikasi |
| `GOOGLE_SAFE_BROWSING_API_KEY` | — | **Wajib** untuk URL scan |
| `VIRUSTOTAL_API_KEY` | — | **Wajib** untuk URL scan |
| `SECRET_KEY` | — | Random string untuk keamanan internal |
| `URL_THREAT_PROVIDER` | `virustotal` | `google_safe_browsing` / `virustotal` / `both` |
| `RATE_LIMIT` | `5/minute` | Rate limit endpoint |
| `DNS_TIMEOUT` | `5.0` | Timeout DNS query (detik) |
| `DATABASE_URL` | SQLite lokal | Path database SQLite |
| `HISTORY_RETENTION_DAYS` | `30` | Berapa hari history disimpan |
| `CORS_ORIGINS` | localhost | Daftar origin yang diizinkan |
| `ENABLE_DOCS` | `true` | Aktifkan Swagger UI (`false` di production) |

---

## Mengganti Provider URL Scan

Atur variabel `URL_THREAT_PROVIDER` di `.env`:

```env
# Gunakan hanya VirusTotal (default, lebih detail)
URL_THREAT_PROVIDER=virustotal

# Gunakan hanya Google Safe Browsing (lebih cepat)
URL_THREAT_PROVIDER=google_safe_browsing

# Gunakan keduanya (lebih akurat, quota 2x lebih cepat habis)
URL_THREAT_PROVIDER=both
```

Restart backend setelah mengubah nilai ini.

---

## Batasan Quota API

| Provider | Per Menit | Per Hari | Per Bulan |
|---|---|---|---|
| VirusTotal (Free) | 4 req | 500 req | 15.500 req |
| Google Safe Browsing | — | 10.000 req | — |

Aplikasi otomatis mengelola quota dan menghentikan request jika limit tercapai. Pantau quota di endpoint `/api/v1/quota-status`.

---

## Dokumentasi Lanjutan

| Dokumen | Isi |
|---|---|
| [`DEPLOY_AZURE.md`](./DEPLOY_AZURE.md) | Panduan deploy ke Azure Ubuntu 24 LTS (Nginx + Systemd + HTTPS) |
| `http://localhost:8000/api/v1/docs` | Swagger UI interaktif (saat dev) |
| `http://localhost:8000/api/v1/redoc` | ReDoc API reference (saat dev) |

---

## Kontribusi

1. Fork repository ini
2. Buat branch fitur: `git checkout -b feat/nama-fitur`
3. Commit perubahan: `git commit -m "feat: deskripsi singkat"`
4. Push ke branch: `git push origin feat/nama-fitur`
5. Buat Pull Request

---

*Email Phishing Scanner v2.0.0 — Internal Security Tool*