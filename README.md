# 🛡️ Email Phishing Scanner - Backend Documentation

Backend aplikasi Email Phishing Scanner dibangun menggunakan **FastAPI** (Python) dengan arsitektur yang mengutamakan keamanan, skalabilitas, dan maintainability.

---

## 📋 Daftar Isi

1. [Prasyarat](#prasyarat)
2. [Setup Lingkungan Pengembangan](#setup-lingkungan-pengembangan)
3. [Struktur Modul](#struktur-modul)
4. [Konfigurasi Environment Variables](#konfigurasi-environment-variables)
5. [Mengganti Google Safe Browsing API](#mengganti-google-safe-browsing-api)
6. [Menjalankan Server](#menjalankan-server)
7. [Testing API](#testing-api)
8. [Troubleshooting](#troubleshooting)

---

## Prasyarat

- Python 3.12 atau lebih baru
- pip (Python Package Manager)
- Virtual Environment (venv)

---

## Setup Lingkungan Pengembangan

### 1. Buat Virtual Environment

```bash
cd backend
python -m venv .venv

2. Aktifkan Virtual Environment
Windows:
bash
1
Mac/Linux:
bash
1
3. Install Dependencies
bash
12
4. Setup Environment Variables
Salin file .env.example menjadi .env:
bash
1
Kemudian edit file .env dan isi dengan nilai yang sesuai (lihat bagian Konfigurasi Environment Variables).
Struktur Modul
backend/
├── main.py              # Entry point & API routes
├── config.py            # Environment configuration (Pydantic)
├── models.py            # Pydantic models untuk request/response
├── core/
│   ├── analysis.py      # Logika analisis SPF/DKIM/DMARC + scoring
│   ├── dns_resolver.py  # DNS resolver dengan timeout control
│   ├── email_parser.py  # Parsing file .eml
│   ├── safe_browsing.py # Integrasi API deteksi URL berbahaya
│   └── url_extractor.py # Ekstraksi URL dari konten email
├── utils/
│   ├── file_validator.py  # Validasi file upload (Magic Bytes + Size)
│   └── sanitizer.py       # Sanitasi HTML untuk mencegah XSS
└── tests/               # Unit & integration tests
Deskripsi Modul
| Modul                     || Fungsi                                                                   |
| ------------------------- || ---                                                                      |
| main.py                   || Entry point aplikasi, definisi endpoint API, middleware CORS             |
| config.py                 || Manajemen konfigurasi menggunakan Pydantic Settings                      |
| models.py                 || Schema validasi request/response menggunakan Pydantic                    |
| core/analysis.py          || Logika scoring risiko berdasarkan SPF, DKIM, DMARC, dan URL threat       |
| core/dns_resolver.py      || DNS resolver dengan timeout untuk mencegah hanging                       |
| core/email_parser.py      || Parsing file .eml menggunakan library mailparser                         |
| core/safe_browsing.py     || Integrasi dengan API deteksi URL berbahaya (df: Google Safe Browsing)    |
| core/url_extractor.py     || Ekstraksi URL dari konten email (teks + HTML)                            |
| utils/file_validator.py   || Validasi file upload: Magic Bytes (message/rfc822) + Max 10MB            |
| utils/sanitizer.py        || Sanitasi HTML menggunakan bleach untuk mencegah XSS                      |

Konfigurasi Environment Variables
File .env di root proyek (email-phishing-scanner/.env) berisi konfigurasi sensitif.
Template .env.example
# ===========================================
# Email Phishing Scanner - Environment Config
# ===========================================

# --- Application Settings ---
APP_ENV=development
API_V1_STR=/api/v1
PROJECT_NAME=Email Phishing Scanner

# --- Security & External APIs ---
# Google Safe Browsing API Key (daftar di: https://console.cloud.google.com/)
GOOGLE_SAFE_BROWSING_API_KEY=your_api_key_here

# Secret key untuk internal use (JWT, session, dll)
SECRET_KEY=your_secret_key_here

# --- Rate Limiting ---
RATE_LIMIT=5/minute

# --- URL Threat Detection Provider ---
# Pilihan: "google_safe_browsing", "virustotal", "custom"
URL_THREAT_PROVIDER=google_safe_browsing

# --- Alternative API Keys (jika mengganti provider) ---
VIRUSTOTAL_API_KEY=
CUSTOM_THREAT_API_URL=
CUSTOM_THREAT_API_KEY=

# --- DNS Settings ---
DNS_TIMEOUT=5.0
DNS_NAMESERVERS=8.8.8.8,8.8.4.4

Mengganti Google Safe Browsing API
Aplikasi ini dirancang dengan arsitektur modular sehingga API deteksi URL berbahaya dapat diganti dengan mudah tanpa mengubah logika bisnis utama.
📌 Kapan Perlu Mengganti API?
Kuota Google Safe Browsing habis
Ingin menggunakan provider dengan deteksi lebih akurat
Kebijakan internal mengharuskan penggunaan vendor tertentu
Biaya API lebih ekonomis

Langkah-Langkah Mengganti Provider
Langkah 1: Update Environment Variables
Edit file .env dan ubah provider:
# Ganti provider
URL_THREAT_PROVIDER=virustotal

# Isi API key provider baru
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# Nonaktifkan Google Safe Browsing (opsional)
# GOOGLE_SAFE_BROWSING_API_KEY=

Langkah 2: Buat Adapter Baru (Jika Belum Ada)
Buat file baru di backend/core/ sesuai provider, contoh: backend/core/virustotal.py
import httpx
import logging
from typing import List, Dict, Any
from config import settings

logger = logging.getLogger(__name__)

class VirusTotalAdapter:
    """
    Adapter untuk VirusTotal API.
    Implementasi mengikuti interface yang sama dengan Google Safe Browsing.
    """
    
    BASE_URL = "https://www.virustotal.com/api/v3/urls"
    
    async def check_urls(self, urls: List[str]) -> Dict[str, Any]:
        """
        Periksa daftar URL menggunakan VirusTotal API.
        
        Args:
            urls: List URL untuk diperiksa
            
        Returns:
            Dictionary dengan format yang sama seperti Google Safe Browsing
        """
        if not urls:
            return {
                "total_urls": 0,
                "threatening_urls": 0,
                "threats": [],
                "status": "no_urls"
            }
        
        # Batasi jumlah URL (VirusTotal punya rate limit)
        MAX_URLS = 50
        urls_to_check = urls[:MAX_URLS]
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                threats = []
                
                for url in urls_to_check:
                    # VirusTotal memerlukan URL di-base64 terlebih dahulu
                    import base64
                    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
                    
                    response = await client.get(
                        f"{self.BASE_URL}/{url_id}",
                        headers={
                            "x-apikey": settings.VIRUSTOTAL_API_KEY
                        }
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        
                        # Jika ada malicious detection
                        if stats.get("malicious", 0) > 0:
                            threats.append({
                                "url": url,
                                "threat_type": "MALWARE",
                                "platform": "ANY",
                                "detection_count": stats.get("malicious", 0)
                            })
                
                return {
                    "total_urls": len(urls_to_check),
                    "threatening_urls": len(threats),
                    "threats": threats,
                    "status": "success"
                }
                
        except Exception as e:
            logger.error(f"VirusTotal API error: {e}")
            return {
                "total_urls": len(urls_to_check),
                "threatening_urls": 0,
                "threats": [],
                "status": "error",
                "error": str(e)
            }

# Instance global
virustotal_adapter = VirusTotalAdapter()

Langkah 3: Update Factory di safe_browsing.py
Edit file backend/core/safe_browsing.py untuk menambahkan factory pattern:
from typing import Any, Dict, List
from config import settings

# Import semua adapter yang tersedia
from .google_safe_browsing import google_adapter
from .virustotal import virustotal_adapter
# from .phishtank import phishtank_adapter  # Jika ada

def get_threat_detector():
    """
    Factory function untuk mendapatkan adapter sesuai konfigurasi.
    """
    provider = settings.URL_THREAT_PROVIDER
    
    adapters = {
        "google_safe_browsing": google_adapter,
        "virustotal": virustotal_adapter,
        # "phishtank": phishtank_adapter,
    }
    
    if provider not in adapters:
        raise ValueError(f"Unknown threat provider: {provider}")
    
    return adapters[provider]

async def check_urls_safe_browsing(urls: List[str]) -> Dict[str, Any]:
    """
    Wrapper function yang menggunakan factory untuk delegasi ke adapter.
    """
    detector = get_threat_detector()
    return await detector.check_urls(urls)

Langkah 4: Update requirements.txt (Jika Perlu)
Jika provider baru memerlukan library tambahan, tambahkan ke requirements.txt:
# Existing dependencies
fastapi==0.109.0
uvicorn==0.27.0
...

# New dependency for VirusTotal (jika perlu)
virustotal-api==1.1.10

Langkah 5: Testing
Test endpoint /scan dengan file .eml yang mengandung URL untuk memastikan provider baru berfungsi:
# Via Swagger UI
http://localhost:8000/api/v1/docs

# Atau via curl
curl -X POST "http://localhost:8000/api/v1/scan" \
  -H "accept: application/json" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@test_email.eml"

Menjalankan Server
Development Mode
uvicorn main:app --reload --host 0.0.0.0 --port 8000

Production Mode (Docker)
cd infrastructure
docker-compose up -d

Kontak & Support
Untuk pertanyaan teknis atau issue, hubungi:
Tech Lead: [nama@company.com]
Security Team: [security@company.com]
Repository: [link ke Git repo internal]

Referensi
FastAPI Documentation
Google Safe Browsing API
VirusTotal API
checkdmarc Documentation
bleach Documentation