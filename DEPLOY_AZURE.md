# Panduan Deploy ke Azure (Ubuntu 24 LTS)

Panduan lengkap untuk men-deploy **Email Phishing Scanner** ke Azure VM dengan Ubuntu 24 LTS menggunakan Nginx + Systemd + FastAPI + React.

---

## Daftar Isi

1. [Arsitektur Deploy](#arsitektur-deploy)
2. [Prasyarat](#prasyarat)
3. [Step 1 — Buat VM di Azure](#step-1--buat-vm-di-azure)
4. [Step 2 — Setup Server](#step-2--setup-server)
5. [Step 3 — Clone & Setup Project](#step-3--clone--setup-project)
6. [Step 4 — Setup Backend](#step-4--setup-backend)
7. [Step 5 — Build Frontend](#step-5--build-frontend)
8. [Step 6 — Systemd Service](#step-6--buat-systemd-service-untuk-backend)
9. [Step 7 — Konfigurasi Nginx](#step-7--konfigurasi-nginx)
10. [Step 8 — Buka Port Azure NSG](#step-8--buka-port-di-azure-network-security-group)
11. [Step 9 — HTTPS dengan Let's Encrypt](#step-9--opsional-https-dengan-lets-encrypt)
12. [Troubleshooting](#troubleshooting)
13. [Checklist Deploy](#checklist-deploy)

---

## Arsitektur Deploy

```
Internet
    │
    ▼
[Azure NSG] ── Port 80/443
    │
    ▼
[Nginx :80/:443]
    ├── / ──────────────► [Static Files React] /var/www/.../frontend/dist
    └── /api/ ──────────► [FastAPI :8000] via proxy_pass
                               │
                               ▼
                          [SQLite DB] /var/www/.../backend/data/
```

---

## Prasyarat

Sebelum memulai, pastikan kamu sudah memiliki:

- Akun Azure aktif
- API Key **VirusTotal** → [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)
- API Key **Google Safe Browsing** → [console.cloud.google.com](https://console.cloud.google.com/apis/credentials)
- SSH client (Terminal / PuTTY)
- Source code project (lokal atau di GitHub)

---

## Step 1 — Buat VM di Azure

Di **Azure Portal**, buat Virtual Machine baru dengan spesifikasi berikut:

| Setting | Value |
|---|---|
| **Image** | Ubuntu Server 24.04 LTS |
| **Size** | B2s (2 vCPU, 4 GB RAM) — minimal |
| **Authentication** | SSH Public Key |
| **Inbound Ports** | 22, 80, 443 |
| **OS Disk** | Standard SSD, 30 GB |

Setelah VM dibuat, login via SSH:

```bash
ssh azureuser@<IP_PUBLIC_VM>
```

---

## Step 2 — Setup Server

Update sistem dan install semua dependency yang dibutuhkan:

```bash
# Update package list & upgrade
sudo apt update && sudo apt upgrade -y

# Install dependency sistem
sudo apt install -y python3.12 python3.12-venv python3-pip \
  nginx git curl build-essential libmagic1

# Install Node.js 20 (wajib untuk Vite 8)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Verifikasi versi
python3.12 --version   # Python 3.12.x
node --version         # v20.x.x (minimal 20.19.0)
nginx -v               # nginx/1.x.x
```

---

## Step 3 — Clone & Setup Project

```bash
# Buat direktori aplikasi
sudo mkdir -p /var/www/phishing-scanner
sudo chown $USER:$USER /var/www/phishing-scanner
cd /var/www/phishing-scanner

# Pilih salah satu cara upload project:

# Opsi A — Clone dari GitHub
git clone https://github.com/<username>/<repo>.git .

# Opsi B — Upload dari komputer lokal (jalankan dari lokal)
# scp -r ./email-phishing-scanner azureuser@<IP_VM>:/var/www/phishing-scanner
```

---

## Step 4 — Setup Backend

### 4.1 — Buat Virtual Environment & Install Dependencies

```bash
cd /var/www/phishing-scanner/backend

# Buat dan aktifkan virtual environment
python3.12 -m venv .venv
source .venv/bin/activate

# Install semua dependencies Python
pip install --upgrade pip
pip install -r requirements.txt

# Buat folder database SQLite
mkdir -p data
```

### 4.2 — Buat File `.env`

Buat file konfigurasi environment di **root project** (satu level di atas `backend/`):

```bash
nano /var/www/phishing-scanner/.env
```

Isi dengan konfigurasi berikut (sesuaikan nilainya):

```env
# =============================================
# Application Settings
# =============================================
APP_ENV=production
API_V1_STR=/api/v1
PROJECT_NAME=Email Phishing Scanner

# =============================================
# External API Keys (WAJIB diisi!)
# =============================================
GOOGLE_SAFE_BROWSING_API_KEY=your_google_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# Generate random string 32 karakter:
# python3 -c "import secrets; print(secrets.token_hex(16))"
SECRET_KEY=isi_random_string_32_karakter_disini

# =============================================
# URL Threat Detection Provider
# =============================================
# Pilihan: "google_safe_browsing", "virustotal", "both"
URL_THREAT_PROVIDER=virustotal

# =============================================
# Rate Limiting & DNS
# =============================================
RATE_LIMIT=5/minute
DNS_TIMEOUT=10.0
DNS_NAMESERVERS=8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1

# =============================================
# Database
# =============================================
DATABASE_URL=sqlite:////var/www/phishing-scanner/backend/data/scan_history.db
HISTORY_RETENTION_DAYS=30

# =============================================
# Server Settings
# =============================================
UVICORN_HOST=127.0.0.1
UVICORN_PORT=8000
LOG_LEVEL=info
ENABLE_DOCS=false

# Ganti dengan IP VM atau domain kamu
CORS_ORIGINS=http://<IP_VM>,https://<DOMAIN_KAMU>
```

> **Tips generate SECRET_KEY:**
> ```bash
> python3 -c "import secrets; print(secrets.token_hex(16))"
> ```

### 4.3 — Test Backend Berjalan

```bash
cd /var/www/phishing-scanner/backend
source .venv/bin/activate

uvicorn main:app --host 127.0.0.1 --port 8000
# Pastikan tidak ada error, lalu tekan Ctrl+C
```

---

## Step 5 — Build Frontend

### 5.1 — Update Base URL API

Edit file `frontend/src/services/api.js`, ubah `API_BASE_URL` ke domain atau IP VM produksi:

```js
// Ganti baris ini:
const API_BASE_URL = 'http://localhost:8000/api/v1';

// Menjadi (gunakan domain jika sudah punya, atau IP sementara):
const API_BASE_URL = 'https://<DOMAIN_KAMU>/api/v1';
// atau
const API_BASE_URL = 'http://<IP_VM>/api/v1';
```

### 5.2 — Build untuk Production

```bash
cd /var/www/phishing-scanner/frontend

npm install
npm run build

# Hasil build tersimpan di: frontend/dist/
ls dist/  # Pastikan ada index.html dan folder assets/
```

---

## Step 6 — Buat Systemd Service untuk Backend

Buat service agar backend otomatis berjalan dan restart jika crash:

```bash
sudo nano /etc/systemd/system/phishing-scanner.service
```

Isi dengan konfigurasi berikut:

```ini
[Unit]
Description=Email Phishing Scanner - FastAPI Backend
After=network.target
StartLimitIntervalSec=0

[Service]
Type=exec
User=www-data
Group=www-data
WorkingDirectory=/var/www/phishing-scanner/backend
Environment="PATH=/var/www/phishing-scanner/backend/.venv/bin"
ExecStart=/var/www/phishing-scanner/backend/.venv/bin/uvicorn main:app \
    --host 127.0.0.1 \
    --port 8000 \
    --workers 2 \
    --log-level info
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Aktifkan dan jalankan service:

```bash
# Set ownership folder ke www-data
sudo chown -R www-data:www-data /var/www/phishing-scanner

# Reload systemd dan aktifkan service
sudo systemctl daemon-reload
sudo systemctl enable phishing-scanner
sudo systemctl start phishing-scanner

# Cek status service
sudo systemctl status phishing-scanner

# Lihat live logs
sudo journalctl -u phishing-scanner -f
```

Output yang diharapkan:

```
● phishing-scanner.service - Email Phishing Scanner - FastAPI Backend
     Loaded: loaded (/etc/systemd/system/phishing-scanner.service; enabled)
     Active: active (running) since ...
```

---

## Step 7 — Konfigurasi Nginx

Buat konfigurasi Nginx sebagai reverse proxy:

```bash
sudo nano /etc/nginx/sites-available/phishing-scanner
```

```nginx
server {
    listen 80;
    server_name <IP_VM_atau_DOMAIN>;

    # ── Frontend: serve static files React ──────────────────
    root /var/www/phishing-scanner/frontend/dist;
    index index.html;

    # Handle React Router (SPA — semua route diarahkan ke index.html)
    location / {
        try_files $uri $uri/ /index.html;
    }

    # ── Backend API: proxy ke FastAPI ────────────────────────
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeout lebih lama untuk proses scan (VirusTotal bisa lambat)
        proxy_read_timeout 120s;
        proxy_connect_timeout 10s;
        proxy_send_timeout 120s;

        # Batas ukuran upload file (.eml max 10MB)
        client_max_body_size 10M;
    }

    # ── Security Headers ─────────────────────────────────────
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";
}
```

Aktifkan konfigurasi dan reload Nginx:

```bash
# Aktifkan site
sudo ln -s /etc/nginx/sites-available/phishing-scanner \
           /etc/nginx/sites-enabled/

# Hapus default config bawaan
sudo rm -f /etc/nginx/sites-enabled/default

# Test konfigurasi Nginx
sudo nginx -t

# Reload Nginx (tanpa downtime)
sudo systemctl reload nginx
```

Output `nginx -t` yang diharapkan:

```
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

---

## Step 8 — Buka Port di Azure Network Security Group

Di **Azure Portal**, buka: **VM → Networking → Inbound port rules → Add inbound rule**

Tambahkan rule berikut:

| Nama | Port | Protokol | Action | Prioritas |
|---|---|---|---|---|
| Allow-HTTP | 80 | TCP | Allow | 100 |
| Allow-HTTPS | 443 | TCP | Allow | 110 |

Setelah selesai, buka browser dan akses:

```
http://<IP_PUBLIC_VM>
```

Aplikasi seharusnya sudah bisa diakses.

---

## Step 9 — (Opsional) HTTPS dengan Let's Encrypt

> **Prasyarat:** Kamu harus memiliki domain yang sudah di-pointing ke IP VM (via DNS A record).

```bash
# Install Certbot dan plugin Nginx
sudo apt install -y certbot python3-certbot-nginx

# Generate sertifikat SSL (ganti dengan domain kamu)
sudo certbot --nginx -d phishing-scanner.example.com

# Ikuti instruksi interaktif:
# - Masukkan email untuk notifikasi
# - Setuju Terms of Service
# - Pilih redirect HTTP ke HTTPS (opsi 2, disarankan)

# Aktifkan auto-renewal sertifikat (setiap 90 hari)
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer

# Test auto-renewal
sudo certbot renew --dry-run
```

Setelah selesai, akses aplikasi via:

```
https://phishing-scanner.example.com
```

---

## Troubleshooting

### Backend tidak jalan

```bash
# Cek status service
sudo systemctl status phishing-scanner

# Lihat log error detail
sudo journalctl -u phishing-scanner --since "10 minutes ago" --no-pager

# Cek apakah port 8000 aktif
ss -tlnp | grep 8000

# Test API langsung dari server
curl http://127.0.0.1:8000/api/v1/health
```

### Frontend tidak tampil / 404

```bash
# Pastikan folder dist ada dan tidak kosong
ls /var/www/phishing-scanner/frontend/dist/

# Cek error Nginx
sudo tail -f /var/log/nginx/error.log

# Cek konfigurasi Nginx
sudo nginx -t
```

### Error upload file `.eml`

```bash
# Pastikan libmagic terinstall
python3 -c "import magic; print('OK')"

# Jika error, install ulang:
sudo apt install -y libmagic1
pip install python-magic
```

### Permission denied

```bash
# Reset ownership ke www-data
sudo chown -R www-data:www-data /var/www/phishing-scanner

# Cek permission folder data (SQLite)
ls -la /var/www/phishing-scanner/backend/data/
```

### API tidak bisa diakses dari browser (CORS error)

Edit file `.env` dan pastikan `CORS_ORIGINS` sudah benar:

```env
# Sesuaikan dengan URL frontend yang diakses browser
CORS_ORIGINS=http://<IP_VM>,https://<DOMAIN_KAMU>
```

Lalu restart backend:

```bash
sudo systemctl restart phishing-scanner
```

---

## Update Aplikasi

Setelah ada perubahan kode, jalankan langkah berikut:

```bash
cd /var/www/phishing-scanner

# Pull perubahan terbaru
git pull origin main

# Update backend dependencies (jika ada perubahan requirements.txt)
cd backend
source .venv/bin/activate
pip install -r requirements.txt

# Rebuild frontend (jika ada perubahan kode React)
cd ../frontend
npm install
npm run build

# Fix permission & restart
sudo chown -R www-data:www-data /var/www/phishing-scanner
sudo systemctl restart phishing-scanner
sudo systemctl reload nginx
```

---

## Checklist Deploy

Gunakan checklist ini untuk memastikan semua langkah sudah selesai:

- [ ] VM Azure Ubuntu 24 sudah berjalan
- [ ] Port 80 dan 443 sudah dibuka di Azure NSG
- [ ] Python 3.12 dan Node.js 20 sudah terinstall
- [ ] Project sudah di-clone/upload ke `/var/www/phishing-scanner`
- [ ] File `.env` sudah dibuat dan diisi dengan API keys yang valid
- [ ] Backend virtual environment sudah dibuat dan dependencies terinstall
- [ ] Folder `backend/data/` sudah dibuat untuk SQLite
- [ ] Test manual `uvicorn` berhasil tanpa error
- [ ] Frontend sudah di-build dengan URL API yang benar (bukan localhost)
- [ ] Systemd service `phishing-scanner` sudah aktif dan running
- [ ] Nginx dikonfigurasi dan reload berhasil
- [ ] Endpoint `http://<IP_VM>/api/v1/health` return `{"status": "healthy"}`
- [ ] Aplikasi bisa diakses dari browser di `http://<IP_VM>`
- [ ] (Opsional) SSL Let's Encrypt sudah dikonfigurasi untuk HTTPS

---

## Referensi

- [FastAPI Deployment Docs](https://fastapi.tiangolo.com/deployment/)
- [Uvicorn Deployment](https://www.uvicorn.org/deployment/)
- [Nginx Configuration Guide](https://nginx.org/en/docs/)
- [Let's Encrypt Certbot](https://certbot.eff.org/)
- [Azure VM Networking](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview)

---

*Dibuat untuk: Email Phishing Scanner v2.0.0 | Testing: Azure Ubuntu 24.04 LTS*
