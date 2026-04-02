from fastapi import FastAPI, UploadFile, File, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from typing import Annotated

from config import settings
from utils.file_validator import validate_email_file
from utils.sanitizer import sanitize_html
from core.email_parser import parse_eml_file
from core.analysis import analyze_authenticity
from core.threat_detector import check_url_threats
from models import URLScanRequest, URLScanResult
from core.rate_limiter import quota_manager

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Aplikasi Internal Deteksi Phishing Email",
    version="0.1.0",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
)

# --- CORS Middleware ---
origins = ["http://localhost:5173", "http://localhost:3000"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get(f"{settings.API_V1_STR}/health")
async def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "environment": settings.APP_ENV
    }

# ===========================================
# ENDPOINT BARU: Scan URL Langsung
# ===========================================
@app.post(f"{settings.API_V1_STR}/scan-url", response_model=URLScanResult)
async def scan_url(request: URLScanRequest):
    """
    Scan URL langsung untuk deteksi phishing/malware.
    Menggunakan VirusTotal API untuk analisis URL.
    
    **Use Case:**
    - Cek link sebelum diklik
    - Verifikasi URL dari SMS/WhatsApp
    - Analisis URL tanpa perlu file email
    """
    
    # Validasi URL sederhana
    if not request.url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL harus dimulai dengan http:// atau https://"
        )
    
    # Cek URL menggunakan threat detector (VirusTotal)
    url_threat_results = await check_url_threats([request.url])
    
    # Hitung skor risiko berdasarkan hasil
    risk_score = 0
    threatening_urls = url_threat_results.get("threatening_urls", 0)
    
    if threatening_urls > 0:
        # Ada URL berbahaya terdeteksi
        risk_score = 100
        verdict = "malicious"
    elif url_threat_results.get("status") == "unknown":
        # URL belum pernah dianalisis
        risk_score = 50
        verdict = "suspicious"
    else:
        # Tidak ada ancaman terdeteksi
        risk_score = 0
        verdict = "safe"
    
    return URLScanResult(
        url=request.url,
        verdict=verdict,
        risk_score=risk_score,
        provider=url_threat_results.get("provider", settings.URL_THREAT_PROVIDER),
        details=url_threat_results
    )

# ===========================================
# ENDPOINT EXISTING: Scan Email (.eml)
# ===========================================
@app.post(f"{settings.API_V1_STR}/scan")
async def scan_email(file: Annotated[UploadFile, File(description="File email .eml untuk dianalisis")]):
    """
    Endpoint utama untuk scan email phishing.
    Flow:
    1. Validasi file (ukuran + magic bytes)
    2. Parse email (ekstrak header, body, URL)
    3. Analisis otentikasi (SPF/DKIM/DMARC)
    4. Analisis URL (Google Safe Browsing / VirusTotal)
    5. Hitung skor risiko dan verdict
    """
    
    # --- Step 1: Validasi File ---
    validated_content = await validate_email_file(file)
    
    # --- Step 2: Parse Email ---
    parsed_email = parse_eml_file(validated_content)
    
    if not parsed_email.get("from_domain"):
        return {
            "verdict": "suspicious",
            "risk_score": 50,
            "risk_factors": ["Tidak dapat mengidentifikasi domain pengirim"],
            "details": parsed_email,
            "sanitized_body_preview": parsed_email.get("sanitized_html", "")[:500],
            "email_subject": parsed_email.get("subject", ""),
            "from_domain": "",
        }
    
    # --- Step 3: Analisis Otentikasi (SPF/DMARC) ---
    auth_results = await analyze_authenticity(parsed_email["from_domain"])
    
    # --- Step 4: Ekstrak & Analisis URL ---
    urls = parsed_email.get("urls", [])
    url_threat_results = await check_url_threats(urls)
    
    # --- Step 5: Hitung Skor Risiko ---
    risk_score = 0
    risk_factors = []
    
    # DMARC fail = +40 poin
    if auth_results.get("dmarc", {}).get("status") == "fail":
        risk_score += 40
        risk_factors.append("DMARC verification failed")
    
    # SPF fail = +30 poin
    if auth_results.get("spf", {}).get("status") == "fail":
        risk_score += 30
        risk_factors.append("SPF verification failed")
    
    # DKIM not configured = +20 poin
    if auth_results.get("dkim", {}).get("status") == "not_configured":
        risk_score += 20
        risk_factors.append("DKIM not configured for domain")
    
    # Error saat check otentikasi = +25 poin
    if "error" in auth_results:
        risk_score += 25
        risk_factors.append(f"Authentication check error: {auth_results['error']}")
    
    # URL BERBAHAYA TERDETEKSI = +60 poin
    if url_threat_results.get("threatening_urls", 0) > 0:
        risk_score += 60
        threat_count = url_threat_results["threatening_urls"]
        provider_name = url_threat_results.get("provider", "URL Threat Detector")
        risk_factors.append(f"{threat_count} URL berbahaya terdeteksi oleh {provider_name}")
    
    # Error saat check URL = +15 poin
    if url_threat_results.get("status") in ["error", "timeout"]:
        risk_score += 15
        risk_factors.append(f"URL check error: {url_threat_results.get('error', 'Unknown')}")
    
    # Tentukan verdict berdasarkan skor
    if risk_score >= 70:
        verdict = "phishing"
    elif risk_score >= 40:
        verdict = "suspicious"
    else:
        verdict = "safe"
    
    # --- Return Hasil ---
    return {
        "verdict": verdict,
        "risk_score": min(risk_score, 100),
        "risk_factors": risk_factors,
        "details": {
            "from_domain": parsed_email["from_domain"],
            "subject": parsed_email["subject"],
            "authentication": auth_results,
            "url_analysis": url_threat_results,
            "urls_found": len(urls),
        },
        "sanitized_body_preview": sanitize_html(parsed_email.get("html", ""))[:1000] if parsed_email.get("html") else None,
        "email_subject": parsed_email.get("subject", ""),
        "from_domain": parsed_email.get("from_domain", ""),
    }

@app.get(f"{settings.API_V1_STR}/quota-status")
async def get_quota_status():
    """
    Endpoint untuk monitoring quota API.
    Berguna untuk admin memantau sisa quota sebelum habis.
    """
    vt_status = await quota_manager.check_rate_limit("virustotal")
    gs_status = await quota_manager.check_rate_limit("google_safe_browsing")
    
    return {
        "virustotal": {
            "remaining": vt_status["remaining"],
            "warnings": vt_status["warnings"],
            "allowed": vt_status["allowed"]
        },
        "google_safe_browsing": {
            "remaining": gs_status["remaining"],
            "warnings": gs_status["warnings"],
            "allowed": gs_status["allowed"]
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)