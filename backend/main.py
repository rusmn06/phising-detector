from fastapi import FastAPI, UploadFile, File, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from typing import Annotated

from config import settings
from utils.file_validator import validate_email_file
from utils.sanitizer import sanitize_html
from core.email_parser import parse_eml_file
from core.analysis import analyze_authenticity
from core.threat_detector import check_url_threats  # ⭐ GANTI IMPORT

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

@app.post(f"{settings.API_V1_STR}/scan")
async def scan_email(file: Annotated[UploadFile, File(description="File email .eml untuk dianalisis")]):
    """
    Endpoint utama untuk scan email phishing.
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
    
    # --- Step 4: Ekstrak & Analisis URL (dengan factory provider) ---
    urls = parsed_email.get("urls", [])
    url_threat_results = await check_url_threats(urls)  # ⭐ MENGGUNAKAN FACTORY
    
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
    
    # ⭐ URL BERBAHAYA TERDETEKSI = +60 poin (HIGH RISK!)
    if url_threat_results.get("threatening_urls", 0) > 0:
        risk_score += 60
        threat_count = url_threat_results["threatening_urls"]
        provider_name = url_threat_results.get("provider", "URL Threat Detector")
        risk_factors.append(f"{threat_count} URL berbahaya terdeteksi oleh {provider_name}")
    
    # Error saat check URL = +15 poin (inconclusive)
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)