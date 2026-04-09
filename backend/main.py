"""
Main entry point for FastAPI application.
Initializes all routes, middleware, and database.
"""
from datetime import datetime
from typing import Annotated, Optional

import logging
from fastapi import Depends, FastAPI, File, HTTPException, Request, Status, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

# Import configuration
from config import settings

# Import utilities
from utils.file_validator import validate_email_file
from utils.sanitizer import sanitize_html

# Import core logic
from core.analysis import analyze_authenticity
from core.email_parser import parse_eml_file
from core.rate_limiter import quota_manager
from core.safe_browsing import check_urls_safe_browsing
from core.virustotal import virustotal_adapter

# Import models
from models import URLScanRequest, URLScanResult

# Import database
from database import ScanHistory, cleanup_old_records, get_db, init_db

# Import routes
from routes.history import router as history_router

# ===========================================
# Logging Configuration
# ===========================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ===========================================
# FastAPI Application Initialization
# ===========================================
app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Internal Email Phishing Detection Application - Hybrid Architecture Based",
    version="1.0.0",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
)

# ===========================================
# Middleware Configuration
# ===========================================
CORS_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ===========================================
# Startup Event - Initialize Database
# ===========================================
@app.on_event("startup")
async def startup_event():
    """Initialize database tables on application startup."""
    logger.info("Starting application initialization...")
    init_db()
    logger.info("Database initialized successfully")


# ===========================================
# Health Check Endpoint
# ===========================================
@app.get(f"{settings.API_V1_STR}/health", tags=["Health"])
async def health_check():
    """
    Health check endpoint for monitoring and load balancer.
    Returns application status and environment.
    """
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "environment": settings.APP_ENV,
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }


# ===========================================
# Quota Status Endpoint
# ===========================================
@app.get(f"{settings.API_V1_STR}/quota-status", tags=["Monitoring"])
async def get_quota_status():
    """Get API quota status for monitoring."""
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


# ===========================================
# Helper Functions
# ===========================================
def get_auth_status(auth_dict: dict, key: str) -> str:
    """Safely get status from auth_results with fallback."""
    try:
        return auth_dict.get(key, {}).get("status", "unknown")
    except (AttributeError, TypeError):
        return "unknown"


def is_auth_timeout(auth_dict: dict, key: str) -> bool:
    """Check if auth check timed out."""
    try:
        return auth_dict.get(key, {}).get("is_timeout", False)
    except (AttributeError, TypeError):
        return False


def calculate_risk_score(
    auth_results: dict,
    url_threat_results: dict
) -> tuple[int, list[str], str]:
    """
    Calculate risk score based on authentication and URL analysis results.
    
    Returns:
        Tuple of (risk_score, risk_factors, verdict)
    """
    risk_score = 0
    risk_factors = []
    
    # DMARC Scoring
    dmarc_status = get_auth_status(auth_results, "dmarc")
    if dmarc_status == "fail":
        risk_score += 40
        risk_factors.append("DMARC verification failed")
    elif dmarc_status == "error" or is_auth_timeout(auth_results, "dmarc"):
        risk_factors.append("⚠️ DMARC check timeout - cannot verify")
    
    # SPF Scoring
    spf_status = get_auth_status(auth_results, "spf")
    if spf_status == "fail":
        risk_score += 30
        risk_factors.append("SPF verification failed")
    elif spf_status == "error" or is_auth_timeout(auth_results, "spf"):
        risk_factors.append("⚠️ SPF check timeout - cannot verify")
    
    # DKIM Scoring
    dkim_status = get_auth_status(auth_results, "dkim")
    if dkim_status == "not_configured":
        risk_score += 20
        risk_factors.append("DKIM not configured for domain")
    
    # Authentication check error
    if "error" in auth_results:
        risk_score += 25
        risk_factors.append(f"Authentication check error: {auth_results['error']}")
    
    # Dangerous URLs detected (+60 points)
    if url_threat_results.get("threatening_urls", 0) > 0:
        risk_score += 60
        threat_count = url_threat_results["threatening_urls"]
        provider_name = url_threat_results.get("provider", "URL Threat Detector")
        risk_factors.append(f"{threat_count} dangerous URL(s) detected by {provider_name}")
    
    # URL check error
    if url_threat_results.get("status") in ["error", "timeout"]:
        risk_score += 15
        risk_factors.append(f"URL check error: {url_threat_results.get('error', 'Unknown')}")
    
    # Determine verdict based on score
    if risk_score >= 70:
        verdict = "phishing"
    elif risk_score >= 40:
        verdict = "suspicious"
    else:
        verdict = "safe"
    
    return min(risk_score, 100), risk_factors, verdict


def create_scan_record(
    filename: str,
    verdict: str,
    risk_score: int,
    parsed_email: dict,
    url_threat_results: dict,
    request: Request,
    auth_results: Optional[dict] = None,
    risk_factors: Optional[list] = None,
) -> ScanHistory:
    """Create a scan history record."""
    return ScanHistory(
        filename=filename,
        verdict=verdict,
        risk_score=risk_score,
        from_domain=parsed_email.get("from_domain", ""),
        from_email=parsed_email.get("from", ""),
        subject=parsed_email.get("subject", ""),
        url_count=len(parsed_email.get("urls", [])),
        threatening_url_count=url_threat_results.get("threatening_urls", 0),
        ip_address=request.client.host if request.client else "unknown",
        result_data={
            "authentication": auth_results,
            "url_analysis": url_threat_results,
            "risk_factors": risk_factors,
        } if auth_results else {
            "error": "Unable to identify sender domain",
            "parsed_email": parsed_email
        }
    )


# ===========================================
# POST /scan-url - Direct URL Scanning
# ===========================================
@app.post(f"{settings.API_V1_STR}/scan-url", response_model=URLScanResult, tags=["Scanning"])
async def scan_url(request: URLScanRequest):
    """
    Scan URL directly for phishing/malware detection.
    Uses VirusTotal API for URL analysis.
    """
    # Validate URL format
    if not request.url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=Status.HTTP_400_BAD_REQUEST,
            detail="URL must start with http:// or https://"
        )
    
    # Check URL using threat detector (VirusTotal)
    url_threat_results = await virustotal_adapter.check_urls([request.url])
    
    # Calculate risk score based on results
    threatening_urls = url_threat_results.get("threatening_urls", 0)
    
    if threatening_urls > 0:
        risk_score = 100
        verdict = "malicious"
    elif url_threat_results.get("status") == "unknown":
        risk_score = 50
        verdict = "suspicious"
    else:
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
# POST /scan - Email Scanning (.eml file)
# ===========================================
@app.post(f"{settings.API_V1_STR}/scan", tags=["Scanning"])
async def scan_email(
    file: Annotated[UploadFile, File(description="Email .eml file for analysis")],
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Main endpoint for email phishing scanning.
    
    Flow:
    1. Validate file (size + magic bytes)
    2. Parse email (extract header, body, URLs)
    3. Analyze authentication (SPF/DKIM/DMARC)
    4. Analyze URLs (Google Safe Browsing / VirusTotal)
    5. Calculate risk score and verdict
    6. Save to database for history
    """
    logger.info(f"Starting scan for file: {file.filename}")
    
    # --- Step 1: Validate File ---
    try:
        validated_content = await validate_email_file(file)
    except HTTPException as e:
        logger.warning(f"File validation failed: {e.detail}")
        raise
    
    # --- Step 2: Parse Email ---
    parsed_email = parse_eml_file(validated_content)
    
    # Handle unidentified sender domain
    if not parsed_email.get("from_domain"):
        scan_record = create_scan_record(
            filename=file.filename,
            verdict="suspicious",
            risk_score=50,
            parsed_email=parsed_email,
            url_threat_results={"threatening_urls": 0},
            request=request,
        )
        db.add(scan_record)
        db.commit()
        db.refresh(scan_record)
        
        return {
            "verdict": "suspicious",
            "risk_score": 50,
            "scan_id": scan_record.id,
            "scanned_at": scan_record.scanned_at.isoformat(),
            "risk_factors": ["Unable to identify sender domain"],
            "details": parsed_email,
            "sanitized_body_preview": parsed_email.get("sanitized_html", "")[:500],
            "email_subject": parsed_email.get("subject", ""),
            "from_domain": "",
        }
    
    # --- Step 3: Analyze Authentication (SPF/DMARC) ---
    logger.info(f"Analyzing authenticity for domain: {parsed_email['from_domain']}")
    auth_results = await analyze_authenticity(parsed_email["from_domain"])
    
    # --- Step 4: Extract & Analyze URLs ---
    urls = parsed_email.get("urls", [])
    logger.info(f"Found {len(urls)} URLs in email")
    url_threat_results = await check_urls_safe_browsing(urls)
    
    # --- Step 5: Calculate Risk Score ---
    risk_score, risk_factors, verdict = calculate_risk_score(
        auth_results,
        url_threat_results
    )
    
    logger.info(f"Scan completed - Verdict: {verdict}, Score: {risk_score}")
    
    # --- Step 6: Save to Database ---
    scan_record = create_scan_record(
        filename=file.filename,
        verdict=verdict,
        risk_score=risk_score,
        parsed_email=parsed_email,
        url_threat_results=url_threat_results,
        request=request,
        auth_results=auth_results,
        risk_factors=risk_factors,
    )
    
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)
    
    # --- Return Results ---
    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "scan_id": scan_record.id,
        "scanned_at": scan_record.scanned_at.isoformat(),
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


# ===========================================
# Include Routers
# ===========================================
app.include_router(history_router, prefix=f"{settings.API_V1_STR}", tags=["History"])


# ===========================================
# Main Entry Point
# ===========================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )