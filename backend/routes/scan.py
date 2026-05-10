"""
API routes for scanning functionality.
Extracted from main.py for better code organization.
"""

import logging
from fastapi import APIRouter, UploadFile, File, HTTPException, status, Request, Depends
from sqlalchemy.orm import Session

from config import settings
from validators.file_validators import validate_email_file
from services.scan_service import scan_service
from models import URLScanRequest, URLScanResult
from database import get_db

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/scan-url", response_model=URLScanResult, tags=["Scanning"])
async def scan_url(request: URLScanRequest):
    """
    Scan URL langsung untuk deteksi phishing/malware.
    Menggunakan VirusTotal API untuk analisis URL.
    
    **Use Case:**
    - Cek link sebelum diklik
    - Verifikasi URL dari SMS/WhatsApp
    - Analisis URL tanpa perlu file email
    """
    
    return await scan_service.scan_url(request)

@router.post("/scan", tags=["Scanning"])
async def scan_email(
    file: UploadFile = File(description="File email .eml untuk dianalisis"),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """
    Endpoint utama untuk scan email phishing.
    
    **Flow:**
    1. Validasi file (ukuran + magic bytes)
    2. Parse email (ekstrak header, body, URL)
    3. Analisis otentikasi (SPF/DKIM/DMARC)
    4. Analisis URL (Google Safe Browsing / VirusTotal)
    5. Hitung skor risiko dan verdict
    6. Simpan ke database untuk history
    
    **File Requirements:**
    - Format: .eml (RFC822)
    - Max Size: 10MB
    - Magic Bytes: message/rfc822
    """
    
    logger.info(f"Starting scan for file: {file.filename}")
    
    # Validasi file
    try:
        validated_content = await validate_email_file(file)
    except HTTPException as e:
        logger.warning(f"File validation failed: {e.detail}")
        raise e
    
    # Get client IP
    client_ip = request.client.host if request.client else "unknown"
    
    # Scan email
    return await scan_service.scan_email(
        validated_content, 
        file.filename, 
        client_ip, 
        db
    )
