"""
Service layer for email scanning functionality.
Handles business logic for scanning emails and URLs.
"""

import logging
from typing import Dict, Any, List
from sqlalchemy.orm import Session

from core.email_parser import parse_eml_file
from core.analysis import analyze_authenticity
from core.safe_browsing import check_urls_safe_browsing
from core.virustotal import virustotal_adapter
from utils.sanitizer import sanitize_html
from database import ScanHistory
from models import URLScanRequest, URLScanResult

logger = logging.getLogger(__name__)

class ScanService:
    """Service class for handling email and URL scanning operations."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    async def scan_email(self, file_content: bytes, filename: str, ip_address: str, db: Session) -> Dict[str, Any]:
        """
        Scan email file for phishing threats.
        
        Args:
            file_content: Validated email file content
            filename: Original filename
            ip_address: Client IP address for audit
            db: Database session
            
        Returns:
            Dict with scan results
        """
        self.logger.info(f"Starting email scan for file: {filename}")
        
        # Parse email
        parsed_email = parse_eml_file(file_content)
        
        # Handle missing domain
        if not parsed_email.get("from_domain"):
            return self._handle_missing_domain(filename, parsed_email, ip_address, db)
        
        # Analyze authenticity
        self.logger.info(f"Analyzing authenticity for domain: {parsed_email['from_domain']}")
        auth_results = await analyze_authenticity(parsed_email["from_domain"])
        
        # Analyze URLs
        urls = parsed_email.get("urls", [])
        self.logger.info(f"Found {len(urls)} URLs in email")
        url_threat_results = await check_urls_safe_browsing(urls)
        
        # Calculate risk score
        risk_analysis = self._calculate_risk_score(auth_results, url_threat_results)
        
        # Save to database
        scan_record = self._save_scan_result(
            filename, risk_analysis, parsed_email, auth_results, 
            url_threat_results, urls, ip_address, db
        )
        
        # Return results
        return {
            "verdict": risk_analysis["verdict"],
            "risk_score": risk_analysis["risk_score"],
            "scan_id": scan_record.id,
            "scanned_at": scan_record.scanned_at.isoformat(),
            "risk_factors": risk_analysis["risk_factors"],
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
    
    async def scan_url(self, request: URLScanRequest) -> URLScanResult:
        """
        Scan URL directly for threats.
        
        Args:
            request: URL scan request
            
        Returns:
            URLScanResult with threat analysis
        """
        self.logger.info(f"Starting URL scan for: {request.url}")
        
        # Check URL using threat detector
        url_threat_results = await virustotal_adapter.check_urls([request.url])
        
        # Calculate risk score
        risk_score = 0
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
            provider=url_threat_results.get("provider", "virustotal"),
            details=url_threat_results
        )
    
    def _handle_missing_domain(self, filename: str, parsed_email: Dict[str, Any], 
                             ip_address: str, db: Session) -> Dict[str, Any]:
        """Handle case when sender domain cannot be identified."""
        scan_record = ScanHistory(
            filename=filename,
            verdict="suspicious",
            risk_score=50,
            from_domain="",
            from_email=parsed_email.get("from", ""),
            subject=parsed_email.get("subject", ""),
            url_count=0,
            threatening_url_count=0,
            ip_address=ip_address,
            result_data={
                "error": "Tidak dapat mengidentifikasi domain pengirim",
                "parsed_email": parsed_email
            }
        )
        db.add(scan_record)
        db.commit()
        db.refresh(scan_record)
        
        return {
            "verdict": "suspicious",
            "risk_score": 50,
            "scan_id": scan_record.id,
            "scanned_at": scan_record.scanned_at.isoformat(),
            "risk_factors": ["Tidak dapat mengidentifikasi domain pengirim"],
            "details": parsed_email,
            "sanitized_body_preview": parsed_email.get("sanitized_html", "")[:500],
            "email_subject": parsed_email.get("subject", ""),
            "from_domain": "",
        }
    
    def _calculate_risk_score(self, auth_results: Dict[str, Any], 
                             url_threat_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate risk score and determine verdict."""
        risk_score = 0
        risk_factors = []
        
        def get_status(auth_dict: dict, key: str) -> str:
            """Safely get status from auth_results with fallback."""
            try:
                return auth_dict.get(key, {}).get("status", "unknown")
            except (AttributeError, TypeError):
                return "unknown"
        
        def is_timeout(auth_dict: dict, key: str) -> bool:
            """Check if auth check timed out."""
            try:
                return auth_dict.get(key, {}).get("is_timeout", False)
            except (AttributeError, TypeError):
                return False
        
        # DMARC scoring
        dmarc_status = get_status(auth_results, "dmarc")
        if dmarc_status == "fail":
            risk_score += 40
            risk_factors.append("DMARC verification failed")
        elif dmarc_status == "error" or is_timeout(auth_results, "dmarc"):
            risk_factors.append("⚠️ DMARC check timeout - tidak dapat diverifikasi")
        
        # SPF scoring
        spf_status = get_status(auth_results, "spf")
        if spf_status == "fail":
            risk_score += 30
            risk_factors.append("SPF verification failed")
        elif spf_status == "error" or is_timeout(auth_results, "spf"):
            risk_factors.append("⚠️ SPF check timeout - tidak dapat diverifikasi")
        
        # DKIM scoring
        dkim_status = get_status(auth_results, "dkim")
        if dkim_status == "not_configured":
            risk_score += 20
            risk_factors.append("DKIM not configured for domain")
        
        # Authentication errors
        if "error" in auth_results:
            risk_score += 25
            risk_factors.append(f"Authentication check error: {auth_results['error']}")
        
        # URL threats
        if url_threat_results.get("threatening_urls", 0) > 0:
            risk_score += 60
            threat_count = url_threat_results["threatening_urls"]
            provider_name = url_threat_results.get("provider", "URL Threat Detector")
            risk_factors.append(f"{threat_count} URL berbahaya terdeteksi oleh {provider_name}")
        
        # URL check errors
        if url_threat_results.get("status") in ["error", "timeout"]:
            risk_score += 15
            risk_factors.append(f"URL check error: {url_threat_results.get('error', 'Unknown')}")
        
        # Determine verdict
        if risk_score >= 70:
            verdict = "phishing"
        elif risk_score >= 40:
            verdict = "suspicious"
        else:
            verdict = "safe"
        
        return {
            "risk_score": min(risk_score, 100),
            "verdict": verdict,
            "risk_factors": risk_factors
        }
    
    def _save_scan_result(self, filename: str, risk_analysis: Dict[str, Any],
                         parsed_email: Dict[str, Any], auth_results: Dict[str, Any],
                         url_threat_results: Dict[str, Any], urls: List[str],
                         ip_address: str, db: Session) -> ScanHistory:
        """Save scan result to database."""
        scan_record = ScanHistory(
            filename=filename,
            verdict=risk_analysis["verdict"],
            risk_score=risk_analysis["risk_score"],
            from_domain=parsed_email.get("from_domain", ""),
            from_email=parsed_email.get("from", ""),
            subject=parsed_email.get("subject", ""),
            url_count=len(urls),
            threatening_url_count=url_threat_results.get("threatening_urls", 0),
            ip_address=ip_address,
            result_data={
                "authentication": auth_results,
                "url_analysis": url_threat_results,
                "risk_factors": risk_analysis["risk_factors"],
            }
        )
        
        db.add(scan_record)
        db.commit()
        db.refresh(scan_record)
        
        return scan_record

# Global service instance
scan_service = ScanService()
