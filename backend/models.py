"""
Pydantic models for API request/response validation.
"""
from pydantic import BaseModel
from typing import Optional, List, Dict, Any


class AuthenticationResult(BaseModel):
    """Authentication analysis result structure."""
    spf: Dict[str, Any]
    dkim: Dict[str, Any]
    dmarc: Dict[str, Any]


class URLAnalysisResult(BaseModel):
    """URL analysis result structure."""
    total_urls: int
    threatening_urls: int
    threats: List[Dict[str, Any]]
    status: str


class ScanResult(BaseModel):
    """Main response structure for /scan endpoint."""
    verdict: str  # "safe", "suspicious", "phishing"
    risk_score: int  # 0-100
    risk_factors: List[str]
    details: Dict[str, Any]
    
    # Safe content fields
    sanitized_body_preview: Optional[str] = None
    email_subject: Optional[str] = None
    from_domain: Optional[str] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "verdict": "safe",
                "risk_score": 15,
                "risk_factors": ["DKIM not configured"],
                "details": {
                    "authentication": {"spf": {"status": "pass"}},
                    "url_analysis": {"total_urls": 2, "threatening_urls": 0}
                },
                "sanitized_body_preview": "<p>Email content here...</p>",
                "email_subject": "Test Email",
                "from_domain": "example.com"
            }
        }


class URLScanRequest(BaseModel):
    """Request model for direct URL scanning."""
    url: str
    
    class Config:
        json_schema_extra = {
            "example": {
                "url": "https://suspicious-site.com/login"
            }
        }


class URLScanResult(BaseModel):
    """Result model for URL scanning."""
    url: str
    verdict: str  # "safe", "suspicious", "malicious"
    risk_score: int  # 0-100
    provider: str
    details: Dict[str, Any]