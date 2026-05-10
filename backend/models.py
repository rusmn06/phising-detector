from pydantic import BaseModel, HttpUrl, field_validator, validator
from typing import Optional, List, Dict, Any
import re

class AuthenticationResult(BaseModel):
    """Struktur hasil analisis otentikasi domain."""
    spf: Dict[str, Any]
    dkim: Dict[str, Any]
    dmarc: Dict[str, Any]

class URLAnalysisResult(BaseModel):
    """Struktur hasil analisis URL."""
    total_urls: int
    threatening_urls: int
    threats: List[Dict[str, Any]]
    status: str

class ScanResult(BaseModel):
    """Struktur respons utama untuk endpoint /scan."""
    verdict: str  # "safe", "suspicious", "phishing"
    risk_score: int  # 0-100
    risk_factors: List[str]
    details: Dict[str, Any]
    
    # Field khusus untuk konten aman
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
    """Request model untuk scan URL langsung."""
    url: str
    
    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
        """Validate URL format and security."""
        if not v:
            raise ValueError('URL is required')
        
        # Basic URL format validation
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        if not url_pattern.match(v):
            raise ValueError('Invalid URL format')
        
        # Block localhost and private IPs
        if 'localhost' in v.lower() or v.startswith('http://127.') or v.startswith('http://10.') or v.startswith('http://192.168.'):
            raise ValueError('Local/private URLs are not allowed')
        
        # Block file:// and other protocols
        if v.startswith(('file://', 'ftp://', 'javascript:', 'data:')):
            raise ValueError('Only HTTP and HTTPS URLs are allowed')
        
        return v.strip()
    
    class Config:
        json_schema_extra = {
            "example": {
                "url": "https://suspicious-site.com/login"
            }
        }

class URLScanResult(BaseModel):
    """Result model untuk scan URL."""
    url: str
    verdict: str  # "safe", "suspicious", "malicious"
    risk_score: int  # 0-100
    provider: str
    details: Dict[str, Any]

