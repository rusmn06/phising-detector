import httpx
import logging
from typing import List, Dict, Any
from config import settings
from .rate_limiter import quota_manager

logger = logging.getLogger(__name__)

SAFE_BROWSING_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

async def check_urls_safe_browsing(urls: List[str]) -> Dict[str, Any]:
    """
    Periksa URL menggunakan Google Safe Browsing dengan rate limit handling.
    """
    if not urls:
        return {
            "total_urls": 0,
            "threatening_urls": 0,
            "threats": [],
            "status": "no_urls",
            "provider": "google_safe_browsing"
        }
    
    # ⭐ CEK RATE LIMIT ⭐
    rate_limit_status = await quota_manager.check_rate_limit("google_safe_browsing")
    
    if not rate_limit_status["allowed"]:
        logger.warning(f"Google Safe Browsing rate limit exceeded: {rate_limit_status['limits_exceeded']}")
        return {
            "total_urls": len(urls),
            "threatening_urls": 0,
            "threats": [],
            "status": "rate_limited",
            "error": f"API quota exceeded: {', '.join(rate_limit_status['limits_exceeded'])}",
            "provider": "google_safe_browsing"
        }
    
    # Log warnings
    for warning in rate_limit_status.get("warnings", []):
        logger.warning(f"Google Safe Browsing: {warning}")
    
    # Record request (1 request bisa check multiple URLs)
    await quota_manager.record_request("google_safe_browsing")
    
    # Batasi URLs per request
    MAX_URLS_PER_REQUEST = 500
    urls_to_check = urls[:MAX_URLS_PER_REQUEST]
    
    threat_entries = [{"url": url} for url in urls_to_check]
    
    payload = {
        "client": {
            "clientId": "phishing-detector-2",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": threat_entries
        }
    }
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                SAFE_BROWSING_API_URL,
                params={"key": settings.GOOGLE_SAFE_BROWSING_API_KEY},
                json=payload
            )
            
            if response.status_code == 200:
                data = response.json()
                threats = data.get("matches", [])
                
                threatening_urls = []
                for threat in threats:
                    threatening_urls.append({
                        "url": threat.get("threat", {}).get("url", "unknown"),
                        "threat_type": threat.get("threatType", "UNKNOWN"),
                        "platform": threat.get("platformType", "ANY")
                    })
                
                return {
                    "total_urls": len(urls_to_check),
                    "threatening_urls": len(threatening_urls),
                    "threats": threatening_urls,
                    "status": "success",
                    "provider": "google_safe_browsing",
                    "remaining_quota": rate_limit_status["remaining"]
                }
            elif response.status_code == 429:
                logger.error("Google Safe Browsing returned 429 - Rate Limit Exceeded")
                return {
                    "total_urls": len(urls_to_check),
                    "threatening_urls": 0,
                    "threats": [],
                    "status": "rate_limited",
                    "error": "Server rate limit exceeded",
                    "provider": "google_safe_browsing"
                }
            else:
                logger.error(f"Safe Browsing API error: {response.status_code}")
                return {
                    "total_urls": len(urls_to_check),
                    "threatening_urls": 0,
                    "threats": [],
                    "status": "api_error",
                    "error": f"API returned status {response.status_code}",
                    "provider": "google_safe_browsing"
                }
                
    except httpx.TimeoutException:
        return {
            "total_urls": len(urls_to_check),
            "threatening_urls": 0,
            "threats": [],
            "status": "timeout",
            "error": "API request timeout",
            "provider": "google_safe_browsing"
        }
    except Exception as e:
        logger.error(f"Safe Browsing API error: {e}")
        return {
            "total_urls": len(urls_to_check),
            "threatening_urls": 0,
            "threats": [],
            "status": "error",
            "error": str(e),
            "provider": "google_safe_browsing"
        }