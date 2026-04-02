import httpx
import logging
from typing import List, Dict, Any
from config import settings

logger = logging.getLogger(__name__)

# Google Safe Browsing API v4 Endpoint
SAFE_BROWSING_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

async def check_urls_safe_browsing(urls: List[str]) -> Dict[str, Any]:
    """
    Periksa daftar URL menggunakan Google Safe Browsing API.
    
    Args:
        urls: List URL untuk diperiksa
        
    Returns:
        Dictionary dengan hasil pemeriksaan:
        - total_urls: Jumlah URL yang diperiksa
        - threatening_urls: Jumlah URL berbahaya
        - threats: Detail URL yang terdeteksi berbahaya
        - status: success/error
    """
    if not urls:
        return {
            "total_urls": 0,
            "threatening_urls": 0,
            "threats": [],
            "status": "no_urls"
        }
    
    # Batasi maksimal URL yang diperiksa (untuk menghindari quota limit)
    # Google Safe Browsing punya limit request per hari
    MAX_URLS_TO_CHECK = 50
    urls_to_check = urls[:MAX_URLS_TO_CHECK]
    
    # Siapkan payload untuk API Google Safe Browsing v4
    # API ini menggunakan hash prefix untuk privasi
    threat_entries = [{"url": url} for url in urls_to_check]
    
    payload = {
        "client": {
            "clientId": "phishing-detector-2",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "THREAT_TYPE_UNSPECIFIED",
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
                
                # Ekstrak informasi ancaman
                threatening_urls = []
                for threat in threats:
                    threat_url = threat.get("threat", {}).get("url", "unknown")
                    threat_type = threat.get("threatType", "UNKNOWN")
                    platform = threat.get("platformType", "ANY")
                    
                    threatening_urls.append({
                        "url": threat_url,
                        "threat_type": threat_type,
                        "platform": platform
                    })
                
                return {
                    "total_urls": len(urls_to_check),
                    "threatening_urls": len(threatening_urls),
                    "threats": threatening_urls,
                    "status": "success"
                }
            else:
                logger.error(f"Safe Browsing API error: {response.status_code} - {response.text}")
                return {
                    "total_urls": len(urls_to_check),
                    "threatening_urls": 0,
                    "threats": [],
                    "status": "api_error",
                    "error": f"API returned status {response.status_code}"
                }
                
    except httpx.TimeoutException:
        logger.error("Safe Browsing API timeout")
        return {
            "total_urls": len(urls_to_check),
            "threatening_urls": 0,
            "threats": [],
            "status": "timeout",
            "error": "API request timeout"
        }
    except Exception as e:
        logger.error(f"Safe Browsing API error: {e}")
        return {
            "total_urls": len(urls_to_check),
            "threatening_urls": 0,
            "threats": [],
            "status": "error",
            "error": str(e)
        }