import httpx
import base64
import logging
import asyncio
from typing import List, Dict, Any
from config import settings
from .rate_limiter import quota_manager

logger = logging.getLogger(__name__)

class VirusTotalAdapter:
    """
    Adapter untuk VirusTotal API v3 dengan rate limit handling.
    """
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            "x-apikey": api_key,
            "Accept": "application/json"
        }
    
    async def check_url(self, url: str) -> Dict[str, Any]:
        """Periksa satu URL dengan rate limit check."""
        
        # ⭐ CEK RATE LIMIT SEBELUM REQUEST ⭐
        rate_limit_status = await quota_manager.check_rate_limit("virustotal")
        
        if not rate_limit_status["allowed"]:
            logger.warning(f"VirusTotal rate limit exceeded: {rate_limit_status['limits_exceeded']}")
            return {
                "url": url,
                "status": "rate_limited",
                "error": f"API quota exceeded: {', '.join(rate_limit_status['limits_exceeded'])}",
                "retry_after": rate_limit_status.get("retry_after"),
                "remaining": rate_limit_status["remaining"]
            }
        
        # Log warnings jika mendekati limit
        for warning in rate_limit_status.get("warnings", []):
            logger.warning(f"VirusTotal: {warning}")
        
        # Record request
        await quota_manager.record_request("virustotal")
        
        # Proceed dengan API call
        if not url:
            return {"error": "No URL provided"}
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
                endpoint = f"{self.BASE_URL}/urls/{url_id}"
                
                response = await client.get(endpoint, headers=self.headers)
                
                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    last_analysis_stats = attributes.get("last_analysis_stats", {})
                    
                    malicious = last_analysis_stats.get("malicious", 0)
                    suspicious = last_analysis_stats.get("suspicious", 0)
                    
                    if malicious > 0:
                        status = "malicious"
                    elif suspicious > 0:
                        status = "suspicious"
                    else:
                        status = "clean"
                    
                    return {
                        "url": url,
                        "status": status,
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": last_analysis_stats.get("harmless", 0),
                        "total_engines": sum(last_analysis_stats.values()),
                        "reputation": attributes.get("reputation", 0),
                    }
                    
                elif response.status_code == 404:
                    return {
                        "url": url,
                        "status": "unknown",
                        "message": "URL belum pernah dianalisis",
                    }
                elif response.status_code == 429:
                    # Rate limit dari server
                    logger.error("VirusTotal returned 429 - Rate Limit Exceeded")
                    return {
                        "url": url,
                        "status": "rate_limited",
                        "error": "Server rate limit exceeded",
                        "retry_after": 60
                    }
                else:
                    return {
                        "url": url,
                        "status": "error",
                        "error": f"API returned status {response.status_code}",
                    }
                    
        except httpx.TimeoutException:
            return {"url": url, "status": "timeout", "error": "API request timeout"}
        except Exception as e:
            logger.error(f"VirusTotal API error: {e}")
            return {"url": url, "status": "error", "error": str(e)}
    
    async def check_urls(self, urls: List[str]) -> Dict[str, Any]:
        """
        Periksa daftar URL dengan rate limit protection.
        """
        if not urls:
            return {
                "total_urls": 0,
                "threatening_urls": 0,
                "threats": [],
                "status": "no_urls",
                "provider": "virustotal"
            }
        
        # ⭐ BATASI URL PER SCAN UNTUK HORMATI RATE LIMIT ⭐
        MAX_URLS_PER_SCAN = 4  # Sesuai limit 4 request/minute
        urls_to_check = urls[:MAX_URLS_PER_SCAN]
        
        threats = []
        rate_limited_count = 0
        
        for url in urls_to_check:
            result = await self.check_url(url)
            
            if result.get("status") == "rate_limited":
                rate_limited_count += 1
                logger.warning(f"Rate limited for URL: {url}")
                # Stop jika rate limited
                break
            
            if result.get("status") in ["malicious", "suspicious"]:
                threats.append(result)
            
            # ⭐ DELAY ANTAR REQUEST UNTUK HORMATI RATE LIMIT ⭐
            await asyncio.sleep(15)  # 15 detik antar request (4 request/menit)
        
        return {
            "total_urls": len(urls_to_check),
            "threatening_urls": len(threats),
            "threats": threats,
            "status": "success" if rate_limited_count == 0 else "partial_rate_limited",
            "provider": "virustotal",
            "rate_limited_count": rate_limited_count,
            "note": f"Checked {len(urls_to_check)} of {len(urls)} URLs (rate limit protection)"
        }

# Global instance
virustotal_adapter = VirusTotalAdapter(api_key=settings.VIRUSTOTAL_API_KEY)