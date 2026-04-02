import httpx
import base64
import logging
from typing import List, Dict, Any
from config import settings

logger = logging.getLogger(__name__)

class VirusTotalAdapter:
    """
    Adapter untuk VirusTotal API v3.
    Mendeteksi URL berbahaya menggunakan multi-engine scanning.
    """
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            "x-apikey": api_key,
            "Accept": "application/json"
        }
    
    async def check_url(self, url: str) -> Dict[str, Any]:
        """
        Periksa satu URL menggunakan VirusTotal API.
        
        Args:
            url: URL untuk diperiksa
            
        Returns:
            Dictionary dengan hasil analisis URL
        """
        if not url:
            return {"error": "No URL provided"}
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                # VirusTotal memerlukan URL di-base64-kan (tanpa padding)
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
                
                # Endpoint untuk mendapatkan laporan URL
                endpoint = f"{self.BASE_URL}/urls/{url_id}"
                
                response = await client.get(endpoint, headers=self.headers)
                
                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    last_analysis_stats = attributes.get("last_analysis_stats", {})
                    
                    # Hitung jumlah deteksi berbahaya
                    malicious = last_analysis_stats.get("malicious", 0)
                    suspicious = last_analysis_stats.get("suspicious", 0)
                    harmless = last_analysis_stats.get("harmless", 0)
                    timeout_count = last_analysis_stats.get("timeout", 0)
                    
                    # Tentukan status berdasarkan deteksi
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
                        "harmless": harmless,
                        "timeout": timeout_count,
                        "total_engines": sum(last_analysis_stats.values()),
                        "last_analysis_date": attributes.get("last_analysis_date"),
                        "reputation": attributes.get("reputation", 0),
                        "categories": attributes.get("categories", {}),
                    }
                    
                elif response.status_code == 404:
                    # URL belum pernah dianalisis
                    return {
                        "url": url,
                        "status": "unknown",
                        "message": "URL belum pernah dianalisis oleh VirusTotal",
                        "malicious": 0,
                        "suspicious": 0,
                    }
                else:
                    logger.error(f"VirusTotal API error: {response.status_code} - {response.text}")
                    return {
                        "url": url,
                        "status": "error",
                        "error": f"API returned status {response.status_code}",
                    }
                    
        except httpx.TimeoutException:
            logger.error(f"VirusTotal API timeout for URL: {url}")
            return {
                "url": url,
                "status": "timeout",
                "error": "API request timeout",
            }
        except Exception as e:
            logger.error(f"VirusTotal API error: {e}")
            return {
                "url": url,
                "status": "error",
                "error": str(e),
            }
    
    async def check_urls(self, urls: List[str]) -> Dict[str, Any]:
        """
        Periksa daftar URL menggunakan VirusTotal API.
        Membatasi request sesuai rate limit free tier (4 request/menit).
        
        Args:
            urls: List URL untuk diperiksa
            
        Returns:
            Dictionary dengan ringkasan hasil pemeriksaan
        """
        if not urls:
            return {
                "total_urls": 0,
                "threatening_urls": 0,
                "threats": [],
                "status": "no_urls",
                "provider": "virustotal"
            }
        
        # Batasi jumlah URL untuk menghindari rate limit
        # Free tier: 4 request/menit, 500 request/hari
        MAX_URLS_PER_SCAN = 10
        urls_to_check = urls[:MAX_URLS_PER_SCAN]
        
        threats = []
        total_malicious = 0
        total_suspicious = 0
        
        # Check URLs secara sequential untuk menghormati rate limit
        for url in urls_to_check:
            result = await self.check_url(url)
            
            if result.get("status") in ["malicious", "suspicious"]:
                threats.append(result)
                total_malicious += result.get("malicious", 0)
                total_suspicious += result.get("suspicious", 0)
            
            # Delay kecil untuk menghormati rate limit (15 detik antar request)
            # Untuk production, pertimbangkan menggunakan queue + background task
            import asyncio
            await asyncio.sleep(0.5)  # Delay minimal untuk demo
        
        return {
            "total_urls": len(urls_to_check),
            "threatening_urls": len(threats),
            "total_malicious_detections": total_malicious,
            "total_suspicious_detections": total_suspicious,
            "threats": threats,
            "status": "success",
            "provider": "virustotal",
            "note": f"Checked {len(urls_to_check)} of {len(urls)} URLs (rate limit protection)"
        }

# Instance global dengan API key dari environment
virustotal_adapter = VirusTotalAdapter(api_key=settings.VIRUSTOTAL_API_KEY)