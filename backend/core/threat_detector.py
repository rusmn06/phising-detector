from typing import Any, Dict, List
from config import settings
import logging

logger = logging.getLogger(__name__)

# Import semua adapter yang tersedia
from .safe_browsing import check_urls_safe_browsing
from .virustotal import virustotal_adapter

class ThreatDetectorFactory:
    """
    Factory pattern untuk memilih provider deteksi URL ancaman.
    Memudahkan switching antara Google Safe Browsing dan VirusTotal.
    """
    
    @staticmethod
    def get_detector(provider: str):
        """
        Mendapatkan adapter deteksi URL sesuai konfigurasi.
        
        Args:
            provider: Nama provider ("google_safe_browsing", "virustotal", "both")
            
        Returns:
            Function atau object adapter yang sesuai
        """
        adapters = {
            "google_safe_browsing": check_urls_safe_browsing,
            "virustotal": virustotal_adapter.check_urls,
        }
        
        if provider not in adapters:
            logger.warning(f"Unknown provider '{provider}', falling back to google_safe_browsing")
            return check_urls_safe_browsing
        
        return adapters[provider]

async def check_url_threats(urls: List[str]) -> Dict[str, Any]:
    """
    Wrapper function untuk memeriksa URL ancaman menggunakan provider yang dikonfigurasi.
    
    Args:
        urls: List URL untuk diperiksa
        
    Returns:
        Dictionary dengan hasil pemeriksaan URL
    """
    provider = settings.URL_THREAT_PROVIDER
    
    # Jika provider adalah "both", jalankan kedua adapter
    if provider == "both":
        try:
            # Jalankan kedua provider secara paralel
            import asyncio
            google_result, vt_result = await asyncio.gather(
                check_urls_safe_browsing(urls),
                virustotal_adapter.check_urls(urls),
                return_exceptions=True
            )
            
            # Merge results (prioritaskan deteksi positif dari salah satu provider)
            merged_threats = []
            
            if isinstance(google_result, dict):
                merged_threats.extend(google_result.get("threats", []))
            
            if isinstance(vt_result, dict):
                merged_threats.extend(vt_result.get("threats", []))
            
            # Deduplikasi berdasarkan URL
            seen_urls = set()
            unique_threats = []
            for threat in merged_threats:
                url = threat.get("url")
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    unique_threats.append(threat)
            
            return {
                "total_urls": len(urls),
                "threatening_urls": len(unique_threats),
                "threats": unique_threats,
                "status": "success",
                "provider": "both (google_safe_browsing + virustotal)",
                "google_result": google_result if isinstance(google_result, dict) else {"error": str(google_result)},
                "virustotal_result": vt_result if isinstance(vt_result, dict) else {"error": str(vt_result)},
            }
            
        except Exception as e:
            logger.error(f"Error in 'both' provider mode: {e}")
            return {
                "total_urls": len(urls),
                "threatening_urls": 0,
                "threats": [],
                "status": "error",
                "error": str(e),
            }
    
    # Jika provider tunggal, gunakan factory
    detector = ThreatDetectorFactory.get_detector(provider)
    
    try:
        result = await detector(urls)
        return result
    except Exception as e:
        logger.error(f"Error checking URL threats with {provider}: {e}")
        return {
            "total_urls": len(urls),
            "threatening_urls": 0,
            "threats": [],
            "status": "error",
            "error": str(e),
            "provider": provider,
        }