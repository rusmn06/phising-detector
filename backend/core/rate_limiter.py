import asyncio
import time
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class APIQuotaManager:
    """
    Mengelola quota dan rate limit untuk external API (VirusTotal, Google Safe Browsing).
    Menggunakan file-based storage untuk persistence (bisa diganti Redis untuk production).
    """
    
    def __init__(self, storage_path: str = "backend/data/quota_cache.json"):
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Konfigurasi quota per provider
        self.quotas = {
            "virustotal": {
                "per_minute": 4,
                "per_day": 500,
                "per_month": 15500,
                "window_minute": 60,
                "window_day": 86400,
                "window_month": 2592000
            },
            "google_safe_browsing": {
                "per_day": 10000,
                "window_day": 86400
            }
        }
        
        # Load existing quota data
        self.quota_data = self._load_quota_data()
    
    def _load_quota_data(self) -> Dict[str, Any]:
        """Load quota data dari file JSON."""
        if self.storage_path.exists():
            try:
                with open(self.storage_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading quota data: {e}")
        
        return {
            "virustotal": {
                "requests": [],
                "daily_count": 0,
                "monthly_count": 0,
                "last_reset_day": None,
                "last_reset_month": None
            },
            "google_safe_browsing": {
                "requests": [],
                "daily_count": 0,
                "last_reset_day": None
            }
        }
    
    def _save_quota_data(self):
        """Save quota data ke file JSON."""
        try:
            with open(self.storage_path, 'w') as f:
                json.dump(self.quota_data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving quota data: {e}")
    
    def _reset_if_needed(self, provider: str):
        """Reset counter jika sudah masuk hari/bulan baru."""
        now = datetime.now()
        today = now.strftime("%Y-%m-%d")
        this_month = now.strftime("%Y-%m")
        
        data = self.quota_data.get(provider, {})
        
        # Reset harian
        if data.get("last_reset_day") != today:
            data["daily_count"] = 0
            data["last_reset_day"] = today
            logger.info(f"Reset daily quota for {provider}")
        
        # Reset bulanan (hanya untuk VirusTotal)
        if provider == "virustotal" and data.get("last_reset_month") != this_month:
            data["monthly_count"] = 0
            data["last_reset_month"] = this_month
            logger.info(f"Reset monthly quota for {provider}")
        
        # Cleanup old requests (lebih tua dari 1 menit)
        current_time = time.time()
        data["requests"] = [
            req_time for req_time in data.get("requests", [])
            if current_time - req_time < 60
        ]
        
        self.quota_data[provider] = data
        self._save_quota_data()
    
    def _safe_remaining(self, limit: Optional[int], count: int) -> Optional[int]:
        """
        Hitung remaining quota dengan aman untuk JSON serialization.
        Return None jika tidak ada limit (bukan inf).
        """
        if limit is None:
            return None
        return max(0, limit - count)
    
    async def check_rate_limit(self, provider: str) -> Dict[str, Any]:
        """
        Cek apakah request diperbolehkan berdasarkan rate limit.
        
        Returns:
            Dict dengan status dan info quota
        """
        self._reset_if_needed(provider)
        
        quota_config = self.quotas.get(provider, {})
        data = self.quota_data.get(provider, {})
        
        current_time = time.time()
        requests_last_minute = len(data.get("requests", []))
        daily_count = data.get("daily_count", 0)
        monthly_count = data.get("monthly_count", 0)
        
        # Check limits
        limits_exceeded = []
        
        per_minute_limit = quota_config.get("per_minute")
        per_day_limit = quota_config.get("per_day")
        per_month_limit = quota_config.get("per_month")
        
        if per_minute_limit and requests_last_minute >= per_minute_limit:
            limits_exceeded.append("per_minute")
        
        if per_day_limit and daily_count >= per_day_limit:
            limits_exceeded.append("per_day")
        
        if per_month_limit and monthly_count >= per_month_limit:
            limits_exceeded.append("per_month")
        
        # ⭐ HITUNG REMAINING DENGAN AMAN (TANPA inf) ⭐
        remaining = {
            "per_minute": self._safe_remaining(per_minute_limit, requests_last_minute),
            "per_day": self._safe_remaining(per_day_limit, daily_count),
        }
        
        if per_month_limit:
            remaining["per_month"] = self._safe_remaining(per_month_limit, monthly_count)
        
        # Check warning thresholds (80% usage)
        warnings = []
        if per_day_limit:
            daily_usage_percent = (daily_count / per_day_limit) * 100
            if daily_usage_percent >= 80:
                warnings.append(f"Daily quota {daily_usage_percent:.1f}% used")
        
        if per_month_limit:
            monthly_usage_percent = (monthly_count / per_month_limit) * 100
            if monthly_usage_percent >= 80:
                warnings.append(f"Monthly quota {monthly_usage_percent:.1f}% used")
        
        return {
            "allowed": len(limits_exceeded) == 0,
            "limits_exceeded": limits_exceeded,
            "remaining": remaining,
            "warnings": warnings,
            "retry_after": 60 if "per_minute" in limits_exceeded else None
        }
    
    async def record_request(self, provider: str):
        """Record bahwa request telah dilakukan."""
        self._reset_if_needed(provider)
        
        current_time = time.time()
        data = self.quota_data.get(provider, {})
        
        # Add timestamp
        if "requests" not in data:
            data["requests"] = []
        data["requests"].append(current_time)
        
        # Increment counters
        data["daily_count"] = data.get("daily_count", 0) + 1
        data["monthly_count"] = data.get("monthly_count", 0) + 1
        
        self.quota_data[provider] = data
        self._save_quota_data()
        
        # Log warning jika mendekati limit
        quota_config = self.quotas.get(provider, {})
        per_day_limit = quota_config.get("per_day")
        if per_day_limit:
            daily_usage = (data["daily_count"] / per_day_limit) * 100
            if daily_usage >= 90:
                logger.warning(f"⚠️ {provider} daily quota at {daily_usage:.1f}%!")

# Global instance
quota_manager = APIQuotaManager()