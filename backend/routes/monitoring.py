"""
API routes for monitoring and health checks.
Extracted from main.py for better code organization.
"""

import logging
from datetime import datetime
from fastapi import APIRouter

from config import settings
from core.rate_limiter import quota_manager

logger = logging.getLogger(__name__)

router = APIRouter()

@router.get("/health", tags=["Health"])
async def health_check():
    """
    Health check endpoint for monitoring and load balancer.
    Returns application status and environment.
    """
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "environment": settings.APP_ENV,
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }

@router.get("/quota-status", tags=["Monitoring"])
async def get_quota_status():
    """
    Get API quota status for monitoring.
    Useful to check remaining quota before making requests.
    """
    vt_status = await quota_manager.check_rate_limit("virustotal")
    gs_status = await quota_manager.check_rate_limit("google_safe_browsing")
    
    return {
        "virustotal": {
            "remaining": vt_status["remaining"],
            "warnings": vt_status["warnings"],
            "allowed": vt_status["allowed"]
        },
        "google_safe_browsing": {
            "remaining": gs_status["remaining"],
            "warnings": gs_status["warnings"],
            "allowed": gs_status["allowed"]
        }
    }
