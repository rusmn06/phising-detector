"""
Main entry point untuk FastAPI application.
Using modular architecture with app factory pattern.
"""

import logging
from app_factory import create_app

# ===========================================
# Logging Configuration
# ===========================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ===========================================
# FastAPI Application Initialization
# ===========================================
app = create_app()


# ===========================================
# Main Entry Point
# ===========================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )