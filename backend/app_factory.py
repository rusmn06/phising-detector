"""
Application factory for FastAPI app initialization.
Provides better organization and testability.
"""

import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from database import init_db
from routes.scan import router as scan_router
from routes.history import router as history_router
from routes.monitoring import router as monitoring_router
from exception_handlers import setup_exception_handlers

logger = logging.getLogger(__name__)

def create_app() -> FastAPI:
    """
    Create and configure FastAPI application.
    
    Returns:
        Configured FastAPI app instance
    """
    # Initialize FastAPI app
    app = FastAPI(
        title=settings.PROJECT_NAME,
        description="Aplikasi Internal Deteksi Phishing Email - Berbasis Arsitektur Hybrid",
        version="1.0.0",
        docs_url=f"{settings.API_V1_STR}/docs",
        redoc_url=f"{settings.API_V1_STR}/redoc",
    )
    
    # Add middleware
    _add_middleware(app)
    
    # Add event handlers
    _add_event_handlers(app)
    
    # Setup exception handlers
    setup_exception_handlers(app)
    
    # Include routers
    _include_routers(app)
    
    return app

def _add_middleware(app: FastAPI) -> None:
    """Add middleware to the FastAPI app."""
    # CORS Middleware - Allow frontend to access API
    origins = [
        "http://localhost:5173",  # Vite dev server
        "http://localhost:3000",  # Alternative dev port
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ]
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

def _add_event_handlers(app: FastAPI) -> None:
    """Add startup and shutdown event handlers."""
    @app.on_event("startup")
    async def startup_event():
        """
        Initialize database tables on application startup.
        Also trigger initial cleanup if needed.
        """
        logger.info("Starting application initialization...")
        init_db()
        logger.info("Database initialized successfully")

def _include_routers(app: FastAPI) -> None:
    """Include all API routers."""
    app.include_router(scan_router, prefix=f"{settings.API_V1_STR}", tags=["Scanning"])
    app.include_router(history_router, prefix=f"{settings.API_V1_STR}", tags=["History"])
    app.include_router(monitoring_router, prefix=f"{settings.API_V1_STR}", tags=["Monitoring"])
