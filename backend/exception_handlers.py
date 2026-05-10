"""
Global exception handlers for FastAPI application.
Provides consistent error responses across all endpoints.
"""

import logging
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from exceptions.custom_exceptions import PhishingDetectorException

logger = logging.getLogger(__name__)


async def phishing_detector_exception_handler(request: Request, exc: PhishingDetectorException):
    """Handle custom PhishingDetectorException."""
    logger.error(f"PhishingDetectorException: {exc.message}", exc_info=True)
    
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": exc.error_code or "INTERNAL_ERROR",
                "message": exc.message,
                "details": exc.details
            }
        }
    )


async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle FastAPI HTTPException."""
    logger.warning(f"HTTPException: {exc.detail}")
    
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.detail if isinstance(exc.detail, dict) else {
            "error": {
                "code": "HTTP_ERROR",
                "message": str(exc.detail)
            }
        }
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle request validation errors."""
    logger.warning(f"Validation error: {exc.errors()}")
    
    formatted_errors = []
    for error in exc.errors():
        field = " -> ".join(str(loc) for loc in error["loc"])
        formatted_errors.append({
            "field": field,
            "message": error["msg"],
            "type": error["type"]
        })
    
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "Request validation failed",
                "details": {
                    "errors": formatted_errors
                }
            }
        }
    )


async def general_exception_handler(request: Request, exc: Exception):
    """Handle any unhandled exceptions."""
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An unexpected error occurred. Please try again later.",
                "details": {
                    "type": type(exc).__name__
                }
            }
        }
    )


def setup_exception_handlers(app):
    """Setup all exception handlers for the FastAPI app."""
    app.add_exception_handler(PhishingDetectorException, phishing_detector_exception_handler)
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, general_exception_handler)
