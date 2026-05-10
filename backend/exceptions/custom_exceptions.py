"""
Custom exception classes for better error handling and structured responses.
"""

from typing import Optional, Dict, Any
from fastapi import HTTPException, status


class PhishingDetectorException(Exception):
    """Base exception class for phishing detector application."""
    
    def __init__(self, message: str, error_code: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)


class ValidationException(PhishingDetectorException):
    """Exception raised for validation errors."""
    
    def __init__(self, message: str, field: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "VALIDATION_ERROR", details)
        self.field = field


class FileProcessingException(PhishingDetectorException):
    """Exception raised during file processing."""
    
    def __init__(self, message: str, filename: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "FILE_PROCESSING_ERROR", details)
        self.filename = filename


class EmailParsingException(PhishingDetectorException):
    """Exception raised during email parsing."""
    
    def __init__(self, message: str, filename: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "EMAIL_PARSING_ERROR", details)
        self.filename = filename


class AuthenticationCheckException(PhishingDetectorException):
    """Exception raised during SPF/DMARC authentication checks."""
    
    def __init__(self, message: str, domain: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "AUTHENTICATION_CHECK_ERROR", details)
        self.domain = domain


class URLAnalysisException(PhishingDetectorException):
    """Exception raised during URL analysis."""
    
    def __init__(self, message: str, url: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "URL_ANALYSIS_ERROR", details)
        self.url = url


class ExternalAPIException(PhishingDetectorException):
    """Exception raised when external API calls fail."""
    
    def __init__(self, message: str, provider: Optional[str] = None, status_code: Optional[int] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "EXTERNAL_API_ERROR", details)
        self.provider = provider
        self.status_code = status_code


class QuotaExceededException(PhishingDetectorException):
    """Exception raised when API quota is exceeded."""
    
    def __init__(self, message: str, provider: Optional[str] = None, retry_after: Optional[int] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "QUOTA_EXCEEDED", details)
        self.provider = provider
        self.retry_after = retry_after


class DatabaseException(PhishingDetectorException):
    """Exception raised during database operations."""
    
    def __init__(self, message: str, operation: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "DATABASE_ERROR", details)
        self.operation = operation


# HTTP Exception helpers
def create_http_exception(exception: PhishingDetectorException, status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR) -> HTTPException:
    """Convert custom exception to HTTPException with structured response."""
    
    response_data = {
        "error": {
            "code": exception.error_code or "INTERNAL_ERROR",
            "message": exception.message,
            "details": exception.details
        }
    }
    
    # Add specific fields based on exception type
    if isinstance(exception, ValidationException) and exception.field:
        response_data["error"]["field"] = exception.field
    
    if isinstance(exception, FileProcessingException) and exception.filename:
        response_data["error"]["filename"] = exception.filename
    
    if isinstance(exception, ExternalAPIException):
        if exception.provider:
            response_data["error"]["provider"] = exception.provider
        if exception.status_code:
            response_data["error"]["status_code"] = exception.status_code
    
    if isinstance(exception, QuotaExceededException):
        if exception.provider:
            response_data["error"]["provider"] = exception.provider
        if exception.retry_after:
            response_data["error"]["retry_after"] = exception.retry_after
    
    return HTTPException(
        status_code=status_code,
        detail=response_data
    )


def create_validation_http_exception(message: str, field: Optional[str] = None) -> HTTPException:
    """Create validation HTTP exception."""
    exception = ValidationException(message, field)
    return create_http_exception(exception, status.HTTP_400_BAD_REQUEST)


def create_file_processing_http_exception(message: str, filename: Optional[str] = None) -> HTTPException:
    """Create file processing HTTP exception."""
    exception = FileProcessingException(message, filename)
    return create_http_exception(exception, status.HTTP_400_BAD_REQUEST)


def create_external_api_http_exception(message: str, provider: Optional[str] = None, status_code: Optional[int] = None) -> HTTPException:
    """Create external API HTTP exception."""
    exception = ExternalAPIException(message, provider, status_code)
    return create_http_exception(exception, status.HTTP_503_SERVICE_UNAVAILABLE)


def create_quota_exceeded_http_exception(message: str, provider: Optional[str] = None, retry_after: Optional[int] = None) -> HTTPException:
    """Create quota exceeded HTTP exception."""
    exception = QuotaExceededException(message, provider, retry_after)
    return create_http_exception(exception, status.HTTP_429_TOO_MANY_REQUESTS)
