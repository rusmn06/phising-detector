"""
Enhanced file validation utilities with proper error handling.
"""

import magic
import logging
from fastapi import UploadFile, HTTPException, status
from typing import Optional

from exceptions.custom_exceptions import create_file_processing_http_exception, create_validation_http_exception

logger = logging.getLogger(__name__)

# Allowed file types and their magic bytes
ALLOWED_MIME_TYPES = {
    'message/rfc822': ['.eml'],
    'text/plain': ['.eml', '.txt'],
}

# Maximum file size (10MB)
MAX_FILE_SIZE = 10 * 1024 * 1024

# Dangerous file extensions to block
DANGEROUS_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js', '.jar', '.app', '.deb', '.pkg', '.dmg',
    '.msi', '.php', '.asp', '.aspx', '.jsp', '.py', '.rb', '.pl', '.sh', '.ps1', '.vb', '.wsf', '.hta'
}


async def validate_email_file(file: UploadFile) -> bytes:
    """
    Validate uploaded email file with comprehensive checks.
    
    Args:
        file: UploadFile object from FastAPI
        
    Returns:
        bytes: Validated file content
        
    Raises:
        HTTPException: If validation fails
    """
    logger.info(f"Validating file: {file.filename}")
    
    # Check if filename is provided
    if not file.filename:
        raise create_validation_http_exception("Filename is required")
    
    # Check file extension
    file_extension = file.filename.lower().split('.')[-1] if '.' in file.filename else ''
    if not file_extension:
        raise create_validation_http_exception("File must have an extension")
    
    # Check for dangerous extensions
    full_extension = f".{file_extension}"
    if full_extension in DANGEROUS_EXTENSIONS:
        raise create_file_processing_http_exception(
            f"File type {full_extension} is not allowed for security reasons",
            file.filename
        )
    
    # Check file size
    try:
        file_content = await file.read()
        file_size = len(file_content)
        
        if file_size == 0:
            raise create_file_processing_http_exception("File is empty", file.filename)
        
        if file_size > MAX_FILE_SIZE:
            raise create_file_processing_http_exception(
                f"File size {file_size} bytes exceeds maximum allowed size of {MAX_FILE_SIZE} bytes",
                file.filename
            )
        
        # Reset file position for further processing
        await file.seek(0)
        
    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        logger.error(f"Error reading file {file.filename}: {e}")
        raise create_file_processing_http_exception(
            f"Error reading file: {str(e)}",
            file.filename
        )
    
    # Validate file type using magic bytes
    try:
        mime_type = magic.from_buffer(file_content, mime=True)
        logger.info(f"Detected MIME type: {mime_type} for file: {file.filename}")
        
        # Check if MIME type is allowed
        if mime_type not in ALLOWED_MIME_TYPES:
            allowed_types = ', '.join(ALLOWED_MIME_TYPES.keys())
            raise create_file_processing_http_exception(
                f"File type {mime_type} is not allowed. Allowed types: {allowed_types}",
                file.filename
            )
        
        # Additional check: ensure file extension matches MIME type
        allowed_extensions = ALLOWED_MIME_TYPES[mime_type]
        if full_extension not in allowed_extensions:
            raise create_file_processing_http_exception(
                f"File extension {full_extension} does not match detected file type {mime_type}",
                file.filename
            )
        
    except magic.MagicException as e:
        logger.error(f"Magic library error for file {file.filename}: {e}")
        raise create_file_processing_http_exception(
            "Unable to determine file type",
            file.filename
        )
    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        logger.error(f"Error validating file type for {file.filename}: {e}")
        raise create_file_processing_http_exception(
            f"File type validation failed: {str(e)}",
            file.filename
        )
    
    # Basic content validation - check for suspicious patterns
    await _validate_file_content(file_content, file.filename)
    
    logger.info(f"File validation successful: {file.filename}")
    return file_content


async def _validate_file_content(content: bytes, filename: str) -> None:
    """
    Validate file content for suspicious patterns.
    
    Args:
        content: File content as bytes
        filename: Original filename
        
    Raises:
        HTTPException: If suspicious content is found
    """
    try:
        content_str = content.decode('utf-8', errors='ignore').lower()
        
        # Check for suspicious script patterns in email content
        suspicious_patterns = [
            '<script',
            'javascript:',
            'vbscript:',
            'onload=',
            'onerror=',
            'onclick=',
            'eval(',
            'document.cookie',
            'window.location',
            'xss',
            '<iframe',
            'data:text/html',
        ]
        
        found_patterns = []
        for pattern in suspicious_patterns:
            if pattern in content_str:
                found_patterns.append(pattern)
        
        # Allow some patterns that might be legitimate in email content
        # but flag highly suspicious ones
        high_risk_patterns = ['<script', 'javascript:', 'vbscript:', 'eval(']
        high_risk_found = [p for p in high_risk_patterns if p in content_str]
        
        if high_risk_found:
            logger.warning(f"High-risk patterns found in {filename}: {high_risk_found}")
            # Don't reject file, but log for security monitoring
            # In production, you might want to quarantine such files
        
    except UnicodeDecodeError:
        # File contains binary content, which is suspicious for email files
        logger.warning(f"File {filename} contains binary content")
        raise create_file_processing_http_exception(
            "File appears to contain binary content, which is not allowed for email files",
            filename
        )
    except Exception as e:
        logger.error(f"Error validating content for {filename}: {e}")
        # Don't fail validation for content checking errors, just log them


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent directory traversal and injection attacks.
    
    Args:
        filename: Original filename
        
    Returns:
        str: Sanitized filename
    """
    if not filename:
        return "unknown_file.eml"
    
    # Remove path separators and dangerous characters
    sanitized = filename.replace('\\', '/').split('/')[-1]
    sanitized = sanitized.replace('..', '')
    sanitized = ''.join(c for c in sanitized if c.isalnum() or c in '.-_')
    
    # Ensure filename is not empty after sanitization
    if not sanitized or sanitized == '.' or sanitized == '..':
        sanitized = "sanitized_file.eml"
    
    return sanitized[:255]  # Limit filename length
