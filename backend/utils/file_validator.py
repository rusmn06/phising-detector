"""
Email file validation utility.
Validates file size and MIME type using magic bytes.
"""
import magic
from fastapi import UploadFile, HTTPException, status

# Constants
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
EXPECTED_MIME_TYPE = "message/rfc822"


async def validate_email_file(file: UploadFile) -> bytes:
    """
    Validate uploaded email file:
    1. Check file size (max 10MB).
    2. Check Magic Bytes for correct MIME type.
    
    Args:
        file: Uploaded file object
        
    Returns:
        File content as bytes
        
    Raises:
        HTTPException: If validation fails
    """
    
    # --- 1. Validate File Size ---
    file.file.seek(0, 2)  # Seek to end
    file_size = file.file.tell()
    file.file.seek(0)  # Reset pointer
    
    if file_size > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File size ({file_size} bytes) exceeds maximum limit of 10MB."
        )
    
    if file_size == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty file is not allowed."
        )

    # --- 2. Validate Magic Bytes (MIME Type) ---
    file_content = await file.read()
    mime_type = magic.from_buffer(file_content, mime=True)
    file.file.seek(0)  # Reset pointer for later reading
    
    if mime_type != EXPECTED_MIME_TYPE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file type. Found '{mime_type}', expected '{EXPECTED_MIME_TYPE}'."
        )
    
    return file_content