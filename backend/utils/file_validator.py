import magic
from fastapi import UploadFile, HTTPException, status

# Konstanta batas ukuran (10 MB)
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024 
EXPECTED_MIME_TYPE = "message/rfc822"

async def validate_email_file(file: UploadFile) -> bytes:
    """
    Validasi file email yang diunggah:
    1. Cek ukuran file (maksimal 10MB).
    2. Cek Magic Bytes untuk memastikan tipe MIME yang benar.
    """
    
    # --- 1. Validasi Ukuran File ---
    # PENTING: Gunakan file.file (objek Python asli) untuk seek dengan 2 parameter
    file.file.seek(0, 2)  # SEEK_END - pindah ke akhir file
    file_size = file.file.tell()  # Dapatkan posisi (ukuran)
    file.file.seek(0)  # Reset pointer ke awal
    
    if file_size > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Ukuran file ({file_size} bytes) melebihi batas maksimal 10MB."
        )
    
    if file_size == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File kosong tidak diperbolehkan."
        )

    # --- 2. Validasi Magic Bytes (Tipe MIME) ---
    # Baca konten file (menggunakan async method dari UploadFile)
    file_content = await file.read()
    
    # Deteksi tipe MIME berdasarkan konten (bukan ekstensi!)
    mime_type = magic.from_buffer(file_content, mime=True)
    
    # Reset pointer lagi agar bisa dibaca ulang oleh fungsi parsing nanti
    # Gunakan file.file untuk seek sync
    file.file.seek(0)
    
    if mime_type != EXPECTED_MIME_TYPE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Tipe file tidak valid. Ditemukan '{mime_type}', diharapkan '{EXPECTED_MIME_TYPE}'."
        )
    
    # Jika lolos semua, kembalikan konten file
    return file_content