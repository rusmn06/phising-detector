# backend/config.py
from pydantic_settings import BaseSettings
from pathlib import Path

# Tentukan path ke file .env
BASE_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = BASE_DIR / ".env"

class Settings(BaseSettings):
    """
    Kelas untuk mengelola konfigurasi aplikasi.
    """
    
    # Aplikasi
    APP_ENV: str = "development"
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Email Phishing Scanner"
    
    # Keamanan & API Eksternal
    GOOGLE_SAFE_BROWSING_API_KEY: str
    SECRET_KEY: str
    
    # Rate Limiting
    RATE_LIMIT: str = "5/minute"
    
    class Config:
        env_file = ENV_FILE
        env_file_encoding = "utf-8"
        case_sensitive = True

settings = Settings()