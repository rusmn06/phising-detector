"""
Configuration module for the application.
Uses Pydantic Settings for automatic validation.
"""
from pydantic_settings import BaseSettings
from pathlib import Path

# Path to .env file (project root, one level above backend/)
BASE_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = BASE_DIR / ".env"


class Settings(BaseSettings):
    """
    Application configuration management class.
    Based on 'Email Phishing Scanner' blueprint.
    """
    
    # ===========================================
    # Application Settings
    # ===========================================
    APP_ENV: str = "development"
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "phising-detector-2"
    
    # ===========================================
    # Security & External APIs
    # ===========================================
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    SECRET_KEY: str = "change-this-to-random-string-in-production"
    
    # ===========================================
    # URL Threat Detection Provider
    # Options: "google_safe_browsing", "virustotal", "both"
    # ===========================================
    URL_THREAT_PROVIDER: str = "virustotal"
    
    # ===========================================
    # Rate Limiting
    # ===========================================
    RATE_LIMIT: str = "5/minute"
    
    # ===========================================
    # DNS Settings
    # ===========================================
    DNS_TIMEOUT: float = 5.0
    DNS_NAMESERVERS: str = "8.8.8.8,8.8.4.4"
    
    class Config:
        env_file = ENV_FILE
        env_file_encoding = "utf-8"
        case_sensitive = True
        extra = "ignore"  # Ignore undefined .env variables


# Global settings instance
settings = Settings()