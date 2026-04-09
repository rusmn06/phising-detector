"""
Database configuration dan models untuk menyimpan history scan.
Menggunakan SQLite untuk simplicity (production bisa migrate ke PostgreSQL).
"""

from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime, timedelta, timezone
import logging
import os

logger = logging.getLogger(__name__)

# SQLite database path
# Buat folder data jika belum ada
os.makedirs("data", exist_ok=True)
SQLALCHEMY_DATABASE_URL = "sqlite:///./data/scan_history.db"

# Create database engine
# check_same_thread=False needed for SQLite with FastAPI
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, 
    connect_args={"check_same_thread": False}
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()

# ===========================================
# Database Models
# ===========================================

class ScanHistory(Base):
    """
    Model untuk menyimpan history scan email.
    Setiap scan akan disimpan untuk referensi dan audit.
    """
    __tablename__ = "scan_history"
    
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False, index=True)
    verdict = Column(String(20), nullable=False, index=True)  # safe/suspicious/phishing
    risk_score = Column(Integer, nullable=False)
    from_domain = Column(String(255), index=True)
    from_email = Column(String(255))
    subject = Column(Text)
    url_count = Column(Integer, default=0)
    threatening_url_count = Column(Integer, default=0)
    scanned_at = Column(DateTime, default=datetime.utcnow, index=True)
    ip_address = Column(String(45))  # For audit trail
    result_data = Column(JSON)  # Full response stored for detail view
    
    def to_dict(self):
        """Convert model to dictionary for API response."""
        scanned_at = None
        if self.scanned_at:
            # treat as UTC and serialize with 'Z' so JS parses it as UTC
            scanned_at = (
                self.scanned_at
                .replace(tzinfo=timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
            )
        return {
            "id": self.id,
            "filename": self.filename,
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "from_domain": self.from_domain,
            "from_email": self.from_email,
            "subject": self.subject,
            "url_count": self.url_count,
            "threatening_url_count": self.threatening_url_count,
            "scanned_at": scanned_at,
            "ip_address": self.ip_address,
        }

class CleanupLog(Base):
    """
    Model untuk logging cleanup job (auto-delete record >30 hari).
    """
    __tablename__ = "cleanup_log"
    
    id = Column(Integer, primary_key=True, index=True)
    executed_at = Column(DateTime, default=datetime.utcnow)
    records_deleted = Column(Integer, default=0)
    status = Column(String(20))  # success/failed
    error_message = Column(Text)

# ===========================================
# Database Functions
# ===========================================

def get_db():
    """
    Dependency untuk mendapatkan database session.
    Gunakan di endpoint dengan Depends(get_db).
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """
    Initialize database - create tables if not exist.
    Panggil ini saat aplikasi start.
    """
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized successfully")

def cleanup_old_records(db: SessionLocal, retention_days: int = 30):
    """
    Delete scan history older than retention_days.
    Dipanggil secara otomatis setiap hari atau manual via endpoint.
    
    Args:
        db: Database session
        retention_days: Berapa hari record disimpan (default: 30)
    
    Returns:
        Dict dengan status dan jumlah record yang dihapus
    """
    try:
        # Hitung cutoff date
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        # Query record yang akan dihapus
        old_records = db.query(ScanHistory).filter(
            ScanHistory.scanned_at < cutoff_date
        )
        
        # Hitung jumlah sebelum delete
        deleted_count = old_records.count()
        
        # Delete records
        old_records.delete(synchronize_session=False)
        db.commit()
        
        # Log cleanup activity
        log = CleanupLog(
            records_deleted=deleted_count,
            status="success"
        )
        db.add(log)
        db.commit()
        
        logger.info(f"Cleanup completed: {deleted_count} records deleted (older than {retention_days} days)")
        
        return {"status": "success", "deleted": deleted_count}
        
    except Exception as e:
        db.rollback()
        logger.error(f"Cleanup failed: {e}")
        
        # Log error
        log = CleanupLog(
            records_deleted=0,
            status="failed",
            error_message=str(e)
        )
        db.add(log)
        db.commit()
        
        return {"status": "failed", "error": str(e)}