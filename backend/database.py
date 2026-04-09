"""
Database configuration and models for storing scan history.
Uses SQLite for simplicity (production can migrate to PostgreSQL).
"""
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta
import logging
import os

logger = logging.getLogger(__name__)

# SQLite database path
os.makedirs("data", exist_ok=True)
SQLALCHEMY_DATABASE_URL = "sqlite:///./data/scan_history.db"

# Create database engine
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
    Model to store scan history.
    Each scan is saved for reference and audit.
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
            "scanned_at": self.scanned_at.isoformat() if self.scanned_at else None,
            "ip_address": self.ip_address,
        }


class CleanupLog(Base):
    """
    Model for logging cleanup jobs (auto-delete records >30 days).
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
    Dependency to get database session.
    Use in endpoints with Depends(get_db).
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initialize database - create tables if not exist."""
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized successfully")


def cleanup_old_records(db, retention_days: int = 30):
    """
    Delete scan history older than retention_days.
    
    Args:
        db: Database session
        retention_days: Days to retain records (default: 30)
    
    Returns:
        Dict with status and number of deleted records
    """
    try:
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        old_records = db.query(ScanHistory).filter(
            ScanHistory.scanned_at < cutoff_date
        )
        
        deleted_count = old_records.count()
        old_records.delete(synchronize_session=False)
        db.commit()
        
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
        
        log = CleanupLog(
            records_deleted=0,
            status="failed",
            error_message=str(e)
        )
        db.add(log)
        db.commit()
        
        return {"status": "failed", "error": str(e)}