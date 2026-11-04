"""SQLite-backed session factory."""
import datetime

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from .config import settings
from .models import Base, Scan

engine = create_engine(settings.database_url, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    Base.metadata.create_all(engine)
    # Concurrent pipelines + API handlers share this file; WAL keeps
    # readers from blocking writers.
    try:
        with engine.connect() as conn:
            conn.execute(text("PRAGMA journal_mode=WAL;"))
            conn.commit()
    except Exception:
        pass


def fail_stale_scans() -> int:
    """Mark scans left mid-pipeline by a server restart as failed."""
    session = SessionLocal()
    try:
        stale = session.query(Scan).filter(~Scan.status.in_(["done", "failed"])).all()
        for scan in stale:
            scan.status = "failed"
            scan.error = "interrupted by server restart"
            scan.finished_at = datetime.datetime.now(datetime.timezone.utc)
        session.commit()
        return len(stale)
    finally:
        session.close()


def get_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
