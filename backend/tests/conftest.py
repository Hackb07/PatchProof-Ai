import os
import sys
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

os.environ.setdefault("LLM_MOCK", "1")


@pytest.fixture()
def tmp_db(monkeypatch, tmp_path):
    db = tmp_path / "test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db}")
    # Re-import store with the test DB URL.
    import app.store as store
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.models import Base

    engine = create_engine(f"sqlite:///{db}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    store.engine = engine
    store.SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    store.init_db()
    yield db


@pytest.fixture()
def client(tmp_db):
    from app.main import app

    return TestClient(app)


@pytest.fixture()
def fixture_repo():
    return str(ROOT / "fixtures" / "vuln-app")
