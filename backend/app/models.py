"""SQLAlchemy models for scans, findings, patches, verifications, evidence."""
import datetime
import uuid

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _uid() -> str:
    return uuid.uuid4().hex[:12]


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uid)
    repo_url: Mapped[str] = mapped_column(String(1024))
    branch: Mapped[str] = mapped_column(String(256), default="HEAD")
    status: Mapped[str] = mapped_column(String(32), default="queued")  # queued|scanning|triaging|patching|verifying|done|failed
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=_now)
    finished_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)
    repo_path: Mapped[str] = mapped_column(String(1024), default="")
    error: Mapped[str] = mapped_column(Text, default="")

    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    evidence: Mapped[list["Evidence"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(256))
    cwe: Mapped[str] = mapped_column(String(32), default="")
    severity: Mapped[str] = mapped_column(String(16), default="medium")  # critical|high|medium|low
    confidence: Mapped[str] = mapped_column(String(16), default="medium")
    file_path: Mapped[str] = mapped_column(String(1024))
    line_no: Mapped[int] = mapped_column(Integer)
    snippet: Mapped[str] = mapped_column(Text, default="")
    explanation: Mapped[str] = mapped_column(Text, default="")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_rationale: Mapped[str] = mapped_column(Text, default="")
    reproduced: Mapped[bool] = mapped_column(Boolean, default=False)
    repro_log: Mapped[str] = mapped_column(Text, default="")
    validated: Mapped[bool] = mapped_column(Boolean, default=False)
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False)

    scan: Mapped[Scan] = relationship(back_populates="findings")
    patches: Mapped[list["Patch"]] = relationship(back_populates="finding", cascade="all, delete-orphan")


class Patch(Base):
    __tablename__ = "patches"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uid)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    diff: Mapped[str] = mapped_column(Text, default="")
    summary: Mapped[str] = mapped_column(String(1024), default="")
    applied: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=_now)

    finding: Mapped[Finding] = relationship(back_populates="patches")
    verifications: Mapped[list["Verification"]] = relationship(back_populates="patch", cascade="all, delete-orphan")


class Verification(Base):
    __tablename__ = "verifications"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uid)
    patch_id: Mapped[str] = mapped_column(ForeignKey("patches.id"), index=True)
    status: Mapped[str] = mapped_column(String(16), default="inconclusive")  # fixed|unfixed|inconclusive
    rescan_clean: Mapped[bool] = mapped_column(Boolean, default=False)
    tests_passed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    test_log: Mapped[str] = mapped_column(Text, default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=_now)

    patch: Mapped[Patch] = relationship(back_populates="verifications")


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    stage: Mapped[str] = mapped_column(String(32))  # clone|scan|triage|risk|repro|patch|verify|done
    actor: Mapped[str] = mapped_column(String(64), default="system")
    message: Mapped[str] = mapped_column(Text, default="")
    ref_id: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=_now)

    scan: Mapped[Scan] = relationship(back_populates="evidence")
