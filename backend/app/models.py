from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship

from .database import Base


def utc_now():
    return datetime.now(timezone.utc)


class Application(Base):
    __tablename__ = "applications"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    repo_url = Column(String(255), nullable=False)
    default_branch = Column(String(50), default="main", nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    pipeline_runs = relationship("PipelineRun", back_populates="application", cascade="all, delete-orphan")
    dependency_updates = relationship("DependencyUpdate", back_populates="application", cascade="all, delete-orphan")
    deployments = relationship("Deployment", back_populates="application", cascade="all, delete-orphan")


class PipelineRun(Base):
    __tablename__ = "pipeline_runs"

    id = Column(Integer, primary_key=True, index=True)
    application_id = Column(Integer, ForeignKey("applications.id"), nullable=False)
    provider = Column(String(50), nullable=False)  # github, jenkins, gitlab, azure
    commit_id = Column(String(64), nullable=False)
    branch = Column(String(100), default="main", nullable=False)
    status = Column(String(30), default="pending", nullable=False)  # pending, running, success, failed
    started_at = Column(DateTime, default=utc_now, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    application = relationship("Application", back_populates="pipeline_runs")
    scans = relationship("ScanRun", back_populates="pipeline_run", cascade="all, delete-orphan")


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True, index=True)
    pipeline_run_id = Column(Integer, ForeignKey("pipeline_runs.id"), nullable=False)
    scanner = Column(String(50), nullable=False)  # semgrep, gitleaks, trivy, pip-audit
    status = Column(String(30), default="pending", nullable=False)  # pending, running, success, failed
    findings_count = Column(Integer, default=0, nullable=False)
    report_location = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    pipeline_run = relationship("PipelineRun", back_populates="scans")
    findings = relationship("Finding", back_populates="scan_run", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id"), nullable=False)
    rule_id = Column(String(100), nullable=False, index=True)
    severity = Column(String(20), nullable=False)  # critical, high, medium, low, info
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    file_or_package = Column(String(255), nullable=False)
    line_number = Column(Integer, nullable=True)
    remediation = Column(Text, nullable=True)
    status = Column(String(20), default="open", nullable=False)  # open, resolved, excepted
    created_at = Column(DateTime, default=utc_now, nullable=False)

    scan_run = relationship("ScanRun", back_populates="findings")


class DependencyUpdate(Base):
    __tablename__ = "dependency_updates"

    id = Column(Integer, primary_key=True, index=True)
    application_id = Column(Integer, ForeignKey("applications.id"), nullable=False)
    package_name = Column(String(100), nullable=False)
    current_version = Column(String(50), nullable=False)
    proposed_version = Column(String(50), nullable=False)
    review_status = Column(String(30), default="pending", nullable=False)  # pending, approved, rejected, merged
    created_at = Column(DateTime, default=utc_now, nullable=False)

    application = relationship("Application", back_populates="dependency_updates")


class Deployment(Base):
    __tablename__ = "deployments"

    id = Column(Integer, primary_key=True, index=True)
    application_id = Column(Integer, ForeignKey("applications.id"), nullable=False)
    image_tag = Column(String(100), nullable=False)
    target_environment = Column(String(50), default="local", nullable=False)  # local, staging, prod
    status = Column(String(30), default="running", nullable=False)  # deploying, running, stopped, failed
    health = Column(String(30), default="healthy", nullable=False)  # healthy, degraded, unhealthy
    deployed_at = Column(DateTime, default=utc_now, nullable=False)

    application = relationship("Application", back_populates="deployments")
