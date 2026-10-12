from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict


# Application Schemas
class ApplicationBase(BaseModel):
    name: str
    repo_url: str
    default_branch: str = "main"


class ApplicationCreate(ApplicationBase):
    pass


class ApplicationResponse(ApplicationBase):
    id: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


# Finding Schemas
class FindingBase(BaseModel):
    rule_id: str
    severity: str
    title: str
    description: Optional[str] = None
    file_or_package: str
    line_number: Optional[int] = None
    remediation: Optional[str] = None
    status: str = "open"


class FindingCreate(FindingBase):
    scan_run_id: int


class FindingResponse(FindingBase):
    id: int
    scan_run_id: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


# ScanRun Schemas
class ScanRunBase(BaseModel):
    scanner: str
    status: str = "pending"
    findings_count: int = 0
    report_location: Optional[str] = None


class ScanRunCreate(ScanRunBase):
    pipeline_run_id: int


class ScanRunResponse(ScanRunBase):
    id: int
    pipeline_run_id: int
    created_at: datetime
    findings: List[FindingResponse] = []
    model_config = ConfigDict(from_attributes=True)


# PipelineRun Schemas
class PipelineRunBase(BaseModel):
    provider: str
    commit_id: str
    branch: str = "main"
    status: str = "pending"


class PipelineRunCreate(PipelineRunBase):
    application_id: int


class PipelineRunResponse(PipelineRunBase):
    id: int
    application_id: int
    started_at: datetime
    completed_at: Optional[datetime] = None
    scans: List[ScanRunResponse] = []
    model_config = ConfigDict(from_attributes=True)


# DependencyUpdate Schemas
class DependencyUpdateBase(BaseModel):
    package_name: str
    current_version: str
    proposed_version: str
    review_status: str = "pending"


class DependencyUpdateCreate(DependencyUpdateBase):
    application_id: int


class DependencyUpdateResponse(DependencyUpdateBase):
    id: int
    application_id: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


# Deployment Schemas
class DeploymentBase(BaseModel):
    image_tag: str
    target_environment: str = "local"
    status: str = "running"
    health: str = "healthy"


class DeploymentCreate(DeploymentBase):
    application_id: int


class DeploymentResponse(DeploymentBase):
    id: int
    application_id: int
    deployed_at: datetime
    model_config = ConfigDict(from_attributes=True)


# Dashboard Overview Schema
class DashboardOverview(BaseModel):
    total_applications: int
    total_pipelines: int
    total_findings: int
    critical_findings: int
    high_findings: int
    pending_dependency_updates: int
    active_deployments: int
    latest_pipeline_status: Optional[str] = None
