from contextlib import asynccontextmanager
import os
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, Query, Response, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func

from .database import engine, Base, get_db
from .models import Application, PipelineRun, ScanRun, Finding, DependencyUpdate, Deployment, utc_now
from . import schemas


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables on startup
    Base.metadata.create_all(bind=engine)
    # Seed default SecureShip application if none exists
    db = next(get_db())
    try:
        app_count = db.query(Application).count()
        if app_count == 0:
            demo_app = Application(
                name="SecureShip Core",
                repo_url="https://github.com/secureship/secureship",
                default_branch="main",
            )
            db.add(demo_app)
            db.commit()
    finally:
        db.close()
    yield


app = FastAPI(
    title="SecureShip API",
    description="Automated DevSecOps platform API for vulnerability detection, dependency management and deployments",
    version="0.1.0",
    lifespan=lifespan,
)

CORS_ALLOWED_ORIGINS = [
    origin.strip().rstrip("/")
    for origin in os.getenv(
        "SECURESHIP_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]

# Enable CORS for frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Instrument with Prometheus metrics at /metrics
from prometheus_fastapi_instrumentator import Instrumentator
Instrumentator().instrument(app).expose(app)


@app.get("/")
def root():
    return {
        "application": "SecureShip",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


# Overview Endpoint
@app.get("/api/overview", response_model=schemas.DashboardOverview)
def get_overview(db: Session = Depends(get_db)):
    total_apps = db.query(Application).count()
    total_pipelines = db.query(PipelineRun).count()
    total_findings = db.query(Finding).count()
    critical_findings = db.query(Finding).filter(Finding.severity.ilike("critical")).count()
    high_findings = db.query(Finding).filter(Finding.severity.ilike("high")).count()
    pending_deps = db.query(DependencyUpdate).filter(DependencyUpdate.review_status == "pending").count()
    active_deployments = db.query(Deployment).filter(Deployment.status == "running").count()

    latest_pipeline = db.query(PipelineRun).order_by(PipelineRun.id.desc()).first()
    latest_status = latest_pipeline.status if latest_pipeline else "Passed (Simulated)"

    return schemas.DashboardOverview(
        total_applications=total_apps,
        total_pipelines=total_pipelines,
        total_findings=total_findings,
        critical_findings=critical_findings,
        high_findings=high_findings,
        pending_dependency_updates=pending_deps,
        active_deployments=active_deployments,
        latest_pipeline_status=latest_status,
    )


# Applications Endpoints
@app.get("/api/applications", response_model=List[schemas.ApplicationResponse])
def get_applications(db: Session = Depends(get_db)):
    return db.query(Application).order_by(Application.created_at.desc()).all()


@app.post("/api/applications", response_model=schemas.ApplicationResponse, status_code=status.HTTP_201_CREATED)
def create_application(app_in: schemas.ApplicationCreate, db: Session = Depends(get_db)):
    existing = db.query(Application).filter(Application.name == app_in.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Application with this name already exists")
    new_app = Application(**app_in.model_dump())
    db.add(new_app)
    db.commit()
    db.refresh(new_app)
    return new_app


# Pipelines Endpoints
@app.get("/api/pipelines", response_model=List[schemas.PipelineRunResponse])
def get_pipelines(
    application_id: Optional[int] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    query = db.query(PipelineRun)
    if application_id is not None:
        query = query.filter(PipelineRun.application_id == application_id)
    return query.order_by(PipelineRun.started_at.desc()).limit(limit).all()


@app.post("/api/pipelines", response_model=schemas.PipelineRunResponse, status_code=status.HTTP_201_CREATED)
def create_pipeline_run(run_in: schemas.PipelineRunCreate, db: Session = Depends(get_db)):
    app_obj = db.query(Application).filter(Application.id == run_in.application_id).first()
    if not app_obj:
        raise HTTPException(status_code=404, detail="Application not found")
    pipeline_run = PipelineRun(**run_in.model_dump())
    db.add(pipeline_run)
    db.commit()
    db.refresh(pipeline_run)
    return pipeline_run


@app.patch("/api/pipelines/{pipeline_id}", response_model=schemas.PipelineRunResponse)
def finish_pipeline_run(
    pipeline_id: int,
    status_in: schemas.PipelineRunStatusUpdate,
    db: Session = Depends(get_db),
):
    pipeline_run = db.query(PipelineRun).filter(PipelineRun.id == pipeline_id).first()
    if not pipeline_run:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    if pipeline_run.completed_at is not None:
        if pipeline_run.status != status_in.status:
            raise HTTPException(status_code=409, detail="Pipeline run is already complete")
        return pipeline_run

    pipeline_run.status = status_in.status
    pipeline_run.completed_at = utc_now()
    db.commit()
    db.refresh(pipeline_run)
    return pipeline_run


# Scans Endpoints
@app.get("/api/scans", response_model=List[schemas.ScanRunResponse])
def get_scans(
    pipeline_run_id: Optional[int] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
):
    query = db.query(ScanRun)
    if pipeline_run_id is not None:
        query = query.filter(ScanRun.pipeline_run_id == pipeline_run_id)
    return query.order_by(ScanRun.created_at.desc()).limit(limit).all()


@app.post("/api/scans", response_model=schemas.ScanRunResponse, status_code=status.HTTP_201_CREATED)
def create_scan_run(scan_in: schemas.ScanRunCreate, db: Session = Depends(get_db)):
    pipeline = db.query(PipelineRun).filter(PipelineRun.id == scan_in.pipeline_run_id).first()
    if not pipeline:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    scan_run = ScanRun(**scan_in.model_dump())
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)
    return scan_run


# Findings Endpoints
@app.get("/api/findings", response_model=List[schemas.FindingResponse])
def get_findings(
    severity: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    query = db.query(Finding)
    if severity:
        query = query.filter(Finding.severity.ilike(severity))
    if status_filter:
        query = query.filter(Finding.status == status_filter)
    return query.order_by(Finding.created_at.desc()).limit(limit).all()


@app.post("/api/findings", response_model=schemas.FindingResponse, status_code=status.HTTP_201_CREATED)
def create_finding(
    finding_in: schemas.FindingCreate,
    response: Response,
    db: Session = Depends(get_db),
):
    scan = db.query(ScanRun).filter(ScanRun.id == finding_in.scan_run_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan run not found")

    # Make retries idempotent within a scan. Re-running a scanner creates a new
    # scan_run_id, so historical results remain distinct across separate runs.
    existing = (
        db.query(Finding)
        .filter(
            Finding.scan_run_id == finding_in.scan_run_id,
            Finding.rule_id == finding_in.rule_id,
            Finding.file_or_package == finding_in.file_or_package,
            Finding.line_number == finding_in.line_number,
        )
        .first()
    )
    if existing:
        response.status_code = status.HTTP_200_OK
        return existing

    finding = Finding(**finding_in.model_dump())
    db.add(finding)
    # Increment scan finding count
    scan.findings_count += 1
    db.commit()
    db.refresh(finding)
    return finding


# Dependencies Endpoints
@app.get("/api/dependencies", response_model=List[schemas.DependencyUpdateResponse])
def get_dependencies(
    application_id: Optional[int] = Query(None),
    review_status: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    query = db.query(DependencyUpdate)
    if application_id is not None:
        query = query.filter(DependencyUpdate.application_id == application_id)
    if review_status:
        query = query.filter(DependencyUpdate.review_status == review_status)
    return query.order_by(DependencyUpdate.created_at.desc()).all()


@app.post("/api/dependencies", response_model=schemas.DependencyUpdateResponse, status_code=status.HTTP_201_CREATED)
def create_dependency_update(dep_in: schemas.DependencyUpdateCreate, db: Session = Depends(get_db)):
    app_obj = db.query(Application).filter(Application.id == dep_in.application_id).first()
    if not app_obj:
        raise HTTPException(status_code=404, detail="Application not found")
    dep = DependencyUpdate(**dep_in.model_dump())
    db.add(dep)
    db.commit()
    db.refresh(dep)
    return dep


# Deployments Endpoints
@app.get("/api/deployments", response_model=List[schemas.DeploymentResponse])
def get_deployments(
    application_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
):
    query = db.query(Deployment)
    if application_id is not None:
        query = query.filter(Deployment.application_id == application_id)
    return query.order_by(Deployment.deployed_at.desc()).all()


@app.post("/api/deployments", response_model=schemas.DeploymentResponse, status_code=status.HTTP_201_CREATED)
def create_deployment(dep_in: schemas.DeploymentCreate, db: Session = Depends(get_db)):
    app_obj = db.query(Application).filter(Application.id == dep_in.application_id).first()
    if not app_obj:
        raise HTTPException(status_code=404, detail="Application not found")
    deployment = Deployment(**dep_in.model_dump())
    db.add(deployment)
    db.commit()
    db.refresh(deployment)
    return deployment
