import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database import Base, get_db

# Use an in-memory SQLite database with StaticPool so all threads/sessions share the same DB
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["application"] == "SecureShip"
    assert response.json()["status"] == "running"


def test_applications_flow():
    payload = {
        "name": "Payment Service",
        "repo_url": "https://github.com/secureship/payment-service",
        "default_branch": "main",
    }
    resp = client.post("/api/applications", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Payment Service"
    app_id = data["id"]

    get_resp = client.get("/api/applications")
    assert get_resp.status_code == 200
    apps = get_resp.json()
    assert len(apps) >= 1
    assert any(a["id"] == app_id for a in apps)


def test_pipelines_and_scans_flow():
    app_resp = client.post(
        "/api/applications",
        json={
            "name": "Auth Service",
            "repo_url": "https://github.com/secureship/auth-service",
            "default_branch": "main",
        },
    )
    app_id = app_resp.json()["id"]

    pipe_payload = {
        "application_id": app_id,
        "provider": "github-actions",
        "commit_id": "a1b2c3d4",
        "branch": "main",
        "status": "success",
    }
    pipe_resp = client.post("/api/pipelines", json=pipe_payload)
    assert pipe_resp.status_code == 201
    pipe_id = pipe_resp.json()["id"]

    scan_payload = {
        "pipeline_run_id": pipe_id,
        "scanner": "trivy",
        "status": "success",
        "findings_count": 0,
        "report_location": "tests/reports/trivy-results.json",
    }
    scan_resp = client.post("/api/scans", json=scan_payload)
    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()["id"]

    finding_payload = {
        "scan_run_id": scan_id,
        "rule_id": "CVE-2023-1234",
        "severity": "high",
        "title": "Vulnerable library detected",
        "description": "Buffer overflow in cryptography",
        "file_or_package": "cryptography@3.4.7",
        "line_number": 12,
        "remediation": "Upgrade cryptography >= 41.0.0",
        "status": "open",
    }
    finding_resp = client.post("/api/findings", json=finding_payload)
    assert finding_resp.status_code == 201

    findings_list = client.get("/api/findings?severity=high")
    assert findings_list.status_code == 200
    assert len(findings_list.json()) == 1

    overview = client.get("/api/overview")
    assert overview.status_code == 200
    overview_data = overview.json()
    assert overview_data["total_findings"] == 1
    assert overview_data["high_findings"] == 1
