import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  GitBranch,
  Layers,
  Activity,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  RefreshCw,
  Box,
  Cpu,
  Package,
  Terminal,
  ExternalLink,
  PlusCircle,
  ShieldCheck,
  Server
} from 'lucide-react';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [backendHealth, setBackendHealth] = useState({ status: 'checking', message: 'Connecting to backend...' });
  const [overview, setOverview] = useState(null);
  const [applications, setApplications] = useState([]);
  const [pipelines, setPipelines] = useState([]);
  const [findings, setFindings] = useState([]);
  const [dependencies, setDependencies] = useState([]);
  const [deployments, setDeployments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // App Creation Modal State
  const [showAddApp, setShowAddApp] = useState(false);
  const [newAppName, setNewAppName] = useState('');
  const [newAppRepo, setNewAppRepo] = useState('');

  const fetchHealth = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/health`);
      if (res.ok) {
        const data = await res.json();
        setBackendHealth({ status: 'healthy', message: `Connected (${data.status})` });
      } else {
        setBackendHealth({ status: 'error', message: `HTTP ${res.status}` });
      }
    } catch (err) {
      setBackendHealth({ status: 'offline', message: 'Offline / Cannot connect to 127.0.0.1:8000' });
    }
  };

  const fetchAllData = async () => {
    setRefreshing(true);
    await fetchHealth();
    try {
      const [overviewRes, appsRes, pipesRes, findingsRes, depsRes, deploysRes] = await Promise.all([
        fetch(`${API_BASE_URL}/api/overview`).catch(() => null),
        fetch(`${API_BASE_URL}/api/applications`).catch(() => null),
        fetch(`${API_BASE_URL}/api/pipelines`).catch(() => null),
        fetch(`${API_BASE_URL}/api/findings`).catch(() => null),
        fetch(`${API_BASE_URL}/api/dependencies`).catch(() => null),
        fetch(`${API_BASE_URL}/api/deployments`).catch(() => null),
      ]);

      if (overviewRes && overviewRes.ok) setOverview(await overviewRes.json());
      if (appsRes && appsRes.ok) setApplications(await appsRes.json());
      if (pipesRes && pipesRes.ok) setPipelines(await pipesRes.json());
      if (findingsRes && findingsRes.ok) setFindings(await findingsRes.json());
      if (depsRes && depsRes.ok) setDependencies(await depsRes.json());
      if (deploysRes && deploysRes.ok) setDeployments(await deploysRes.json());
    } catch (e) {
      console.error('Error loading dashboard data:', e);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchAllData();
    const interval = setInterval(fetchHealth, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleCreateApp = async (e) => {
    e.preventDefault();
    if (!newAppName || !newAppRepo) return;
    try {
      const res = await fetch(`${API_BASE_URL}/api/applications`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newAppName, repo_url: newAppRepo, default_branch: 'main' }),
      });
      if (res.ok) {
        setNewAppName('');
        setNewAppRepo('');
        setShowAddApp(false);
        fetchAllData();
      }
    } catch (err) {
      console.error('Failed to create app', err);
    }
  };

  const renderStatusBadge = (status) => {
    const s = (status || '').toLowerCase();
    if (s === 'healthy' || s === 'running' || s === 'success' || s === 'passed') {
      return <span className="badge badge-success"><CheckCircle2 size={13} /> {status}</span>;
    }
    if (s === 'critical' || s === 'failed' || s === 'danger') {
      return <span className="badge badge-danger"><XCircle size={13} /> {status}</span>;
    }
    if (s === 'high' || s === 'warning' || s === 'pending') {
      return <span className="badge badge-warning"><AlertTriangle size={13} /> {status}</span>;
    }
    return <span className="badge badge-info">{status}</span>;
  };

  return (
    <div className="app-container">
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div className="brand-section">
          <div className="brand-logo-icon">
            <ShieldCheck size={22} />
          </div>
          <div>
            <div className="brand-title">SecureShip</div>
            <div className="brand-subtitle">DevSecOps Platform</div>
          </div>
        </div>

        <nav className="nav-menu">
          <button
            className={`nav-item ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveTab('overview')}
          >
            <Activity className="nav-icon" />
            <span>Overview</span>
          </button>

          <button
            className={`nav-item ${activeTab === 'applications' ? 'active' : ''}`}
            onClick={() => setActiveTab('applications')}
          >
            <Box className="nav-icon" />
            <span>Applications</span>
          </button>

          <button
            className={`nav-item ${activeTab === 'pipelines' ? 'active' : ''}`}
            onClick={() => setActiveTab('pipelines')}
          >
            <GitBranch className="nav-icon" />
            <span>Pipeline Runs</span>
          </button>

          <button
            className={`nav-item ${activeTab === 'findings' ? 'active' : ''}`}
            onClick={() => setActiveTab('findings')}
          >
            <ShieldAlert className="nav-icon" />
            <span>Security Findings</span>
          </button>

          <button
            className={`nav-item ${activeTab === 'dependencies' ? 'active' : ''}`}
            onClick={() => setActiveTab('dependencies')}
          >
            <Package className="nav-icon" />
            <span>Dependency Updates</span>
          </button>

          <button
            className={`nav-item ${activeTab === 'deployments' ? 'active' : ''}`}
            onClick={() => setActiveTab('deployments')}
          >
            <Layers className="nav-icon" />
            <span>Docker & Deployments</span>
          </button>

          <button
            className={`nav-item ${activeTab === 'monitoring' ? 'active' : ''}`}
            onClick={() => setActiveTab('monitoring')}
          >
            <Cpu className="nav-icon" />
            <span>Monitoring</span>
          </button>
        </nav>

        <div className="sidebar-footer">
          <div className="connection-pill">
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <span className={`status-dot ${backendHealth.status === 'healthy' ? 'healthy' : 'offline'}`} />
              <span style={{ fontWeight: 600 }}>Backend API</span>
            </div>
            <span style={{ color: backendHealth.status === 'healthy' ? '#10b981' : '#ef4444' }}>
              {backendHealth.status === 'healthy' ? 'Active' : 'Offline'}
            </span>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="main-wrapper">
        <header className="top-header">
          <div className="header-title-block">
            <h1>
              {activeTab === 'overview' && 'DevSecOps Overview Dashboard'}
              {activeTab === 'applications' && 'Monitored Applications'}
              {activeTab === 'pipelines' && 'Multi-CI/CD Pipeline History'}
              {activeTab === 'findings' && 'Vulnerability & Policy Findings'}
              {activeTab === 'dependencies' && 'Renovate Dependency Tracking'}
              {activeTab === 'deployments' && 'Container Deployments & Clusters'}
              {activeTab === 'monitoring' && 'Telemetry & Infrastructure Monitoring'}
            </h1>
            <p>FastAPI Backend · SQLite Database · Automated Pipeline Integration</p>
          </div>

          <div className="header-actions">
            <button
              className="action-btn"
              onClick={fetchAllData}
              disabled={refreshing}
            >
              <RefreshCw size={15} className={refreshing ? 'animate-spin' : ''} />
              <span>Refresh</span>
            </button>
            {activeTab === 'applications' && (
              <button
                className="action-btn primary"
                onClick={() => setShowAddApp(true)}
              >
                <PlusCircle size={15} />
                <span>Add Application</span>
              </button>
            )}
          </div>
        </header>

        <main className="content-body">
          {/* TAB 1: OVERVIEW */}
          {activeTab === 'overview' && (
            <>
              <div className="stat-grid">
                <div className="stat-card">
                  <div className="stat-card-header">
                    <span className="stat-card-title">Pipeline Status</span>
                    <div className="stat-icon-wrapper" style={{ color: '#10b981' }}>
                      <CheckCircle2 size={18} />
                    </div>
                  </div>
                  <div className="stat-value" style={{ color: '#10b981' }}>
                    {overview?.latest_pipeline_status || 'Active'}
                  </div>
                  <div className="stat-hint">
                    Across GitHub Actions, Jenkins, GitLab, Azure
                  </div>
                </div>

                <div className="stat-card">
                  <div className="stat-card-header">
                    <span className="stat-card-title">Security Findings</span>
                    <div className="stat-icon-wrapper" style={{ color: '#ef4444' }}>
                      <ShieldAlert size={18} />
                    </div>
                  </div>
                  <div className="stat-value">
                    {overview?.total_findings ?? 0}
                  </div>
                  <div className="stat-hint">
                    {overview?.critical_findings ?? 0} Critical · {overview?.high_findings ?? 0} High
                  </div>
                </div>

                <div className="stat-card">
                  <div className="stat-card-header">
                    <span className="stat-card-title">Outdated Dependencies</span>
                    <div className="stat-icon-wrapper" style={{ color: '#f59e0b' }}>
                      <Package size={18} />
                    </div>
                  </div>
                  <div className="stat-value">
                    {overview?.pending_dependency_updates ?? 0}
                  </div>
                  <div className="stat-hint">
                    Renovate Automated PR candidates
                  </div>
                </div>

                <div className="stat-card">
                  <div className="stat-card-header">
                    <span className="stat-card-title">Active Deployments</span>
                    <div className="stat-icon-wrapper" style={{ color: '#06b6d4' }}>
                      <Layers size={18} />
                    </div>
                  </div>
                  <div className="stat-value">
                    {overview?.active_deployments ?? 1}
                  </div>
                  <div className="stat-hint">
                    Docker Compose & Kubernetes target
                  </div>
                </div>
              </div>

              {/* DevSecOps Pipeline Flow Diagram Card */}
              <div className="card-panel">
                <div className="panel-header">
                  <div>
                    <h2 className="panel-title">
                      <Terminal size={18} style={{ color: '#6366f1' }} />
                      DevSecOps Execution Pipeline Architecture
                    </h2>
                    <p className="panel-description">End-to-end automated delivery lifecycle across all 4 CI/CD engines</p>
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px', marginTop: '10px' }}>
                  <div style={{ background: 'rgba(0,0,0,0.25)', padding: '16px', borderRadius: '10px', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.72rem', color: '#6366f1', fontWeight: 700, textTransform: 'uppercase' }}>Stage 1 · Code</div>
                    <div style={{ fontWeight: 600, marginTop: '4px' }}>Git & GitHub</div>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '4px' }}>Feature branches, pull requests</div>
                  </div>

                  <div style={{ background: 'rgba(0,0,0,0.25)', padding: '16px', borderRadius: '10px', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.72rem', color: '#06b6d4', fontWeight: 700, textTransform: 'uppercase' }}>Stage 2 · Test</div>
                    <div style={{ fontWeight: 600, marginTop: '4px' }}>Pytest & Newman</div>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '4px' }}>Unit & REST API integration</div>
                  </div>

                  <div style={{ background: 'rgba(0,0,0,0.25)', padding: '16px', borderRadius: '10px', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.72rem', color: '#f59e0b', fontWeight: 700, textTransform: 'uppercase' }}>Stage 3 · Security</div>
                    <div style={{ fontWeight: 600, marginTop: '4px' }}>Semgrep · Trivy · Gitleaks</div>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '4px' }}>SAST, secrets & vuln audit</div>
                  </div>

                  <div style={{ background: 'rgba(0,0,0,0.25)', padding: '16px', borderRadius: '10px', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.72rem', color: '#a855f7', fontWeight: 700, textTransform: 'uppercase' }}>Stage 4 · Package</div>
                    <div style={{ fontWeight: 600, marginTop: '4px' }}>Docker Container</div>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '4px' }}>Versioned build & image scan</div>
                  </div>

                  <div style={{ background: 'rgba(0,0,0,0.25)', padding: '16px', borderRadius: '10px', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.72rem', color: '#10b981', fontWeight: 700, textTransform: 'uppercase' }}>Stage 5 · Deploy</div>
                    <div style={{ fontWeight: 600, marginTop: '4px' }}>Compose / Helm & K8s</div>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '4px' }}>Zero-downtime rolling deploy</div>
                  </div>
                </div>
              </div>
            </>
          )}

          {/* TAB 2: APPLICATIONS */}
          {activeTab === 'applications' && (
            <div className="card-panel">
              <div className="panel-header">
                <div>
                  <h2 className="panel-title">Registered Applications</h2>
                  <p className="panel-description">Repositories connected for automated DevSecOps validation</p>
                </div>
              </div>

              {applications.length === 0 ? (
                <div className="empty-state">
                  <Box size={40} />
                  <p>No applications registered yet. Click "Add Application" to connect a repository.</p>
                </div>
              ) : (
                <div className="table-responsive">
                  <table className="custom-table">
                    <thead>
                      <tr>
                        <th>Application</th>
                        <th>Repository URL</th>
                        <th>Default Branch</th>
                        <th>Registered Date</th>
                      </tr>
                    </thead>
                    <tbody>
                      {applications.map((app) => (
                        <tr key={app.id}>
                          <td style={{ fontWeight: 600 }}>{app.name}</td>
                          <td>
                            <a href={app.repo_url} target="_blank" rel="noreferrer" style={{ color: '#38bdf8', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '6px' }}>
                              {app.repo_url} <ExternalLink size={12} />
                            </a>
                          </td>
                          <td><span className="mono-tag">{app.default_branch}</span></td>
                          <td style={{ color: 'var(--text-dim)' }}>{new Date(app.created_at).toLocaleDateString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: PIPELINES */}
          {activeTab === 'pipelines' && (
            <div className="card-panel">
              <div className="panel-header">
                <div>
                  <h2 className="panel-title">CI/CD Pipeline Executions</h2>
                  <p className="panel-description">Runs from GitHub Actions, Jenkins, GitLab CI/CD, and Azure Pipelines</p>
                </div>
              </div>

              {pipelines.length === 0 ? (
                <div className="empty-state">
                  <GitBranch size={40} />
                  <p>No pipeline runs logged yet. Execute a pipeline step to record telemetry.</p>
                </div>
              ) : (
                <div className="table-responsive">
                  <table className="custom-table">
                    <thead>
                      <tr>
                        <th>Provider</th>
                        <th>Commit</th>
                        <th>Branch</th>
                        <th>Status</th>
                        <th>Started At</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pipelines.map((pipe) => (
                        <tr key={pipe.id}>
                          <td style={{ fontWeight: 600, textTransform: 'capitalize' }}>{pipe.provider}</td>
                          <td><span className="mono-tag">{pipe.commit_id.slice(0, 8)}</span></td>
                          <td><span className="mono-tag">{pipe.branch}</span></td>
                          <td>{renderStatusBadge(pipe.status)}</td>
                          <td style={{ color: 'var(--text-dim)' }}>{new Date(pipe.started_at).toLocaleString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* TAB 4: FINDINGS */}
          {activeTab === 'findings' && (
            <div className="card-panel">
              <div className="panel-header">
                <div>
                  <h2 className="panel-title">Security & Vulnerability Findings</h2>
                  <p className="panel-description">Findings from SAST (Semgrep), Secrets (Gitleaks), and Vulnerabilities (Trivy)</p>
                </div>
              </div>

              {findings.length === 0 ? (
                <div className="empty-state">
                  <ShieldCheck size={40} style={{ color: '#10b981' }} />
                  <p>Zero security findings! All scans have passed security thresholds.</p>
                </div>
              ) : (
                <div className="table-responsive">
                  <table className="custom-table">
                    <thead>
                      <tr>
                        <th>Severity</th>
                        <th>Rule / CVE</th>
                        <th>Title</th>
                        <th>Location</th>
                        <th>Remediation</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {findings.map((f) => (
                        <tr key={f.id}>
                          <td>{renderStatusBadge(f.severity)}</td>
                          <td><span className="mono-tag">{f.rule_id}</span></td>
                          <td style={{ fontWeight: 600 }}>{f.title}</td>
                          <td><span className="mono-tag">{f.file_or_package}{f.line_number ? `:${f.line_number}` : ''}</span></td>
                          <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{f.remediation || 'Upgrade dependency'}</td>
                          <td><span className="badge badge-neutral">{f.status}</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* TAB 5: DEPENDENCIES */}
          {activeTab === 'dependencies' && (
            <div className="card-panel">
              <div className="panel-header">
                <div>
                  <h2 className="panel-title">Renovate Dependency Tracking</h2>
                  <p className="panel-description">Automated package audit and proposed version updates</p>
                </div>
              </div>

              {dependencies.length === 0 ? (
                <div className="empty-state">
                  <Package size={40} />
                  <p>All dependencies are up to date. Renovate will propose updates during scheduled cycles.</p>
                </div>
              ) : (
                <div className="table-responsive">
                  <table className="custom-table">
                    <thead>
                      <tr>
                        <th>Package</th>
                        <th>Current Version</th>
                        <th>Proposed Version</th>
                        <th>Review Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {dependencies.map((dep) => (
                        <tr key={dep.id}>
                          <td style={{ fontWeight: 600 }}>{dep.package_name}</td>
                          <td><span className="mono-tag">{dep.current_version}</span></td>
                          <td><span className="mono-tag" style={{ color: '#10b981' }}>{dep.proposed_version}</span></td>
                          <td>{renderStatusBadge(dep.review_status)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* TAB 6: DEPLOYMENTS */}
          {activeTab === 'deployments' && (
            <div className="card-panel">
              <div className="panel-header">
                <div>
                  <h2 className="panel-title">Container Deployments</h2>
                  <p className="panel-description">Docker Compose, Kubernetes & Helm deployment targets</p>
                </div>
              </div>

              {deployments.length === 0 ? (
                <div className="empty-state">
                  <Layers size={40} />
                  <p>No active deployments tracked. Build and deploy container images to populate.</p>
                </div>
              ) : (
                <div className="table-responsive">
                  <table className="custom-table">
                    <thead>
                      <tr>
                        <th>Image Tag</th>
                        <th>Target Environment</th>
                        <th>State</th>
                        <th>Health</th>
                        <th>Deployed At</th>
                      </tr>
                    </thead>
                    <tbody>
                      {deployments.map((d) => (
                        <tr key={d.id}>
                          <td><span className="mono-tag">{d.image_tag}</span></td>
                          <td><span className="badge badge-info">{d.target_environment}</span></td>
                          <td>{renderStatusBadge(d.status)}</td>
                          <td>{renderStatusBadge(d.health)}</td>
                          <td style={{ color: 'var(--text-dim)' }}>{new Date(d.deployed_at).toLocaleString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* TAB 7: MONITORING */}
          {activeTab === 'monitoring' && (
            <div className="card-panel">
              <div className="panel-header">
                <div>
                  <h2 className="panel-title">Observability & Health Telemetry</h2>
                  <p className="panel-description">Live metrics for FastAPI backend, Prometheus, and Grafana integration</p>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '20px', borderRadius: '12px', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>Backend Health Probe</span>
                    <Server size={18} style={{ color: '#10b981' }} />
                  </div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 700, marginTop: '8px', color: backendHealth.status === 'healthy' ? '#10b981' : '#ef4444' }}>
                    {backendHealth.message}
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', marginTop: '6px' }}>
                    Endpoint: {API_BASE_URL}/health
                  </div>
                </div>

                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '20px', borderRadius: '12px', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>Prometheus Metrics</span>
                    <Activity size={18} style={{ color: '#06b6d4' }} />
                  </div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 700, marginTop: '8px', color: '#06b6d4' }}>
                    Ready for Scraping
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', marginTop: '6px' }}>
                    Target: monitoring/prometheus/prometheus.yml
                  </div>
                </div>

                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '20px', borderRadius: '12px', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>Grafana Dashboard</span>
                    <Layers size={18} style={{ color: '#f59e0b' }} />
                  </div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 700, marginTop: '8px', color: '#f59e0b' }}>
                    Port :3000
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', marginTop: '6px' }}>
                    Target: monitoring/grafana/dashboards/
                  </div>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* Modal for Adding Application */}
      {showAddApp && (
        <div style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(0,0,0,0.7)',
          backdropFilter: 'blur(6px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 100
        }}>
          <div style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '14px',
            padding: '28px',
            width: '100%',
            maxWidth: '460px',
            boxShadow: '0 20px 40px rgba(0,0,0,0.6)'
          }}>
            <h3 style={{ fontSize: '1.15rem', fontWeight: 700, marginBottom: '6px' }}>Register New Application</h3>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '20px' }}>
              Connect a Git repository for continuous security analysis.
            </p>

            <form onSubmit={handleCreateApp} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, marginBottom: '6px', color: 'var(--text-muted)' }}>Application Name</label>
                <input
                  type="text"
                  placeholder="e.g. Payments Gateway"
                  value={newAppName}
                  onChange={(e) => setNewAppName(e.target.value)}
                  required
                  style={{
                    width: '100%',
                    padding: '10px 14px',
                    borderRadius: '8px',
                    background: 'var(--bg-primary)',
                    border: '1px solid var(--border-subtle)',
                    color: '#fff',
                    fontSize: '0.88rem'
                  }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, marginBottom: '6px', color: 'var(--text-muted)' }}>Repository URL</label>
                <input
                  type="url"
                  placeholder="https://github.com/org/repo"
                  value={newAppRepo}
                  onChange={(e) => setNewAppRepo(e.target.value)}
                  required
                  style={{
                    width: '100%',
                    padding: '10px 14px',
                    borderRadius: '8px',
                    background: 'var(--bg-primary)',
                    border: '1px solid var(--border-subtle)',
                    color: '#fff',
                    fontSize: '0.88rem'
                  }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '14px' }}>
                <button
                  type="button"
                  className="action-btn"
                  onClick={() => setShowAddApp(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="action-btn primary"
                >
                  Save Application
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
