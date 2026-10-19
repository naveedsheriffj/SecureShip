# SecureShip — Secure Container Delivery Platform

[![Test Suite](https://img.shields.io/badge/tests-25%20passed-brightgreen.svg)](#running-automated-tests)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.14-blue.svg)](https://python.org)
[![Security Gate](https://img.shields.io/badge/security-Trivy%20Gated-cyan.svg)](#architecture)
[![Host Binding](https://img.shields.io/badge/host-127.0.0.1%20only-green.svg)](#security-model)

SecureShip is a **DevSecOps security gate** situated between container image creation and production deployment. It ensures that no container image can be launched into an execution environment unless its security scan completes successfully, produces authentic vulnerability findings, and satisfies the configured organization security policy.

---

## Architecture Overview

```
               [ Developer / CI Pipeline ]
                           │
                           ▼
             ┌───────────────────────────┐
             │    SecureShip Platform    │
             │   (Flask + Pure JS UI)    │
             └─────────────┬─────────────┘
                           │
         ┌─────────────────┴─────────────────┐
         ▼                                   ▼
┌──────────────────┐               ┌──────────────────┐
│  Trivy Scanner   │               │   Policy Engine  │
│  (Subprocess)    │               │  (Deterministic) │
└────────┬─────────┘               └────────┬─────────┘
         │                                   │
         ▼                                   ▼
┌─────────────────────────────────────────────────────┐
│             8-Point Gatekeeper Verification          │
│   1. Valid scan exists    5. Active policy recheck  │
│   2. Image ref match      6. Immutable image ID     │
│   3. Ref syntax check     7. Authentic scan check   │
│   4. Scan policy approval 8. Localhost host limits  │
└──────────────────────────┬──────────────────────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
      [ POLICY PASS ]            [ POLICY FAIL ]
              │                         │
     Deploy to 127.0.0.1         BLOCKED & AUDITED
   (Restricted Ports 5010+)    (Zero Execution Allowed)
```

---

## Key Features

1. **Deterministic Policy Gatekeeper**: Pure, testable policy engine evaluating CVE severities (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN).
2. **Real Trivy Security Integration**: Native invocation of `trivy image --format json` through safe argument-list subprocesses (no `shell=True`).
3. **8-Point Deployment Verification**: Validates completed scan existence, tag match, immutable image ID, active policy consistency, and host restrictions before launching containers.
4. **Interactive DevSecOps Dashboard**:
   - Live metrics calculated directly from database records.
   - Severity distribution donut and pass/fail distribution charts (Chart.js).
   - Searchable, severity-filtered vulnerability table with advisory links.
   - Raw JSON report download with directory traversal protection.
5. **Configurable Security Policies**: Dynamic threshold adjustments with mandatory change justification and immutable revision history.
6. **Container Lifecycle Management**: Safe start/stop operations restricted strictly to SecureShip-created containers.
7. **Bundled Sample Applications**:
   - `sample-python-app`: Clean, non-root Python 3.11 service designed to pass baseline zero-tolerance policy.
   - `vulnerable-python-app`: Outdated pinned packages with known Critical and High CVEs to demonstrate policy blocking.
8. **Deterministic Demo Fixtures**: Built-in, clearly labeled fixtures for offline demonstration when Docker or live vulnerability databases are unavailable.

---

## Prerequisites (Windows)

- **Python**: Version 3.11 or newer (Python 3.14 tested and verified).
- **Trivy CLI**: Installed via WinGet (`winget install AquaSecurity.Trivy`) or from GitHub Releases.
- **Docker Desktop**: Installed and running for building and executing real containers.

---

## Quickstart & Installation (Windows PowerShell)

### 1. Clone or Navigate to Directory
```powershell
cd "c:\Users\naveed sheriff j\Desktop\SecureShip"
```

### 2. Setup Virtual Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 4. Verify Installed Tools
```powershell
.\.venv\Scripts\python.exe -c "from config import TRIVY_BIN, DOCKER_BIN; print('Trivy:', TRIVY_BIN); print('Docker:', DOCKER_BIN)"
```

### 5. Start SecureShip Server
```powershell
.\.venv\Scripts\python.exe app.py
```
Open your browser to: **`http://127.0.0.1:5000`**

---

## Running Automated Tests

Run the complete test suite (25 tests covering policy engine, scanner, deployment gates, and API):
```powershell
.\.venv\Scripts\pytest.exe -v
```

All unit tests use mocked subprocesses and fixtures to guarantee deterministic, offline execution independent of network connectivity or live CVE databases.

---

## Demonstration Scenarios (Judges' Walkthrough)

### Scenario A: Security Gate Blocks Deployment (Policy Violation)

1. Navigate to **Scan Container** in the sidebar.
2. Select `vulnerable-python-app` from the Bundled Example dropdown.
3. Click **Build Docker Image from Source** (or click **Scenario B: Policy Block** demo button).
4. The scanner invokes Trivy and parses the findings.
5. Notice the **BLOCKED** status with Critical/High vulnerability warnings (e.g. CVE buffer overflows or denial-of-service flaws).
6. Click **Inspect Findings** to view package details and the exact advisory URLs.
7. Navigate to **Deployment Gate**, select this scan, and click **Execute Gated Deployment**.
8. **Outcome**: The backend independently rejects deployment at Gate 4. The container is never started, and the denial is recorded in the audit log.

### Scenario B: Security Gate Approves Deployment (Compliant Image)

1. Under **Scan Container**, select `sample-python-app` from the Bundled Example dropdown.
2. Click **Build Docker Image from Source** (or click **Scenario A: Clean Pass** demo button).
3. Click **Scan Image with Trivy**.
4. The policy engine evaluates findings: 0 Critical, 0 High. Gate status returns **APPROVED**.
5. Click **Proceed to Deploy**.
6. The 8-Point Gatekeeper verifies that:
   - Scan exists and is complete.
   - Image reference matches.
   - Scanned image ID matches current local image.
   - Scan satisfies active policy.
7. Click **Execute Gated Deployment**.
8. **Outcome**: The container starts bound strictly to `127.0.0.1:5010+`. Click the live link to view the running microservice response:
   ```json
   {
     "status": "online",
     "service": "SecureShip Validated Service",
     "message": "This container successfully passed all SecureShip security gate checks!"
   }
   ```
9. Click **Stop** in the Active Deployments table to cleanly terminate the container.

---

## REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Health check endpoint |
| `GET` | `/api/system/status` | Real tool versions (Docker, Trivy, SQLite) |
| `GET` | `/api/dashboard/stats` | Aggregated dashboard metrics |
| `GET` | `/api/dashboard/activity`| Recent audit events & deployments |
| `GET` | `/api/examples` | List available bundled sample apps |
| `POST` | `/api/build` | Build bundled Docker image (`app_key`, `tag`) |
| `POST` | `/api/scans` | Initiate Trivy scan (`image_ref`) |
| `POST` | `/api/scans/fixture` | Execute labeled demo fixture (`fixture_type`) |
| `GET` | `/api/scans` | Paginated scan records (`page`, `limit`, `status`) |
| `GET` | `/api/scans/<id>` | Full scan details with CVE findings |
| `GET` | `/api/scans/<id>/report` | Download raw JSON report (`download=true`) |
| `GET` | `/api/policies` | Active policy and revision history |
| `PUT` | `/api/policies` | Update policy thresholds (`change_reason` required) |
| `POST` | `/api/deployments` | Gated deployment (`scan_id`, `image_ref`) |
| `GET` | `/api/deployments` | List active and past deployments |
| `POST` | `/api/deployments/<id>/stop` | Stop SecureShip-managed container |
| `GET` | `/api/audit` | Read persistent audit trail |

---

## Security Model & Limitations

- **Localhost Threat Model**: Designed exclusively for local workstation DevSecOps evaluation (`127.0.0.1`). Not intended for multi-tenant public internet hosting without external authentication.
- **Fail-Closed Design**: Any scanner failure, parsing exception, or image mismatch causes the deployment gate to default to BLOCKED.
- **Trivy Database Updates**: Live Trivy scans require network access on first run to download vulnerability database metadata; thereafter, scans can execute against local image cache.
