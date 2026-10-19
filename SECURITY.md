# Security Policy: SecureShip

## 1. Overview & Threat Model

SecureShip is designed as a local **DevSecOps delivery gate** between container creation and deployment. It prevents vulnerable, unverified, or policy-violating container images from reaching local or staged execution environments.

### Localhost-Only Threat Model
SecureShip is an engineering workstation prototype intended strictly for `127.0.0.1` binding:
- **No public exposure**: The Flask server and deployed containers bind exclusively to `127.0.0.1`.
- **Single-operator model**: The platform assumes a trusted local developer session. It does not provide multi-tenant isolation or external RBAC in this prototype.
- **Fail-closed posture**: Scanner errors, corrupt reports, network timeouts, or missing scanner dependencies immediately cause gate decisions to reject deployment.

## 2. Defensive Controls Implemented

1. **Subprocess Isolation**: All Docker and Trivy interactions use Python `subprocess.run` with argument lists. `shell=True` is strictly prohibited to eliminate command injection.
2. **Strict Image Reference Validation**: Inputs are validated against a strict regex whitelist (`^[a-zA-Z0-9]+([._\-\/:][a-zA-Z0-9]+)*(@sha256:[a-fA-F0-9]{64})?$`), blocking all shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `>`, `<`, quotes, whitespace).
3. **8-Gate Preflight Verification**: Deployment requires a valid, completed scan record whose image digest/ID matches the current local image, satisfying both scan-time and active policy configurations.
4. **Restricted Container Execution**:
   - Deployed containers bind to `127.0.0.1` within restricted port ranges (5010–5050).
   - Resource limits (CPU: 0.5, Memory: 256MB) are enforced.
   - Sample images run with dedicated non-root users (`appuser`).
   - Privileged mode and host filesystem mounts are disallowed.
5. **Path Traversal Protection**: Raw report downloads sanitize file paths via `os.path.basename` and resolve strictly within `reports/`.
6. **Defensive HTTP Headers**: Content-Security-Policy (CSP), X-Content-Type-Options (`nosniff`), X-Frame-Options (`DENY`), and Referrer-Policy are enforced on every response.
7. **Parameterized Persistence**: All database interactions use parameterized SQLite queries to prevent SQL injection.
8. **Audit Trail**: Every scan, policy revision, deployment attempt, and stop operation is immutably logged with timestamps and outcomes.

## 3. Reporting a Vulnerability

If you identify a security issue in SecureShip:
1. Do not open public issues detailing exploitable attack vectors.
2. Submit a responsible disclosure report directly to the security team.
3. Include reproduction steps, environment details, and affected components.
