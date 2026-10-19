/**
 * SecureShip Deployments Module
 * Gated container deployments, 8-gate preflight checklist, and container lifecycle.
 */

const Deployments = {
  async init() {
    this.setupListeners();
    await this.loadApprovedScansDropdown();
    await this.loadDeploymentsList();
  },

  setupListeners() {
    const deployForm = document.getElementById('deployment-form');
    if (deployForm) {
      deployForm.addEventListener('submit', (e) => {
        e.preventDefault();
        this.submitDeployment();
      });
    }

    const scanSelect = document.getElementById('deploy-scan-select');
    if (scanSelect) {
      scanSelect.addEventListener('change', () => this.handleScanSelection());
    }
  },

  async loadApprovedScansDropdown() {
    try {
      const data = await API.getScans(1, 50);
      const select = document.getElementById('deploy-scan-select');
      if (!select) return;

      select.innerHTML = '<option value="">-- Select Completed Scan --</option>';
      data.scans.forEach(s => {
        const isApproved = s.policy_decision === 'APPROVED';
        const label = `[${s.policy_decision}] ${s.image_ref} (Scan: ${s.id.substring(0, 16)}... | CVEs: ${s.total_vulnerabilities})`;
        select.innerHTML += `<option value="${s.id}" data-image="${s.image_ref}" data-decision="${s.policy_decision}">${label}</option>`;
      });
    } catch (err) {
      console.error('Failed to load scans for deployment:', err);
    }
  },

  handleScanSelection() {
    const select = document.getElementById('deploy-scan-select');
    const selected = select.options[select.selectedIndex];
    const imageInput = document.getElementById('deploy-image-input');
    const previewBox = document.getElementById('deploy-gate-preview');

    if (!selected || !selected.value) {
      previewBox.style.display = 'none';
      return;
    }

    const imageRef = selected.getAttribute('data-image');
    const decision = selected.getAttribute('data-decision');
    imageInput.value = imageRef;

    previewBox.style.display = 'block';
    const isApproved = decision === 'APPROVED';

    previewBox.innerHTML = `
      <div class="alert ${isApproved ? 'alert-info' : 'alert-danger'}">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <strong>Target Scan Selected:</strong> <code>${selected.value}</code> (${imageRef})<br>
            <span style="font-size:0.8rem;">Initial Gate Status: <strong>${decision}</strong></span>
          </div>
          <span class="badge ${isApproved ? 'badge-approved' : 'badge-blocked'}">${decision}</span>
        </div>
      </div>
    `;
  },

  async submitDeployment() {
    const select = document.getElementById('deploy-scan-select');
    const scanId = select.value || document.getElementById('deploy-scan-id-manual').value.trim();
    const imageRef = document.getElementById('deploy-image-input').value.trim();

    if (!scanId || !imageRef) {
      alert('Please select a scan and ensure image reference is provided.');
      return;
    }

    const deployBtn = document.getElementById('btn-execute-deploy');
    const resultBox = document.getElementById('deployment-result-box');

    deployBtn.disabled = true;
    resultBox.innerHTML = `<span style="color:var(--accent-cyan);">Evaluating 8-Gate Security Policy and verifying image integrity...</span>`;

    try {
      const res = await API.createDeployment(scanId, imageRef);

      if (res.status === 'DEPLOYED') {
        resultBox.innerHTML = `
          <div class="alert alert-success">
            <div>
              <div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;">
                <span class="badge badge-approved">PASSED ALL GATES</span>
                <span class="badge badge-deployed">CONTAINER ACTIVE</span>
                <strong>${res.image_ref}</strong>
              </div>
              <p>${res.reason}</p>
              <div style="margin-top:10px; font-size:0.85rem;">
                Container ID: <code>${res.container_id}</code> | Port: <code>${res.host_port}</code>
              </div>
              <div style="margin-top:12px;">
                <a href="${res.app_url}" target="_blank" rel="noopener noreferrer" class="btn btn-primary btn-sm">
                  Open Application: ${res.app_url} &#8599;
                </a>
              </div>
            </div>
          </div>
        `;
      } else {
        resultBox.innerHTML = `
          <div class="alert alert-danger">
            <div>
              <div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;">
                <span class="badge badge-blocked">DEPLOYMENT DENIED</span>
                <strong>${res.image_ref}</strong>
              </div>
              <p>${res.reason}</p>
              <div style="margin-top:8px; font-size:0.78rem; color:#fca5a5;">
                The platform securely blocked container instantiation to prevent unverified or vulnerable workloads from reaching localhost.
              </div>
            </div>
          </div>
        `;
      }

      await this.loadDeploymentsList();
      Dashboard.init();
    } catch (err) {
      resultBox.innerHTML = `
        <div class="alert alert-danger">
          <strong>Deployment Gatekeeper Blocked Action:</strong> ${err.message}
        </div>
      `;
    } finally {
      deployBtn.disabled = false;
    }
  },

  async loadDeploymentsList() {
    const container = document.getElementById('deployments-table-container');
    if (!container) return;

    try {
      const data = await API.getDeployments();
      if (!data.deployments || data.deployments.length === 0) {
        container.innerHTML = `
          <div class="empty-state">
            <div class="empty-title">No Container Deployments</div>
            <div class="empty-desc">Containers successfully deployed through the security gate will appear here with live links and stop actions.</div>
          </div>
        `;
        return;
      }

      let rows = '';
      data.deployments.forEach(d => {
        let statusBadge = '';
        if (d.status === 'DEPLOYED') statusBadge = '<span class="badge badge-deployed">DEPLOYED</span>';
        else if (d.status === 'STOPPED') statusBadge = '<span class="badge badge-stopped">STOPPED</span>';
        else statusBadge = `<span class="badge badge-blocked">${d.status}</span>`;

        const urlCol = d.app_url 
          ? `<a href="${d.app_url}" target="_blank" style="color:var(--accent-cyan);">${d.app_url} &#8599;</a>`
          : '-';

        const stopBtn = d.status === 'DEPLOYED'
          ? `<button class="btn btn-danger btn-sm" onclick="Deployments.stopContainer('${d.id}')">Stop</button>`
          : `<span style="color:var(--text-dim); font-size:0.75rem;">Inactive</span>`;

        rows += `
          <tr>
            <td><code>${d.id}</code></td>
            <td><strong style="color:#fff;">${d.image_ref}</strong></td>
            <td>${statusBadge}</td>
            <td>${d.container_id ? `<code>${d.container_id}</code>` : '-'}</td>
            <td>${urlCol}</td>
            <td style="max-width:220px; font-size:0.78rem; color:var(--text-muted);">${d.reason || '-'}</td>
            <td>${new Date(d.created_at).toLocaleTimeString()}</td>
            <td>${stopBtn}</td>
          </tr>
        `;
      });

      container.innerHTML = `
        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr>
                <th>Deployment ID</th>
                <th>Image Reference</th>
                <th>Status</th>
                <th>Container ID</th>
                <th>Local Endpoint</th>
                <th>Gate Decision / Reason</th>
                <th>Time</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              ${rows}
            </tbody>
          </table>
        </div>
      `;
    } catch (err) {
      container.innerHTML = `<div class="alert alert-danger">Error loading deployments: ${err.message}</div>`;
    }
  },

  async stopContainer(depId) {
    if (!confirm(`Are you sure you want to stop and remove deployment ${depId}?`)) return;

    try {
      const res = await API.stopDeployment(depId);
      alert(res.message);
      await this.loadDeploymentsList();
      Dashboard.init();
    } catch (err) {
      alert(`Failed to stop container: ${err.message}`);
    }
  }
};
