/**
 * SecureShip Scans Module
 * Manages scan triggering, interactive progress states, findings inspection, and history.
 */

let currentScanDetail = null;
let activeSeverityFilter = 'ALL';
let currentSearchTerm = '';

const Scans = {
  async init() {
    this.setupListeners();
    await this.loadExamples();
    await this.loadScanHistory();
  },

  setupListeners() {
    const scanForm = document.getElementById('scan-form');
    if (scanForm) {
      scanForm.addEventListener('submit', (e) => {
        e.preventDefault();
        this.startScan();
      });
    }

    const buildBtn = document.getElementById('btn-build-sample');
    if (buildBtn) {
      buildBtn.addEventListener('click', () => this.buildSampleApp());
    }

    // Fixture buttons for demonstration
    const btnCleanFixture = document.getElementById('btn-fixture-clean');
    if (btnCleanFixture) {
      btnCleanFixture.addEventListener('click', () => this.runFixture('clean'));
    }

    const btnVulnFixture = document.getElementById('btn-fixture-vuln');
    if (btnVulnFixture) {
      btnVulnFixture.addEventListener('click', () => this.runFixture('vulnerable'));
    }
  },

  async loadExamples() {
    try {
      const data = await API.getExamples();
      const select = document.getElementById('bundled-app-select');
      if (!select) return;

      select.innerHTML = '<option value="">-- Choose a Bundled Example --</option>';
      data.examples.forEach(ex => {
        select.innerHTML += `<option value="${ex.key}">${ex.description}</option>`;
      });
    } catch (err) {
      console.error('Failed to load bundled examples:', err);
    }
  },

  async buildSampleApp() {
    const select = document.getElementById('bundled-app-select');
    const appKey = select.value;
    const tagInput = document.getElementById('scan-image-input');

    if (!appKey) {
      alert('Please select a bundled sample application from the dropdown.');
      return;
    }

    const tag = tagInput.value.trim() || `secureship-${appKey}:1.0`;
    tagInput.value = tag;

    const buildStatusEl = document.getElementById('build-status-msg');
    const buildBtn = document.getElementById('btn-build-sample');

    buildBtn.disabled = true;
    buildStatusEl.innerHTML = `<span style="color:var(--accent-cyan);">Building '${tag}' from '${appKey}'... This may take a minute.</span>`;

    try {
      const res = await API.buildImage(appKey, tag);
      buildStatusEl.innerHTML = `
        <div class="alert alert-success" style="margin-top:10px;">
          <strong>Build Succeeded!</strong> Image <code>${res.image_ref}</code> is ready locally in Docker (${res.duration_seconds}s). Image ID: <code>${res.image_id ? res.image_id.substring(0, 19) : 'cached'}</code>
        </div>
      `;
    } catch (err) {
      buildStatusEl.innerHTML = `
        <div class="alert alert-danger" style="margin-top:10px;">
          <strong>Build Failed:</strong> ${err.message}
        </div>
      `;
    } finally {
      buildBtn.disabled = false;
    }
  },

  updateStepper(stage) {
    const stages = ['validate', 'scan', 'policy', 'save'];
    stages.forEach((s, idx) => {
      const el = document.getElementById(`step-${s}`);
      if (!el) return;

      const currentIdx = stages.indexOf(stage);
      if (idx < currentIdx) {
        el.className = 'step-item complete';
      } else if (idx === currentIdx) {
        el.className = 'step-item active';
      } else {
        el.className = 'step-item';
      }
    });
  },

  async startScan() {
    const input = document.getElementById('scan-image-input');
    const imageRef = input.value.trim();
    if (!imageRef) {
      alert('Please enter a container image reference.');
      return;
    }

    const scanBtn = document.getElementById('btn-start-scan');
    const stepperBox = document.getElementById('scan-stepper-box');
    const resultBox = document.getElementById('scan-quick-result');

    scanBtn.disabled = true;
    stepperBox.style.display = 'block';
    resultBox.innerHTML = '';

    try {
      this.updateStepper('validate');
      await new Promise(r => setTimeout(r, 400));

      this.updateStepper('scan');
      const scanPromise = API.scanImage(imageRef);

      const result = await scanPromise;
      this.updateStepper('policy');
      await new Promise(r => setTimeout(r, 400));

      this.updateStepper('save');
      await new Promise(r => setTimeout(r, 300));

      // Display quick result alert and button to view findings
      const isApproved = result.policy_decision === 'APPROVED';
      const alertClass = isApproved ? 'alert-success' : 'alert-danger';
      const badgeClass = isApproved ? 'badge-approved' : 'badge-blocked';

      resultBox.innerHTML = `
        <div class="alert ${alertClass}">
          <div>
            <div style="display:flex; align-items:center; gap:10px; margin-bottom:6px;">
              <strong>Scan Finished:</strong>
              <span class="badge ${badgeClass}">${result.policy_decision}</span>
              <span style="font-size:0.8rem; color:var(--text-dim);">Scan ID: ${result.id}</span>
            </div>
            <p>${result.decision_reason}</p>
            <div style="margin-top:12px; display:flex; gap:10px;">
              <button class="btn btn-primary btn-sm" onclick="App.viewScanDetail('${result.id}')">View Full Report & Findings</button>
              ${isApproved ? `<button class="btn btn-secondary btn-sm" onclick="App.navigateToDeploy('${result.id}', '${result.image_ref}')">Proceed to Deploy</button>` : ''}
            </div>
          </div>
        </div>
      `;

      // Refresh stats and history
      Dashboard.init();
      this.loadScanHistory();
    } catch (err) {
      resultBox.innerHTML = `
        <div class="alert alert-danger">
          <strong>Scan Execution Failed:</strong> ${err.message}
        </div>
      `;
    } finally {
      scanBtn.disabled = false;
    }
  },

  async runFixture(fixtureType) {
    const imageRef = fixtureType === 'clean' ? 'secureship-clean-demo:1.0' : 'secureship-vulnerable-demo:1.0';
    const scanBtn = document.getElementById('btn-start-scan');
    const resultBox = document.getElementById('scan-quick-result');

    resultBox.innerHTML = `<span style="color:var(--accent-cyan);">Generating authentic test fixture (${fixtureType})...</span>`;
    try {
      const result = await API.runFixtureScan(imageRef, fixtureType);
      const isApproved = result.policy_decision === 'APPROVED';
      const alertClass = isApproved ? 'alert-success' : 'alert-danger';

      resultBox.innerHTML = `
        <div class="alert ${alertClass}">
          <div>
            <div style="display:flex; align-items:center; gap:10px; margin-bottom:6px;">
              <span class="badge badge-fixture">DEMO FIXTURE</span>
              <span class="badge ${isApproved ? 'badge-approved' : 'badge-blocked'}">${result.policy_decision}</span>
              <span>${result.image_ref}</span>
            </div>
            <p>${result.decision_reason}</p>
            <div style="margin-top:10px;">
              <button class="btn btn-primary btn-sm" onclick="App.viewScanDetail('${result.id}')">Inspect Findings</button>
            </div>
          </div>
        </div>
      `;
      Dashboard.init();
      this.loadScanHistory();
    } catch (err) {
      resultBox.innerHTML = `<div class="alert alert-danger">Failed to run fixture: ${err.message}</div>`;
    }
  },

  async viewDetail(scanId) {
    const container = document.getElementById('scan-detail-content');
    if (!container) return;

    container.innerHTML = `<div class="empty-state"><div class="empty-title">Loading scan ${scanId}...</div></div>`;

    try {
      const scan = await API.getScan(scanId);
      currentScanDetail = scan;
      this.renderScanDetail(scan);
    } catch (err) {
      container.innerHTML = `<div class="alert alert-danger">Failed to load scan details: ${err.message}</div>`;
    }
  },

  renderScanDetail(scan) {
    const container = document.getElementById('scan-detail-content');
    if (!container) return;

    const isApproved = scan.policy_decision === 'APPROVED';
    const badgeClass = isApproved ? 'badge-approved' : 'badge-blocked';
    const reportUrl = API.getReportDownloadUrl(scan.id, false);
    const downloadUrl = API.getReportDownloadUrl(scan.id, true);

    container.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:20px; flex-wrap:wrap; gap:14px;">
        <div>
          <div style="display:flex; align-items:center; gap:12px; margin-bottom:6px;">
            <h2 style="font-size:1.3rem; color:#fff;">${scan.image_ref}</h2>
            <span class="badge ${badgeClass}" style="font-size:0.85rem; padding:4px 10px;">${scan.policy_decision}</span>
            ${scan.is_fixture ? '<span class="badge badge-fixture">TEST FIXTURE</span>' : ''}
          </div>
          <div style="color:var(--text-muted); font-size:0.82rem; display:flex; gap:16px; flex-wrap:wrap;">
            <span>Scan ID: <code>${scan.id}</code></span>
            <span>Date: ${new Date(scan.created_at).toLocaleString()}</span>
            <span>Scanner: ${scan.scanner_name} (${scan.scanner_version || 'standard'})</span>
            <span>Policy: v${scan.policy_version}</span>
          </div>
        </div>
        <div style="display:flex; gap:10px;">
          <a href="${downloadUrl}" target="_blank" class="btn btn-secondary btn-sm">
            <svg style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
            </svg>
            Download JSON Report
          </a>
          ${isApproved ? `<button class="btn btn-primary btn-sm" onclick="App.navigateToDeploy('${scan.id}', '${scan.image_ref}')">Proceed to Deploy</button>` : ''}
        </div>
      </div>

      <div class="panel" style="margin-bottom:20px; border-left:4px solid ${isApproved ? 'var(--status-pass)' : 'var(--status-fail)'};">
        <div class="panel-body" style="padding:16px 20px;">
          <h4 style="font-size:0.9rem; color:#fff; margin-bottom:6px;">Security Gate Evaluation:</h4>
          <p style="font-size:0.85rem; color:var(--text-muted);">${scan.decision_reason}</p>
        </div>
      </div>

      <!-- Severity Summary Cards -->
      <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(130px, 1fr)); gap:12px; margin-bottom:24px;">
        <div class="metric-card accent-red" style="padding:14px;">
          <div class="metric-label" style="font-size:0.7rem;">Critical</div>
          <div class="metric-value" style="font-size:1.5rem; color:var(--sev-critical);">${scan.critical_count}</div>
        </div>
        <div class="metric-card accent-amber" style="padding:14px;">
          <div class="metric-label" style="font-size:0.7rem;">High</div>
          <div class="metric-value" style="font-size:1.5rem; color:var(--sev-high);">${scan.high_count}</div>
        </div>
        <div class="metric-card" style="padding:14px;">
          <div class="metric-label" style="font-size:0.7rem;">Medium</div>
          <div class="metric-value" style="font-size:1.5rem; color:var(--sev-medium);">${scan.medium_count}</div>
        </div>
        <div class="metric-card accent-blue" style="padding:14px;">
          <div class="metric-label" style="font-size:0.7rem;">Low</div>
          <div class="metric-value" style="font-size:1.5rem; color:var(--sev-low);">${scan.low_count}</div>
        </div>
        <div class="metric-card" style="padding:14px;">
          <div class="metric-label" style="font-size:0.7rem;">Total Vulnerabilities</div>
          <div class="metric-value" style="font-size:1.5rem;">${scan.total_vulnerabilities}</div>
        </div>
      </div>

      <!-- Filter and Search Bar -->
      <div class="filter-bar">
        <button class="filter-pill active" onclick="Scans.setSeverityFilter('ALL', this)">All (${scan.findings ? scan.findings.length : 0})</button>
        <button class="filter-pill" onclick="Scans.setSeverityFilter('CRITICAL', this)">Critical (${scan.critical_count})</button>
        <button class="filter-pill" onclick="Scans.setSeverityFilter('HIGH', this)">High (${scan.high_count})</button>
        <button class="filter-pill" onclick="Scans.setSeverityFilter('MEDIUM', this)">Medium (${scan.medium_count})</button>
        <button class="filter-pill" onclick="Scans.setSeverityFilter('LOW', this)">Low (${scan.low_count})</button>

        <div class="search-wrapper">
          <svg class="search-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
          </svg>
          <input type="text" class="search-input" placeholder="Search CVE ID or Package..." oninput="Scans.handleSearch(this.value)">
        </div>
      </div>

      <!-- Findings Table -->
      <div id="findings-table-container">
        ${this.renderFindingsTable(scan.findings || [])}
      </div>
    `;
  },

  setSeverityFilter(sev, element) {
    activeSeverityFilter = sev;
    document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
    element.classList.add('active');
    this.applyFilters();
  },

  handleSearch(term) {
    currentSearchTerm = term.toLowerCase().trim();
    this.applyFilters();
  },

  applyFilters() {
    if (!currentScanDetail || !currentScanDetail.findings) return;

    let filtered = currentScanDetail.findings;

    if (activeSeverityFilter !== 'ALL') {
      filtered = filtered.filter(f => f.severity.toUpperCase() === activeSeverityFilter);
    }

    if (currentSearchTerm) {
      filtered = filtered.filter(f => 
        (f.vulnerability_id && f.vulnerability_id.toLowerCase().includes(currentSearchTerm)) ||
        (f.pkg_name && f.pkg_name.toLowerCase().includes(currentSearchTerm)) ||
        (f.title && f.title.toLowerCase().includes(currentSearchTerm))
      );
    }

    const container = document.getElementById('findings-table-container');
    if (container) {
      container.innerHTML = this.renderFindingsTable(filtered);
    }
  },

  renderFindingsTable(findings) {
    if (!findings || findings.length === 0) {
      return `
        <div class="empty-state">
          <div class="empty-title">No Vulnerabilities Match Filters</div>
          <div class="empty-desc">No findings matched the selected severity or search term.</div>
        </div>
      `;
    }

    let rows = '';
    findings.forEach(f => {
      const sevClass = `sev-${f.severity.toLowerCase()}`;
      const urlLink = f.primary_url 
        ? `<a href="${f.primary_url}" target="_blank" rel="noopener noreferrer" style="color:var(--accent-cyan); text-decoration:none;">${f.vulnerability_id} &#8599;</a>`
        : `<code>${f.vulnerability_id}</code>`;

      rows += `
        <tr>
          <td><span class="sev-pill ${sevClass}">${f.severity}</span></td>
          <td><strong>${urlLink}</strong></td>
          <td><code>${f.pkg_name}</code></td>
          <td><code style="color:var(--text-muted);">${f.installed_version}</code></td>
          <td><code style="color:var(--status-pass);">${f.fixed_version || 'None'}</code></td>
          <td style="max-width:300px; font-size:0.8rem; color:var(--text-dim);">${f.title || f.description || '-'}</td>
        </tr>
      `;
    });

    return `
      <div class="table-responsive">
        <table class="data-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Vulnerability ID</th>
              <th>Package</th>
              <th>Installed</th>
              <th>Fixed In</th>
              <th>Advisory / Title</th>
            </tr>
          </thead>
          <tbody>
            ${rows}
          </tbody>
        </table>
      </div>
    `;
  },

  async loadScanHistory(page = 1) {
    const container = document.getElementById('scan-history-table-container');
    if (!container) return;

    try {
      const data = await API.getScans(page, 20);
      if (!data.scans || data.scans.length === 0) {
        container.innerHTML = `
          <div class="empty-state">
            <div class="empty-title">Scan History Empty</div>
            <div class="empty-desc">Scan records and policy decisions will be saved here automatically.</div>
          </div>
        `;
        return;
      }

      let rows = '';
      data.scans.forEach(s => {
        const isApproved = s.policy_decision === 'APPROVED';
        const badgeClass = isApproved ? 'badge-approved' : 'badge-blocked';
        const dateStr = new Date(s.created_at).toLocaleString();

        rows += `
          <tr>
            <td><code>${s.id}</code></td>
            <td><strong style="color:#fff;">${s.image_ref}</strong></td>
            <td><span class="badge ${badgeClass}">${s.policy_decision}</span></td>
            <td><span class="sev-pill sev-critical">${s.critical_count}</span></td>
            <td><span class="sev-pill sev-high">${s.high_count}</span></td>
            <td>${s.medium_count} / ${s.low_count}</td>
            <td>v${s.policy_version}</td>
            <td style="color:var(--text-dim);">${dateStr}</td>
            <td>
              <button class="btn btn-secondary btn-sm" onclick="App.viewScanDetail('${s.id}')">Inspect</button>
            </td>
          </tr>
        `;
      });

      container.innerHTML = `
        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr>
                <th>Scan ID</th>
                <th>Image Reference</th>
                <th>Policy Decision</th>
                <th>Critical</th>
                <th>High</th>
                <th>Med/Low</th>
                <th>Policy</th>
                <th>Timestamp</th>
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
      container.innerHTML = `<div class="alert alert-danger">Error loading scan history: ${err.message}</div>`;
    }
  }
};
