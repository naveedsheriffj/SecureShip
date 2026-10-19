/**
 * SecureShip Policies Module
 * Handles policy configuration, threshold tuning, and immutable version history.
 */

const Policies = {
  async init() {
    this.setupListeners();
    await this.loadPolicies();
  },

  setupListeners() {
    const form = document.getElementById('policy-form');
    if (form) {
      form.addEventListener('submit', (e) => {
        e.preventDefault();
        this.savePolicy();
      });
    }
  },

  async loadPolicies() {
    try {
      const data = await API.getPolicies();
      this.populateForm(data.active_policy);
      this.renderHistory(data.history || []);
    } catch (err) {
      console.error('Failed to load policies:', err);
    }
  },

  populateForm(pol) {
    if (!pol) return;

    document.getElementById('pol-name').value = pol.name || '';
    document.getElementById('pol-block-critical').checked = Boolean(pol.block_critical);
    document.getElementById('pol-block-high').checked = Boolean(pol.block_high);
    document.getElementById('pol-max-critical').value = pol.max_critical ?? 0;
    document.getElementById('pol-max-high').value = pol.max_high ?? 0;
    document.getElementById('pol-max-medium').value = pol.max_medium ?? 999;
    document.getElementById('pol-max-low').value = pol.max_low ?? 999;
    document.getElementById('pol-reject-unknown').checked = Boolean(pol.reject_unknown);
    document.getElementById('pol-reject-error').checked = Boolean(pol.reject_on_error);
    document.getElementById('pol-reason').value = '';

    const versionBanner = document.getElementById('active-policy-version-banner');
    if (versionBanner) {
      versionBanner.innerHTML = `Active Policy Revision: <strong>v${pol.version}</strong> (Created ${new Date(pol.created_at).toLocaleString()})`;
    }
  },

  async savePolicy() {
    const reasonInput = document.getElementById('pol-reason');
    const reason = reasonInput.value.trim();

    if (!reason) {
      alert('Audit compliance requirement: Please enter a reason explaining this policy change.');
      reasonInput.focus();
      return;
    }

    const payload = {
      name: document.getElementById('pol-name').value.trim() || 'Custom Policy Revision',
      block_critical: document.getElementById('pol-block-critical').checked,
      block_high: document.getElementById('pol-block-high').checked,
      max_critical: parseInt(document.getElementById('pol-max-critical').value, 10),
      max_high: parseInt(document.getElementById('pol-max-high').value, 10),
      max_medium: parseInt(document.getElementById('pol-max-medium').value, 10),
      max_low: parseInt(document.getElementById('pol-max-low').value, 10),
      reject_unknown: document.getElementById('pol-reject-unknown').checked,
      reject_on_error: document.getElementById('pol-reject-error').checked,
      change_reason: reason
    };

    const statusEl = document.getElementById('policy-status-msg');
    const saveBtn = document.getElementById('btn-save-policy');

    saveBtn.disabled = true;
    statusEl.innerHTML = `<span style="color:var(--accent-cyan);">Persisting new policy revision and logging audit event...</span>`;

    try {
      const updated = await API.updatePolicy(payload);
      statusEl.innerHTML = `
        <div class="alert alert-success">
          <strong>Policy Updated:</strong> Revision <strong>v${updated.version}</strong> is now the active baseline. Subsequent deployment gate decisions will apply this rule set immediately.
        </div>
      `;
      reasonInput.value = '';
      await this.loadPolicies();
      Dashboard.init();
    } catch (err) {
      statusEl.innerHTML = `
        <div class="alert alert-danger">
          <strong>Policy Update Failed:</strong> ${err.message}
        </div>
      `;
    } finally {
      saveBtn.disabled = false;
    }
  },

  renderHistory(history) {
    const container = document.getElementById('policy-history-table');
    if (!container) return;

    if (!history || history.length === 0) {
      container.innerHTML = `<div class="empty-state"><div class="empty-title">No Policy History</div></div>`;
      return;
    }

    let rows = '';
    history.forEach(p => {
      const statusBadge = p.is_active 
        ? `<span class="badge badge-approved">ACTIVE</span>` 
        : `<span class="badge badge-stopped">ARCHIVED</span>`;
      const dateStr = new Date(p.created_at).toLocaleString();

      rows += `
        <tr>
          <td><strong>v${p.version}</strong></td>
          <td style="color:#fff;">${p.name}</td>
          <td>${statusBadge}</td>
          <td>Crit: ${p.block_critical ? 'Block' : `Max ${p.max_critical}`} | High: ${p.block_high ? 'Block' : `Max ${p.max_high}`}</td>
          <td style="max-width:240px; color:var(--text-muted); font-size:0.8rem;">${p.change_reason || '-'}</td>
          <td style="color:var(--text-dim);">${dateStr}</td>
        </tr>
      `;
    });

    container.innerHTML = `
      <div class="table-responsive">
        <table class="data-table">
          <thead>
            <tr>
              <th>Ver</th>
              <th>Policy Name</th>
              <th>Status</th>
              <th>Gate Thresholds</th>
              <th>Change Reason</th>
              <th>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            ${rows}
          </tbody>
        </table>
      </div>
    `;
  }
};
