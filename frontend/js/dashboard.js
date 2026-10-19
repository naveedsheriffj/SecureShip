/**
 * SecureShip Dashboard Module
 * Manages overview statistics, Chart.js visualizations, and recent scan feeds.
 */

let severityChartInstance = null;
let passFailChartInstance = null;

const Dashboard = {
  async init() {
    await this.loadStats();
    await this.loadActivity();
  },

  async loadStats() {
    try {
      const stats = await API.getDashboardStats();

      // Metric numbers
      document.getElementById('stat-total-scans').textContent = stats.total_scans;
      document.getElementById('stat-passed-scans').textContent = stats.passed_scans;
      document.getElementById('stat-failed-scans').textContent = stats.failed_scans;
      document.getElementById('stat-active-deployments').textContent = stats.active_deployments;
      document.getElementById('stat-critical-vulns').textContent = stats.severity_distribution.critical;
      document.getElementById('stat-high-vulns').textContent = stats.severity_distribution.high;

      // Active policy badge in header
      if (stats.active_policy) {
        const policyEl = document.getElementById('header-active-policy');
        if (policyEl) {
          policyEl.textContent = `Policy v${stats.active_policy.version}: ${stats.active_policy.name}`;
        }
      }

      this.renderCharts(stats);
      this.renderRecentScans(stats.recent_scans || []);
    } catch (err) {
      console.error('Failed to load dashboard stats:', err);
    }
  },

  async loadActivity() {
    try {
      const activity = await API.getDashboardActivity();
      this.renderActivityTable(activity.audit_events || []);
    } catch (err) {
      console.error('Failed to load dashboard activity:', err);
    }
  },

  renderCharts(stats) {
    const sev = stats.severity_distribution;
    const ctxSev = document.getElementById('severityChart');

    if (ctxSev && window.Chart) {
      if (severityChartInstance) {
        severityChartInstance.destroy();
      }

      const totalSev = sev.critical + sev.high + sev.medium + sev.low;

      if (totalSev === 0) {
        // Empty state chart
        severityChartInstance = new Chart(ctxSev, {
          type: 'doughnut',
          data: {
            labels: ['No Vulnerabilities Detected'],
            datasets: [{
              data: [1],
              backgroundColor: ['#1e293b'],
              borderWidth: 0
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { position: 'bottom', labels: { color: '#94a3b8' } }
            }
          }
        });
      } else {
        severityChartInstance = new Chart(ctxSev, {
          type: 'doughnut',
          data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
              data: [sev.critical, sev.high, sev.medium, sev.low],
              backgroundColor: ['#ff3366', '#ff7700', '#ffbb00', '#38bdf8'],
              borderWidth: 2,
              borderColor: '#131e31'
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: {
                position: 'bottom',
                labels: { color: '#cbd5e1', boxWidth: 12, padding: 15 }
              }
            },
            cutout: '68%'
          }
        });
      }
    }

    // Pass / Fail distribution
    const ctxPF = document.getElementById('passFailChart');
    if (ctxPF && window.Chart) {
      if (passFailChartInstance) {
        passFailChartInstance.destroy();
      }

      const totalScans = stats.passed_scans + stats.failed_scans;
      if (totalScans === 0) {
        passFailChartInstance = new Chart(ctxPF, {
          type: 'pie',
          data: {
            labels: ['No Scans Executed'],
            datasets: [{
              data: [1],
              backgroundColor: ['#1e293b'],
              borderWidth: 0
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { position: 'bottom', labels: { color: '#94a3b8' } }
            }
          }
        });
      } else {
        passFailChartInstance = new Chart(ctxPF, {
          type: 'pie',
          data: {
            labels: ['Approved (Passed)', 'Blocked (Failed)'],
            datasets: [{
              data: [stats.passed_scans, stats.failed_scans],
              backgroundColor: ['#10b981', '#ef4444'],
              borderWidth: 2,
              borderColor: '#131e31'
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: {
                position: 'bottom',
                labels: { color: '#cbd5e1', boxWidth: 12, padding: 15 }
              }
            }
          }
        });
      }
    }
  },

  renderRecentScans(scans) {
    const container = document.getElementById('dashboard-recent-scans');
    if (!container) return;

    if (!scans || scans.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <svg class="empty-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
          </svg>
          <div class="empty-title">No Scan Activity Yet</div>
          <div class="empty-desc">Scan a container image or build an example project to view live policy gate decisions.</div>
        </div>
      `;
      return;
    }

    let rowsHtml = '';
    scans.forEach(s => {
      const isApproved = s.policy_decision === 'APPROVED';
      const badgeClass = isApproved ? 'badge-approved' : 'badge-blocked';
      const timeStr = new Date(s.created_at).toLocaleString();

      rowsHtml += `
        <tr>
          <td><strong style="color:#fff;">${s.image_ref}</strong></td>
          <td><span class="badge ${badgeClass}">${s.policy_decision}</span></td>
          <td><span class="sev-pill sev-critical">${s.critical_count}</span></td>
          <td><span class="sev-pill sev-high">${s.high_count}</span></td>
          <td>${timeStr}</td>
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
              <th>Image Reference</th>
              <th>Gate Decision</th>
              <th>Critical</th>
              <th>High</th>
              <th>Timestamp</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            ${rowsHtml}
          </tbody>
        </table>
      </div>
    `;
  },

  renderActivityTable(events) {
    const container = document.getElementById('dashboard-recent-activity');
    if (!container) return;

    if (!events || events.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-title">No Audit Events Logged</div>
          <div class="empty-desc">Policy changes, scan executions, and deployments will appear here in chronological order.</div>
        </div>
      `;
      return;
    }

    let rows = '';
    events.slice(0, 8).forEach(e => {
      const outcomeBadge = e.outcome === 'SUCCESS' || e.outcome === 'APPROVED' || e.outcome === 'DEPLOYED'
        ? 'badge-approved'
        : 'badge-blocked';
      const time = new Date(e.created_at).toLocaleTimeString();

      rows += `
        <tr>
          <td><code style="color:var(--accent-cyan);">${e.action}</code></td>
          <td style="max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${e.details}</td>
          <td><span class="badge ${outcomeBadge}">${e.outcome}</span></td>
          <td style="color:var(--text-dim);">${time}</td>
        </tr>
      `;
    });

    container.innerHTML = `
      <div class="table-responsive">
        <table class="data-table">
          <thead>
            <tr>
              <th>Action</th>
              <th>Details</th>
              <th>Outcome</th>
              <th>Time</th>
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
