/**
 * SecureShip Application Orchestrator
 * Manages view routing, navigation state, and real-time tool availability checks.
 */

const App = {
  activeSection: 'overview',

  async init() {
    this.setupNavigation();
    await this.checkSystemStatus();

    // Initialize modules
    await Dashboard.init();
    await Scans.init();
    await Policies.init();
    await Deployments.init();

    // Set initial view
    this.showSection('overview');

    // Periodic health refresh every 30 seconds
    setInterval(() => this.checkSystemStatus(), 30000);
  },

  setupNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', (e) => {
        e.preventDefault();
        const section = item.getAttribute('data-section');
        if (section) {
          this.showSection(section);
        }
      });
    });
  },

  showSection(sectionId) {
    this.activeSection = sectionId;

    // Update nav items
    document.querySelectorAll('.nav-item').forEach(item => {
      if (item.getAttribute('data-section') === sectionId) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });

    // Update visible view section
    document.querySelectorAll('.view-section').forEach(sec => {
      sec.classList.remove('active');
    });

    const target = document.getElementById(`section-${sectionId}`);
    if (target) {
      target.classList.add('active');
    }

    // Refresh views on activation
    if (sectionId === 'overview') {
      Dashboard.init();
    } else if (sectionId === 'history') {
      Scans.loadScanHistory();
    } else if (sectionId === 'deployments') {
      Deployments.loadApprovedScansDropdown();
      Deployments.loadDeploymentsList();
    } else if (sectionId === 'policies') {
      Policies.loadPolicies();
    } else if (sectionId === 'settings') {
      this.checkSystemStatus();
    }
  },

  viewScanDetail(scanId) {
    this.showSection('scan-detail');
    Scans.viewDetail(scanId);
  },

  navigateToDeploy(scanId, imageRef) {
    this.showSection('deployments');
    const select = document.getElementById('deploy-scan-select');
    const imageInput = document.getElementById('deploy-image-input');
    if (select) {
      select.value = scanId;
      Deployments.handleScanSelection();
    }
    if (imageInput && imageRef) {
      imageInput.value = imageRef;
    }
  },

  async checkSystemStatus() {
    try {
      const data = await API.getSystemStatus();
      const prereqs = data.prerequisites;

      // Update header status indicators
      const dockerStatusDot = document.getElementById('status-docker-dot');
      const trivyStatusDot = document.getElementById('status-trivy-dot');

      if (dockerStatusDot) {
        dockerStatusDot.style.backgroundColor = prereqs.docker.available ? 'var(--status-pass)' : 'var(--status-fail)';
        dockerStatusDot.title = `Docker: ${prereqs.docker.version}`;
      }

      if (trivyStatusDot) {
        trivyStatusDot.style.backgroundColor = prereqs.trivy.available ? 'var(--status-pass)' : 'var(--status-fail)';
        trivyStatusDot.title = `Trivy: ${prereqs.trivy.version}`;
      }

      // Settings page details
      const settingsContent = document.getElementById('system-health-content');
      if (settingsContent) {
        settingsContent.innerHTML = `
          <div class="panel" style="margin-bottom:20px;">
            <div class="panel-header">
              <div class="panel-title">System Infrastructure & Tool Availability</div>
            </div>
            <div class="panel-body">
              <div style="display:flex; flex-direction:column; gap:16px;">
                <div style="display:flex; justify-content:space-between; align-items:center; padding:12px; background:rgba(0,0,0,0.2); border-radius:6px;">
                  <div>
                    <strong style="color:#fff;">Trivy Vulnerability Scanner</strong><br>
                    <span style="font-size:0.8rem; color:var(--text-muted);">${prereqs.trivy.version}</span>
                  </div>
                  <div>
                    ${prereqs.trivy.available 
                      ? '<span class="badge badge-approved">AVAILABLE</span>' 
                      : '<span class="badge badge-blocked">NOT DETECTED</span>'}
                  </div>
                </div>

                <div style="display:flex; justify-content:space-between; align-items:center; padding:12px; background:rgba(0,0,0,0.2); border-radius:6px;">
                  <div>
                    <strong style="color:#fff;">Docker Engine / Desktop</strong><br>
                    <span style="font-size:0.8rem; color:var(--text-muted);">${prereqs.docker.version}</span>
                  </div>
                  <div>
                    ${prereqs.docker.available 
                      ? '<span class="badge badge-approved">DAEMON RUNNING</span>' 
                      : '<span class="badge badge-blocked">DAEMON STOPPED</span>'}
                  </div>
                </div>

                <div style="display:flex; justify-content:space-between; align-items:center; padding:12px; background:rgba(0,0,0,0.2); border-radius:6px;">
                  <div>
                    <strong style="color:#fff;">SQLite Security Audit Database</strong><br>
                    <span style="font-size:0.8rem; color:var(--text-muted);">Path: ${prereqs.database.path}</span>
                  </div>
                  <div>
                    <span class="badge badge-approved">CONNECTED</span>
                  </div>
                </div>

                <div style="display:flex; justify-content:space-between; align-items:center; padding:12px; background:rgba(0,0,0,0.2); border-radius:6px;">
                  <div>
                    <strong style="color:#fff;">Active Security Gate Baseline</strong><br>
                    <span style="font-size:0.8rem; color:var(--text-muted);">Policy v${data.policy.version}: ${data.policy.name}</span>
                  </div>
                  <div>
                    <span class="badge badge-approved">ENFORCED</span>
                  </div>
                </div>
              </div>

              ${(!prereqs.docker.available || !prereqs.trivy.available) ? `
                <div class="alert alert-warning" style="margin-top:20px;">
                  <div>
                    <strong>Prerequisites Guidance:</strong><br>
                    ${!prereqs.docker.available ? `• <strong>Docker:</strong> ${prereqs.docker.guidance}<br>` : ''}
                    ${!prereqs.trivy.available ? `• <strong>Trivy:</strong> ${prereqs.trivy.guidance}<br>` : ''}
                    <div style="margin-top:6px; font-size:0.78rem;">
                      Note: You can still test the Policy Engine and Gatekeeper verification using the labeled <strong>Demo Fixtures</strong> on the Scan page without live Docker containers.
                    </div>
                  </div>
                </div>
              ` : ''}
            </div>
          </div>
        `;
      }
    } catch (err) {
      console.error('Error checking system health:', err);
    }
  }
};

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => App.init());
