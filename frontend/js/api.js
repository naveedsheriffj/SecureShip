/**
 * SecureShip API Client
 * Centralized HTTP request handling with structured error reporting.
 */

const API = {
  async request(endpoint, options = {}) {
    const defaultHeaders = {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    };

    const config = {
      ...options,
      headers: {
        ...defaultHeaders,
        ...(options.headers || {})
      }
    };

    try {
      const response = await fetch(endpoint, config);
      const data = await response.json().catch(() => null);

      if (!response.ok) {
        const errorMsg = data?.error || `HTTP ${response.status}: ${response.statusText}`;
        throw new Error(errorMsg);
      }

      return data;
    } catch (err) {
      console.error(`API Error on ${endpoint}:`, err);
      throw err;
    }
  },

  // System & Health
  getHealth() {
    return this.request('/api/health');
  },

  getSystemStatus() {
    return this.request('/api/system/status');
  },

  // Dashboard
  getDashboardStats() {
    return this.request('/api/dashboard/stats');
  },

  getDashboardActivity() {
    return this.request('/api/dashboard/activity');
  },

  // Bundled Examples & Build
  getExamples() {
    return this.request('/api/examples');
  },

  buildImage(appKey, tag) {
    return this.request('/api/build', {
      method: 'POST',
      body: JSON.stringify({ app_key: appKey, tag })
    });
  },

  // Scans
  scanImage(imageRef) {
    return this.request('/api/scans', {
      method: 'POST',
      body: JSON.stringify({ image_ref: imageRef })
    });
  },

  runFixtureScan(imageRef, fixtureType) {
    return this.request('/api/scans/fixture', {
      method: 'POST',
      body: JSON.stringify({ image_ref: imageRef, fixture_type: fixtureType })
    });
  },

  getScans(page = 1, limit = 50, status = '') {
    const params = new URLSearchParams({ page, limit });
    if (status) params.append('status', status);
    return this.request(`/api/scans?${params.toString()}`);
  },

  getScan(scanId) {
    return this.request(`/api/scans/${encodeURIComponent(scanId)}`);
  },

  getReportDownloadUrl(scanId, download = false) {
    return `/api/scans/${encodeURIComponent(scanId)}/report?download=${download ? 'true' : 'false'}`;
  },

  // Policies
  getPolicies() {
    return this.request('/api/policies');
  },

  updatePolicy(policyData) {
    return this.request('/api/policies', {
      method: 'PUT',
      body: JSON.stringify(policyData)
    });
  },

  // Deployments
  createDeployment(scanId, imageRef) {
    return this.request('/api/deployments', {
      method: 'POST',
      body: JSON.stringify({ scan_id: scanId, image_ref: imageRef })
    });
  },

  getDeployments(limit = 50) {
    return this.request(`/api/deployments?limit=${limit}`);
  },

  stopDeployment(depId) {
    return this.request(`/api/deployments/${encodeURIComponent(depId)}/stop`, {
      method: 'POST'
    });
  },

  getAuditEvents(limit = 50) {
    return this.request(`/api/audit?limit=${limit}`);
  }
};
