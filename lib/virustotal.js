// VirusTotal API Integration for URL Guard
// Checks URLs against VirusTotal's malware database

const VirusTotalAPI = {
  // API configuration
  API_BASE: 'https://www.virustotal.com/vtapi/v2',

  // Cache for API responses (reduces API calls)
  cache: new Map(),
  CACHE_TTL: 3600000, // 1 hour in milliseconds

  // Rate limiting (4 requests per minute for free tier)
  requestQueue: [],
  lastRequestTime: 0,
  MIN_REQUEST_INTERVAL: 15000, // 15 seconds between requests

  // Get API key from storage
  async getApiKey() {
    const result = await chrome.storage.local.get(['virustotal_api_key']);
    return result.virustotal_api_key || null;
  },

  // Save API key to storage
  async setApiKey(apiKey) {
    await chrome.storage.local.set({ virustotal_api_key: apiKey });
  },

  // Check if we have an API key configured
  async hasApiKey() {
    const key = await this.getApiKey();
    return !!key;
  },

  // Get cached result if valid
  getCached(url) {
    const cached = this.cache.get(url);
    if (cached && Date.now() - cached.timestamp < this.CACHE_TTL) {
      return cached.data;
    }
    this.cache.delete(url);
    return null;
  },

  // Save to cache
  setCache(url, data) {
    this.cache.set(url, {
      data: data,
      timestamp: Date.now()
    });
  },

  // Wait for rate limit
  async waitForRateLimit() {
    const now = Date.now();
    const timeSinceLastRequest = now - this.lastRequestTime;

    if (timeSinceLastRequest < this.MIN_REQUEST_INTERVAL) {
      const waitTime = this.MIN_REQUEST_INTERVAL - timeSinceLastRequest;
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }

    this.lastRequestTime = Date.now();
  },

  // Check URL against VirusTotal
  async checkUrl(url) {
    // Check cache first
    const cached = this.getCached(url);
    if (cached) {
      return { ...cached, fromCache: true };
    }

    const apiKey = await this.getApiKey();
    if (!apiKey) {
      return {
        success: false,
        error: 'API key not configured',
        requiresApiKey: true
      };
    }

    try {
      // Wait for rate limit
      await this.waitForRateLimit();

      // Get URL report
      const response = await fetch(
        `${this.API_BASE}/url/report?apikey=${apiKey}&resource=${encodeURIComponent(url)}`,
        {
          method: 'GET',
          headers: {
            'Accept': 'application/json'
          }
        }
      );

      if (response.status === 204) {
        // URL not in database
        return {
          success: true,
          found: false,
          message: 'URL not found in VirusTotal database'
        };
      }

      if (response.status === 403) {
        return {
          success: false,
          error: 'Invalid API key'
        };
      }

      if (response.status === 429) {
        return {
          success: false,
          error: 'Rate limit exceeded. Please wait before scanning more URLs.'
        };
      }

      if (!response.ok) {
        return {
          success: false,
          error: `API error: ${response.status}`
        };
      }

      const data = await response.json();

      const result = {
        success: true,
        found: data.response_code === 1,
        positives: data.positives || 0,
        total: data.total || 0,
        scanDate: data.scan_date,
        permalink: data.permalink,
        isMalicious: (data.positives || 0) > 0,
        riskLevel: this.calculateRiskLevel(data.positives, data.total)
      };

      // Cache the result
      this.setCache(url, result);

      return result;

    } catch (error) {
      return {
        success: false,
        error: error.message || 'Network error'
      };
    }
  },

  // Calculate risk level based on detection ratio
  calculateRiskLevel(positives, total) {
    if (!positives || positives === 0) return 'clean';

    const ratio = positives / total;

    if (ratio >= 0.5) return 'high';
    if (ratio >= 0.2) return 'medium';
    if (ratio >= 0.05) return 'low';

    return 'suspicious';
  },

  // Submit URL for scanning (if not in database)
  async submitUrl(url) {
    const apiKey = await this.getApiKey();
    if (!apiKey) {
      return {
        success: false,
        error: 'API key not configured'
      };
    }

    try {
      await this.waitForRateLimit();

      const formData = new FormData();
      formData.append('apikey', apiKey);
      formData.append('url', url);

      const response = await fetch(`${this.API_BASE}/url/scan`, {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        return {
          success: false,
          error: `Scan submission failed: ${response.status}`
        };
      }

      const data = await response.json();

      return {
        success: true,
        scanId: data.scan_id,
        permalink: data.permalink,
        message: 'URL submitted for scanning'
      };

    } catch (error) {
      return {
        success: false,
        error: error.message || 'Network error'
      };
    }
  },

  // Clear cache
  clearCache() {
    this.cache.clear();
  }
};

// Make available globally
if (typeof window !== 'undefined') {
  window.VirusTotalAPI = VirusTotalAPI;
}
