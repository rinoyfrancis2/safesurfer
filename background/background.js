// URL Guard Background Service Worker
// Coordinates between popup and content scripts

// Import libs for service worker context
try {
  importScripts('lib/typosquat.js', 'lib/virustotal.js');
} catch (e) {
  console.error('Failed to import scripts:', e);
}

// Settings state
let settings = {
  malwareScanEnabled: false,
  typosquatCheckEnabled: false
};

// Statistics
let stats = {
  urlsScanned: 0,
  threatsFound: 0
};

// Track if settings have been loaded
let settingsLoaded = false;
let settingsLoadPromise = null;

// Initialize settings from storage
async function initSettings() {
  if (settingsLoaded) return;

  const result = await chrome.storage.local.get(['urlguard_settings', 'urlguard_stats']);
  if (result.urlguard_settings) {
    settings = result.urlguard_settings;
  }
  if (result.urlguard_stats) {
    stats = result.urlguard_stats;
  }
  settingsLoaded = true;
}

// Ensure settings are loaded before use
async function ensureSettingsLoaded() {
  if (!settingsLoadPromise) {
    settingsLoadPromise = initSettings();
  }
  await settingsLoadPromise;
}

// Save settings to storage
async function saveSettings() {
  await chrome.storage.local.set({ urlguard_settings: settings });
}

// Save stats to storage
async function saveStats() {
  await chrome.storage.local.set({ urlguard_stats: stats });
}

// Analyze a single URL
async function analyzeUrl(url) {
  const results = {
    url: url,
    typosquat: null,
    malware: null,
    isSuspicious: false,
    riskScore: 0,
    reasons: []
  };

  // Typosquat check
  if (settings.typosquatCheckEnabled) {
    const typosquatResult = TyposquatDetector.analyzeUrl(url);
    results.typosquat = typosquatResult;

    if (typosquatResult.isSuspicious) {
      results.isSuspicious = true;
      results.riskScore = Math.max(results.riskScore, typosquatResult.riskScore);
      results.reasons.push(...typosquatResult.reasons);
    }
  }

  // Malware check (VirusTotal)
  if (settings.malwareScanEnabled) {
    const malwareResult = await VirusTotalAPI.checkUrl(url);
    results.malware = malwareResult;

    if (malwareResult.success && malwareResult.isMalicious) {
      results.isSuspicious = true;
      results.riskScore = Math.max(results.riskScore, 90);
      results.reasons.push(`VirusTotal: ${malwareResult.positives}/${malwareResult.total} detections`);
    }
  }

  // Update stats
  stats.urlsScanned++;
  if (results.isSuspicious) {
    stats.threatsFound++;
  }
  await saveStats();

  return results;
}

// Analyze multiple URLs
async function analyzeUrls(urls) {
  const results = [];

  for (const url of urls) {
    try {
      const result = await analyzeUrl(url);
      results.push(result);
    } catch (error) {
      results.push({
        url: url,
        error: error.message,
        isSuspicious: false
      });
    }
  }

  return results;
}

// Message handler
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Handle async operations
  (async () => {
    // Always ensure settings are loaded first
    await ensureSettingsLoaded();

    switch (message.type) {
      case 'GET_SETTINGS':
        sendResponse({
          settings: settings,
          stats: stats
        });
        break;

      case 'UPDATE_SETTINGS':
        settings = { ...settings, ...message.settings };
        await saveSettings();

        // Notify all tabs about settings change
        const tabs = await chrome.tabs.query({});
        for (const tab of tabs) {
          try {
            await chrome.tabs.sendMessage(tab.id, {
              type: 'SETTINGS_UPDATED',
              settings: settings
            });
          } catch {
            // Tab might not have content script
          }
        }

        sendResponse({ success: true, settings: settings });
        break;

      case 'ANALYZE_URL':
        const result = await analyzeUrl(message.url);
        sendResponse(result);
        break;

      case 'ANALYZE_URLS':
        const results = await analyzeUrls(message.urls);
        sendResponse(results);
        break;

      case 'GET_STATS':
        sendResponse(stats);
        break;

      case 'RESET_STATS':
        stats = { urlsScanned: 0, threatsFound: 0 };
        await saveStats();
        sendResponse(stats);
        break;

      case 'SET_API_KEY':
        await VirusTotalAPI.setApiKey(message.apiKey);
        sendResponse({ success: true });
        break;

      case 'HAS_API_KEY':
        const hasKey = await VirusTotalAPI.hasApiKey();
        sendResponse({ hasApiKey: hasKey });
        break;

      default:
        sendResponse({ error: 'Unknown message type' });
    }
  })();

  // Return true to indicate async response
  return true;
});

// Initialize on startup
ensureSettingsLoaded();

// Listen for installation
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('URL Guard installed successfully');
  }
});
