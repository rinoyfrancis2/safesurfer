// URL Guard Content Script
// Scans page for URLs and highlights suspicious ones

(function() {
  'use strict';

  // Settings (updated via messages from background)
  let settings = {
    malwareScanEnabled: false,
    typosquatCheckEnabled: false
  };

  // Track highlighted elements
  const highlightedElements = new Map();

  // Styles for highlighting
  const HIGHLIGHT_STYLES = {
    suspicious: {
      outline: '3px solid #ff4444',
      outlineOffset: '2px',
      backgroundColor: 'rgba(255, 68, 68, 0.1)'
    },
    warning: {
      outline: '2px solid #ffaa00',
      outlineOffset: '2px',
      backgroundColor: 'rgba(255, 170, 0, 0.1)'
    }
  };

  // Extract all URLs from the page
  function extractUrls() {
    const urls = new Set();
    const urlElements = new Map();

    // Get all anchor tags
    const anchors = document.querySelectorAll('a[href]');
    anchors.forEach(anchor => {
      const href = anchor.href;
      if (href && (href.startsWith('http://') || href.startsWith('https://'))) {
        // Skip same-origin URLs (usually safe)
        try {
          const urlObj = new URL(href);
          if (urlObj.hostname !== window.location.hostname) {
            urls.add(href);
            if (!urlElements.has(href)) {
              urlElements.set(href, []);
            }
            urlElements.get(href).push(anchor);
          }
        } catch {
          // Invalid URL, skip
        }
      }
    });

    return { urls: Array.from(urls), urlElements };
  }

  // Apply highlight to element
  function highlightElement(element, style, tooltipText) {
    // Store original styles
    if (!highlightedElements.has(element)) {
      highlightedElements.set(element, {
        outline: element.style.outline,
        outlineOffset: element.style.outlineOffset,
        backgroundColor: element.style.backgroundColor
      });
    }

    // Apply highlight styles
    Object.assign(element.style, style);

    // Add tooltip
    element.setAttribute('data-urlguard-warning', tooltipText);
    element.title = `[URL Guard Warning] ${tooltipText}`;
  }

  // Remove highlight from element
  function removeHighlight(element) {
    const original = highlightedElements.get(element);
    if (original) {
      element.style.outline = original.outline;
      element.style.outlineOffset = original.outlineOffset;
      element.style.backgroundColor = original.backgroundColor;
      element.removeAttribute('data-urlguard-warning');
      if (element.title.startsWith('[URL Guard Warning]')) {
        element.title = '';
      }
      highlightedElements.delete(element);
    }
  }

  // Clear all highlights
  function clearAllHighlights() {
    highlightedElements.forEach((_, element) => {
      removeHighlight(element);
    });
  }

  // Scan page for suspicious URLs
  async function scanPage() {
    // Check if any scanning is enabled
    if (!settings.malwareScanEnabled && !settings.typosquatCheckEnabled) {
      clearAllHighlights();
      return;
    }

    const { urls, urlElements } = extractUrls();

    if (urls.length === 0) {
      return;
    }

    // Send URLs to background for analysis
    try {
      const results = await chrome.runtime.sendMessage({
        type: 'ANALYZE_URLS',
        urls: urls
      });

      if (!results) return;

      // Process results and highlight suspicious URLs
      for (const result of results) {
        if (result.isSuspicious) {
          const elements = urlElements.get(result.url);
          if (elements) {
            const tooltipText = result.reasons.join('; ');
            const style = result.riskScore >= 70 ? HIGHLIGHT_STYLES.suspicious : HIGHLIGHT_STYLES.warning;

            elements.forEach(element => {
              highlightElement(element, style, tooltipText);
            });
          }
        }
      }
    } catch (error) {
      console.error('URL Guard: Error scanning URLs', error);
    }
  }

  // Initialize - get current settings
  async function init() {
    try {
      const response = await chrome.runtime.sendMessage({ type: 'GET_SETTINGS' });
      if (response && response.settings) {
        settings = response.settings;
        scanPage();
      }
    } catch (error) {
      console.error('URL Guard: Error initializing', error);
    }
  }

  // Listen for settings updates from background
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'SETTINGS_UPDATED') {
      settings = message.settings;

      // Clear highlights if both options disabled
      if (!settings.malwareScanEnabled && !settings.typosquatCheckEnabled) {
        clearAllHighlights();
      } else {
        // Re-scan with new settings
        scanPage();
      }

      sendResponse({ received: true });
    }
    return true;
  });

  // Observe DOM for new content (infinite scroll, AJAX, etc.)
  const observer = new MutationObserver((mutations) => {
    let hasNewLinks = false;

    for (const mutation of mutations) {
      if (mutation.addedNodes.length > 0) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType === Node.ELEMENT_NODE) {
            if (node.tagName === 'A' || node.querySelector?.('a')) {
              hasNewLinks = true;
              break;
            }
          }
        }
      }
      if (hasNewLinks) break;
    }

    if (hasNewLinks && (settings.malwareScanEnabled || settings.typosquatCheckEnabled)) {
      // Debounce scanning
      clearTimeout(window.urlGuardScanTimeout);
      window.urlGuardScanTimeout = setTimeout(scanPage, 500);
    }
  });

  // Start observing
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });

  // Initialize when ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
