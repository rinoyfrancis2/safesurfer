// URL Guard Popup Script
// Handles UI interactions and communicates with background script

document.addEventListener('DOMContentLoaded', () => {
  // Elements
  const loginView = document.getElementById('login-view');
  const dashboardView = document.getElementById('dashboard-view');
  const loginForm = document.getElementById('login-form');
  const loginError = document.getElementById('login-error');
  const userEmail = document.getElementById('user-email');
  const logoutBtn = document.getElementById('logout-btn');

  const apiKeyInput = document.getElementById('api-key');
  const saveApiKeyBtn = document.getElementById('save-api-key');
  const apiStatus = document.getElementById('api-status');

  const malwareToggle = document.getElementById('malware-toggle');
  const typosquatToggle = document.getElementById('typosquat-toggle');
  const malwareItem = document.getElementById('malware-item');
  const malwareDesc = document.getElementById('malware-desc');

  const urlsScannedEl = document.getElementById('urls-scanned');
  const threatsFoundEl = document.getElementById('threats-found');

  // Track API key status
  let hasApiKey = false;

  // Check authentication status and load settings
  async function init() {
    const isLoggedIn = await Auth.isLoggedIn();

    if (isLoggedIn) {
      showDashboard();
    } else {
      showLogin();
    }
  }

  // Show login view
  function showLogin() {
    loginView.classList.remove('hidden');
    dashboardView.classList.add('hidden');
  }

  // Show dashboard view
  async function showDashboard() {
    loginView.classList.add('hidden');
    dashboardView.classList.remove('hidden');

    // Load user info
    const user = await Auth.getUser();
    if (user) {
      userEmail.textContent = user.email;
    }

    // Load settings and stats
    await loadSettings();
    await checkApiKey();
  }

  // Load settings from background
  async function loadSettings() {
    try {
      const response = await chrome.runtime.sendMessage({ type: 'GET_SETTINGS' });

      if (response) {
        // Update toggles
        malwareToggle.checked = response.settings.malwareScanEnabled || false;
        typosquatToggle.checked = response.settings.typosquatCheckEnabled || false;

        // Update stats
        urlsScannedEl.textContent = response.stats.urlsScanned || 0;
        threatsFoundEl.textContent = response.stats.threatsFound || 0;
      }
    } catch (error) {
      console.error('Error loading settings:', error);
    }
  }

  // Check if API key is set
  async function checkApiKey() {
    try {
      const response = await chrome.runtime.sendMessage({ type: 'HAS_API_KEY' });

      if (response && response.hasApiKey) {
        hasApiKey = true;
        apiStatus.textContent = 'Configured';
        apiStatus.classList.add('active');
        apiKeyInput.placeholder = '••••••••••••••••';

        // Enable malware toggle
        malwareToggle.disabled = false;
        malwareItem.classList.remove('disabled');
        malwareDesc.textContent = 'Check URLs with VirusTotal';
      } else {
        hasApiKey = false;
        apiStatus.textContent = 'Not set';
        apiStatus.classList.remove('active');

        // Disable malware toggle (UI only, don't update settings)
        malwareToggle.disabled = true;
        malwareItem.classList.add('disabled');
        malwareDesc.textContent = 'Requires API key';

        // Only update settings if malware was enabled
        if (malwareToggle.checked) {
          malwareToggle.checked = false;
          await updateSettings({ malwareScanEnabled: false });
        }
      }
    } catch (error) {
      console.error('Error checking API key:', error);
    }
  }

  // Handle login form submission
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    loginError.textContent = '';

    const result = await Auth.login(email, password);

    if (result.success) {
      showDashboard();
    } else {
      loginError.textContent = result.error;
    }
  });

  // Handle logout
  logoutBtn.addEventListener('click', async () => {
    await Auth.logout();
    showLogin();
  });

  // Handle API key save
  saveApiKeyBtn.addEventListener('click', async () => {
    const apiKey = apiKeyInput.value.trim();

    if (!apiKey) {
      return;
    }

    try {
      await chrome.runtime.sendMessage({
        type: 'SET_API_KEY',
        apiKey: apiKey
      });

      apiKeyInput.value = '';
      await checkApiKey();
    } catch (error) {
      console.error('Error saving API key:', error);
    }
  });

  // Handle malware toggle
  malwareToggle.addEventListener('change', async () => {
    // Only allow enabling if API key is set
    if (malwareToggle.checked && !hasApiKey) {
      malwareToggle.checked = false;
      return;
    }

    await updateSettings({
      malwareScanEnabled: malwareToggle.checked
    });
  });

  // Handle typosquat toggle
  typosquatToggle.addEventListener('change', async () => {
    await updateSettings({
      typosquatCheckEnabled: typosquatToggle.checked
    });
  });

  // Update settings in background
  async function updateSettings(newSettings) {
    try {
      await chrome.runtime.sendMessage({
        type: 'UPDATE_SETTINGS',
        settings: newSettings
      });
    } catch (error) {
      console.error('Error updating settings:', error);
    }
  }

  // Initialize
  init();
});
