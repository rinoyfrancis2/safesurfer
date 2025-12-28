// Mock Authentication Module for SafeSurfer
// Uses localStorage for demo purposes - replace with real auth in production

const AUTH_KEY = 'safesurfer_auth';
const USER_KEY = 'safesurfer_user';

const Auth = {
  // Login with email and password
  async login(email, password) {
    // Mock validation - in production, validate against real backend
    if (!email || !password) {
      return { success: false, error: 'Email and password are required' };
    }

    if (!this.isValidEmail(email)) {
      return { success: false, error: 'Invalid email format' };
    }

    if (password.length < 4) {
      return { success: false, error: 'Password must be at least 4 characters' };
    }

    // Mock successful login
    const user = {
      email: email,
      loginTime: Date.now()
    };

    await chrome.storage.local.set({
      [AUTH_KEY]: true,
      [USER_KEY]: user
    });

    return { success: true, user: user };
  },

  // Logout current user
  async logout() {
    await chrome.storage.local.remove([AUTH_KEY, USER_KEY]);
    return { success: true };
  },

  // Check if user is logged in
  async isLoggedIn() {
    const result = await chrome.storage.local.get([AUTH_KEY]);
    return result[AUTH_KEY] === true;
  },

  // Get current user info
  async getUser() {
    const result = await chrome.storage.local.get([USER_KEY]);
    return result[USER_KEY] || null;
  },

  // Validate email format
  isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }
};

// Make available globally
if (typeof window !== 'undefined') {
  window.Auth = Auth;
}
