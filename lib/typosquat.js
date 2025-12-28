// Typosquatting Detection Module for URL Guard
// Detects suspicious URLs that mimic legitimate domains

const TyposquatDetector = {
  // Popular domains to check against
  knownDomains: [
    'google', 'facebook', 'amazon', 'apple', 'microsoft', 'netflix', 'paypal',
    'instagram', 'twitter', 'linkedin', 'youtube', 'whatsapp', 'telegram',
    'reddit', 'github', 'stackoverflow', 'dropbox', 'spotify', 'adobe',
    'salesforce', 'oracle', 'ibm', 'intel', 'nvidia', 'samsung', 'sony',
    'walmart', 'ebay', 'alibaba', 'zoom', 'slack', 'discord', 'twitch',
    'pinterest', 'snapchat', 'tiktok', 'uber', 'airbnb', 'booking',
    'expedia', 'chase', 'bankofamerica', 'wellsfargo', 'citibank', 'hsbc',
    'barclays', 'capitalone', 'americanexpress', 'visa', 'mastercard',
    'coinbase', 'binance', 'kraken', 'blockchain', 'metamask', 'opensea',
    'steam', 'epicgames', 'roblox', 'minecraft', 'playstation', 'xbox',
    'nintendo', 'att', 'verizon', 'tmobile', 'comcast', 'spectrum'
  ],

  // Homograph characters (lookalikes)
  homoglyphs: {
    'a': ['@', '4', 'а', 'ą', 'α'],
    'b': ['8', 'ь', 'β'],
    'c': ['(', 'с', 'ç', '¢'],
    'd': ['đ', 'ð'],
    'e': ['3', 'е', 'ё', 'є', 'ę'],
    'g': ['9', 'ğ'],
    'h': ['һ'],
    'i': ['1', 'l', '!', '|', 'і', 'ı'],
    'k': ['κ'],
    'l': ['1', 'i', '|', 'ł'],
    'm': ['rn', 'м'],
    'n': ['п', 'ń'],
    'o': ['0', 'о', 'ø', 'ο'],
    'p': ['р', 'ρ'],
    's': ['5', '$', 'ś', 'ş'],
    't': ['7', '+', 'ť'],
    'u': ['υ', 'ц', 'ù'],
    'v': ['ν', 'υ'],
    'w': ['vv', 'ω'],
    'x': ['х', '×'],
    'y': ['у', 'ý'],
    'z': ['2', 'ź', 'ż']
  },

  // Suspicious TLDs often used in phishing
  suspiciousTLDs: [
    'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'club', 'online', 'site',
    'website', 'space', 'fun', 'icu', 'buzz', 'monster', 'cam', 'uno'
  ],

  // Calculate Levenshtein distance between two strings
  levenshteinDistance(str1, str2) {
    const m = str1.length;
    const n = str2.length;
    const dp = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));

    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;

    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        if (str1[i - 1] === str2[j - 1]) {
          dp[i][j] = dp[i - 1][j - 1];
        } else {
          dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
        }
      }
    }

    return dp[m][n];
  },

  // Normalize string for comparison (replace homoglyphs)
  normalizeString(str) {
    let normalized = str.toLowerCase();

    // Replace common homoglyphs
    normalized = normalized
      .replace(/0/g, 'o')
      .replace(/1/g, 'l')
      .replace(/3/g, 'e')
      .replace(/4/g, 'a')
      .replace(/5/g, 's')
      .replace(/7/g, 't')
      .replace(/8/g, 'b')
      .replace(/9/g, 'g')
      .replace(/@/g, 'a')
      .replace(/\$/g, 's')
      .replace(/rn/g, 'm')
      .replace(/vv/g, 'w');

    return normalized;
  },

  // Extract domain from URL
  extractDomain(url) {
    try {
      let cleanUrl = url.trim();
      if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
        cleanUrl = 'https://' + cleanUrl;
      }
      const urlObj = new URL(cleanUrl);
      return urlObj.hostname.toLowerCase();
    } catch {
      return null;
    }
  },

  // Get base domain without TLD
  getBaseDomain(hostname) {
    const parts = hostname.split('.');
    if (parts.length >= 2) {
      // Handle common cases like co.uk, com.au
      const secondLast = parts[parts.length - 2];
      if (['co', 'com', 'org', 'net', 'gov', 'edu'].includes(secondLast) && parts.length >= 3) {
        return parts[parts.length - 3];
      }
      return secondLast;
    }
    return parts[0];
  },

  // Get TLD from hostname
  getTLD(hostname) {
    const parts = hostname.split('.');
    return parts[parts.length - 1];
  },

  // Check for subdomain tricks (e.g., paypal.com.evil.com)
  checkSubdomainTrick(hostname) {
    const parts = hostname.split('.');
    if (parts.length > 3) {
      // Check if any known domain appears as subdomain
      for (const known of this.knownDomains) {
        for (let i = 0; i < parts.length - 2; i++) {
          if (parts[i] === known || parts[i].includes(known)) {
            return {
              isSuspicious: true,
              reason: `Subdomain trick detected: "${known}" used as subdomain`,
              matchedDomain: known
            };
          }
        }
      }
    }
    return { isSuspicious: false };
  },

  // Main analysis function
  analyzeUrl(url) {
    const result = {
      url: url,
      isSuspicious: false,
      riskScore: 0,
      reasons: [],
      matchedDomain: null
    };

    const hostname = this.extractDomain(url);
    if (!hostname) {
      return result;
    }

    const baseDomain = this.getBaseDomain(hostname);
    const normalizedDomain = this.normalizeString(baseDomain);
    const tld = this.getTLD(hostname);

    // Check for subdomain tricks
    const subdomainCheck = this.checkSubdomainTrick(hostname);
    if (subdomainCheck.isSuspicious) {
      result.isSuspicious = true;
      result.riskScore += 80;
      result.reasons.push(subdomainCheck.reason);
      result.matchedDomain = subdomainCheck.matchedDomain;
    }

    // Check against known domains
    for (const known of this.knownDomains) {
      // Skip if exact match (legitimate domain)
      if (baseDomain === known) {
        continue;
      }

      // Check Levenshtein distance
      const distance = this.levenshteinDistance(normalizedDomain, known);
      if (distance > 0 && distance <= 2) {
        result.isSuspicious = true;
        result.riskScore += 70;
        result.reasons.push(`Similar to "${known}" (${distance} character difference)`);
        result.matchedDomain = known;
        break;
      }

      // Check if domain contains known brand
      if (baseDomain.includes(known) && baseDomain !== known) {
        result.isSuspicious = true;
        result.riskScore += 60;
        result.reasons.push(`Contains brand name "${known}"`);
        result.matchedDomain = known;
        break;
      }

      // Check normalized version
      if (normalizedDomain !== baseDomain) {
        const normalizedDistance = this.levenshteinDistance(normalizedDomain, known);
        if (normalizedDistance === 0) {
          result.isSuspicious = true;
          result.riskScore += 90;
          result.reasons.push(`Homograph attack: looks like "${known}"`);
          result.matchedDomain = known;
          break;
        }
      }
    }

    // Check for suspicious TLD with brand-like name
    if (this.suspiciousTLDs.includes(tld) && result.matchedDomain) {
      result.riskScore += 20;
      result.reasons.push(`Suspicious TLD: .${tld}`);
    }

    // Cap risk score at 100
    result.riskScore = Math.min(result.riskScore, 100);

    return result;
  }
};

// Make available globally
if (typeof window !== 'undefined') {
  window.TyposquatDetector = TyposquatDetector;
}
