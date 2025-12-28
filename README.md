# SafeSurfer

A cybersecurity browser extension that protects you from malicious URLs and typosquatting attacks.

![Chrome](https://img.shields.io/badge/Chrome-Supported-green)
![Firefox](https://img.shields.io/badge/Firefox-Supported-orange)
![Brave](https://img.shields.io/badge/Brave-Supported-red)

## Features

### Typosquatting Detection (No API Required)
Detects fake lookalike URLs that try to impersonate legitimate websites:
- **Levenshtein distance matching** - Catches domains like `gooogle.com`, `paypai.com`
- **Homograph attack detection** - Identifies character substitutions like `g00gle.com` (zeros instead of 'o')
- **Subdomain tricks** - Flags patterns like `paypal.com.evil.com`
- **Suspicious TLD detection** - Warns about brand-like domains with sketchy TLDs (`.xyz`, `.tk`)

### Malware Scan (VirusTotal API)
Checks URLs against 70+ security vendors via VirusTotal:
- Real-time URL scanning
- Caches results to reduce API calls
- Rate limiting for free tier compatibility

### Visual Alerts
- Automatically scans all external links on any webpage
- Highlights dangerous URLs with a **red border**
- Shows warning tooltips with threat details

## Installation

### Chrome / Brave
1. Download or clone this repository
2. Open `chrome://extensions` (or `brave://extensions`)
3. Enable **Developer mode** (toggle in top-right)
4. Click **Load unpacked**
5. Select the `safesurfer` folder

### Firefox
1. Rename `manifest-firefox.json` to `manifest.json` (backup the original)
2. Open `about:debugging#/runtime/this-firefox`
3. Click **Load Temporary Add-on**
4. Select any file in the `safesurfer` folder

## Usage

1. Click the SafeSurfer extension icon
2. Login with any email/password (mock auth for demo)
3. **Typosquat Detection** - Enable to detect fake URLs (works immediately, no API needed)
4. **Malware Scan** - Requires VirusTotal API key:
   - Get a free key at [virustotal.com](https://www.virustotal.com/gui/join-us)
   - Enter the key in the extension popup
5. Browse any website - suspicious links will be highlighted in red

## Project Structure

```
safesurfer/
├── manifest.json              # Chrome/Brave (Manifest V3)
├── manifest-firefox.json      # Firefox (Manifest V2)
├── popup/
│   ├── popup.html             # Extension popup UI
│   ├── popup.css              # Minimal dark theme
│   └── popup.js               # Popup logic
├── background/
│   └── background.js          # Service worker
├── content/
│   └── content.js             # Page scanner & highlighter
├── lib/
│   ├── auth.js                # Mock authentication
│   ├── typosquat.js           # Typosquatting detector
│   └── virustotal.js          # VirusTotal API wrapper
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

## API Limits

**VirusTotal Free Tier:**
- 4 requests per minute
- 500 requests per day

The extension handles rate limiting automatically and caches results to minimize API usage.

## Tech Stack

- **JavaScript** (Vanilla, no build step)
- **Manifest V3** (Chrome/Brave) with V2 fallback (Firefox)
- **Chrome Storage API** for settings persistence
- **VirusTotal API** for malware detection

## Security Notes

- API keys are stored locally in browser storage
- Mock authentication is for demo purposes only
- No data is sent to external servers except VirusTotal (for malware scans)

## License

MIT License - feel free to use, modify, and distribute.

## Contributing

Pull requests are welcome! For major changes, please open an issue first.
