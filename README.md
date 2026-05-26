# 🔍 jQuery / jQuery-UI CVE Scanner & Exploiter

[![Security](https://img.shields.io/badge/Security-Scanner-red)](https://github.com)
[![CVEs](https://img.shields.io/badge/Covered-7%20CVEs-orange)](https://github.com)
[![JavaScript](https://img.shields.io/badge/JavaScript-ES6-yellow)](https://github.com)

## 📋 Overview

This is a **complete, self-contained security assessment tool** that detects and exploits known vulnerabilities in jQuery and jQuery-UI libraries. It runs entirely in your browser console — no installation required.

### 🎯 CVEs Covered

| CVE | Component | Severity | Description |
|-----|-----------|----------|-------------|
| **CVE-2015-9251** | jQuery < 3.0.0 | 🟡 MEDIUM | CORS script execution |
| **CVE-2019-11358** | jQuery < 3.4.0 | 🟡 MEDIUM | Prototype Pollution |
| **CVE-2020-11022** | jQuery < 3.5.0 | 🔴 HIGH | htmlPrefilter XSS |
| **CVE-2020-11023** | jQuery < 3.5.0 | 🔴 HIGH | .html()/.append() XSS |
| **CVE-2021-41184** | jQuery UI < 1.13.0 | 🔴 HIGH | .position() XSS |
| **CVE-2021-41182/83** | jQuery UI < 1.13.0 | 🟡 MEDIUM | Datepicker XSS |
| **CVE-2022-31160** | jQuery UI < 1.13.0 | 🟡 MEDIUM | Checkboxradio XSS |

---

## 🚀 How to Run

### Step 1: Open the Target Website
Navigate to the website you want to test (must have authorization).

### Step 2: Open Browser Console

| Browser | Shortcut |
|---------|----------|
| **Chrome / Edge** | `F12` or `Ctrl + Shift + J` (Windows) / `Cmd + Option + J` (Mac) |
| **Firefox** | `F12` or `Ctrl + Shift + K` (Windows) / `Cmd + Option + K` (Mac) |
| **Safari** | `Cmd + Option + C` (Enable DevTools first) |

### Step 3: Copy and Paste the Script

```javascript
// Copy the ENTIRE script from jquery-scanner.js
// Paste it into the console
// Press Enter
Step 4: Wait for Results (5-10 seconds)

The scanner will:

    ✅ Detect jQuery / jQuery-UI versions

    ✅ Identify vulnerable CVEs

    ✅ Attempt exploitation

    ✅ Display a visual panel on the page

    ✅ Output a complete JSON report to the console

📊 What You'll See
Console Output Example
text

ℹ️ ═══════════════════════════════════════════════════════════════════
ℹ️ PHASE 1: LIBRARY DETECTION
ℹ️ ═══════════════════════════════════════════════════════════════════
✅ jQuery 1.10.1 detected
🔴 CVE-2020-11022: jQuery 1.10.1 vulnerable to XSS via htmlPrefilter (HIGH)
🔴 CVE-2020-11023: jQuery 1.10.1 vulnerable to XSS via option elements (HIGH)

ℹ️ ═══════════════════════════════════════════════════════════════════
ℹ️ PHASE 3: EXPLOITATION
ℹ️ ═══════════════════════════════════════════════════════════════════
💉 CVE-2020-11022 - XSS payload injected via htmlPrefilter
💉 CVE-2020-11023 - XSS payload injected via .append()
💉 CVE-2019-11358 - Prototype pollution successful

📊 RISK ASSESSMENT: HIGH (Score: 85)

🔴 VULNERABILITIES FOUND: 4
   • CVE-2020-11022 - jQuery 1.10.1 vulnerable to XSS (HIGH)
   • CVE-2020-11023 - jQuery 1.10.1 vulnerable to XSS (HIGH)

💉 EXPLOITS ATTEMPTED: 3
   • CVE-2020-11022 - XSS payload injected
   • CVE-2020-11023 - XSS payload injected

Visual Panel

A floating panel will appear on the bottom-left corner of the page showing:

    jQuery / jQuery-UI versions detected

    Number of CVEs found

    Exploitation status

    Risk level

Stored Results

All results are saved to window.jQueryScannerResults:
javascript

// Access the complete report
console.log(window.jQueryScannerResults);

// View only vulnerabilities
console.log(window.jQueryScannerResults.vulnerabilities);

// View exploited CVEs
console.log(window.jQueryScannerResults.exploited);

🛠️ Configuration Options

You can modify these settings at the top of the script:
javascript

const CONFIG = {
    verbose: true,        // Show detailed console output
    autoExploit: true,    // Automatically attempt exploitation
    testXSS: true,        // Test XSS payloads
    outputToConsole: true,// Print results to console
    createVisualPanel: true // Show floating panel on page
};

📁 Output Data Structure
json

{
  "scanTime": "2026-05-25T10:30:00.000Z",
  "url": "https://target.com",
  "libraries": {
    "jquery": { "detected": true, "version": "1.10.1", "vulnerable": true },
    "jqueryUI": { "detected": true, "version": "1.10.4", "vulnerable": true }
  },
  "vulnerabilities": [
    {
      "name": "jQuery htmlPrefilter XSS",
      "cve": "CVE-2020-11022",
      "severity": "HIGH",
      "poc": "$('<img src=x onerror=alert(1)>').appendTo('body');"
    }
  ],
  "exploited": [
    {
      "name": "CVE-2020-11022",
      "details": "XSS payload injected via htmlPrefilter"
    }
  ]
}

⚠️ Important Notes
✅ Do

    Run only on websites you own or have written permission to test

    Use for legitimate security assessments

    Document findings for remediation

❌ Don't

    Run on websites without authorization

    Use for malicious purposes

    Share victim data from scans

🔧 Troubleshooting
Issue	Solution
$ is not defined	jQuery is not loaded on this page
$.ui is undefined	jQuery UI is not loaded
No output	Check console filter (enable Info, Warnings, Errors)
Script not running	Refresh page and try again
CORS errors	Expected on cross-origin requests (some tests may fail)


MIT License — Free for security testing on authorized targets.
🙏 Acknowledgments

    jQuery Security Team

    Snyk Vulnerability Database

    CVE MITRE Corporation

🔗 Quick Links

    Copy Script

    Report Issues

    CVE Database

🚀 Ready to use? Copy the script and paste it into your browser console!

