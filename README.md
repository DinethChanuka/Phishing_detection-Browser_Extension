# Email Security Guard Pro

## Installation Guide
1. Open Chrome and go to chrome://extensions/
2. Enable "Developer mode" (toggle in top right)
3. Click "Load unpacked" and select your folder
4. The extension will now work on Gmail and Outlook Web App

## Features

- ✅ AI-powered email threat detection with ML scoring
- ✅ Persistent risk labels that survive DOM refresh
- ✅ Sender reputation analysis
- ✅ Keyword-based threat detection
- ✅ Link risk analysis with typosquat detection
- ✅ Sender-Link mismatch detection
- ✅ Free email pretending to be company detection
- ✅ Urgency + Action combo detection
- ✅ Brand impersonation detection
- ✅ Too many links detection
- ✅ Suspicious TLD boost
- ✅ Domain whitelist/blacklist
- ✅ Sensitivity settings (Low/Medium/High)
- ✅ Real-time password field warnings
- ✅ Email summary panel

## New Rules Added (v3.4.0)

1. **Sender-Link Mismatch Rule** - Detects when email sender says PayPal but links go elsewhere
2. **Free Email Pretending Rule** - Flags bank-support@gmail.com style emails
3. **Urgency + Action Combo** - More accurate than keyword-only detection
4. **Typosquat Similarity** - Catches g00gle.com, paypa1.com variants
5. **Too Many Links** - Phishing emails often spam multiple links
6. **Brand Impersonation Boost** - Increases score when brand names appear in subject
7. **High-Risk TLD Boost** - Extra penalty for .xyz, .top, .click domains
8. **Login Path Detection** - Flags URLs containing /login, /verify paths

## Performance Notes

- Uses debounced scanning to avoid UI blocking
- Threat data cached for 30 minutes
- MutationObserver with reset on DOM changes ensures labels persist
- ProcessedRowIds reset on URL change and manual scan
- Duplicate label prevention

## Fixes in v3.4.0

- **Fixed disappearing labels** - Labels now persist after Gmail/Outlook DOM refresh
- **Fixed duplicate labels** - Prevention check before adding new labels
- **Improved mutation observer** - Debounced scanning with proper reset logic
- **Better URL change handling** - Reset tracking when navigating between emails