<div align="center">

<img src="https://img.shields.io/badge/PhishGuard-Phishing%20Email%20Analyser-6366f1?style=for-the-badge&logo=shield&logoColor=white"/>

<br/>
<br/>

[![Live Demo](https://img.shields.io/badge/🔗%20Live%20Demo-r4hul--s3thi.github.io-06b6d4?style=flat-square)](https://r4hul-s3thi.github.io/phishing-email-analyser)
[![License](https://img.shields.io/badge/License-MIT-10b981?style=flat-square)](LICENSE)
[![Client Side](https://img.shields.io/badge/Client%20Side-100%25%20Private-f59e0b?style=flat-square)](#)
[![No Backend](https://img.shields.io/badge/Backend-None%20Required-ef4444?style=flat-square)](#)

<br/>

**PhishGuard** is a real, fully client-side phishing email analysis tool.  
Paste any suspicious email and get an instant threat score with a detailed breakdown of 11 phishing indicators — all running in your browser. No data ever leaves your device.

<br/>

[**→ Try it Live**](https://r4hul-s3thi.github.io/phishing-email-analyser)

</div>

---

## ✨ Features

- **11 phishing indicators** checked instantly — SPF, DKIM, DMARC, spoofed domains, urgency tactics, suspicious URLs, credential harvesting, and more
- **Weighted threat scoring** — 0 to 100 score with animated ring display
- **4-tier verdict system** — from 🛡️ Clean to 🚨 Likely Phishing
- **Full indicator breakdown** — see exactly what triggered and what passed
- **100% private** — runs entirely in your browser, zero network requests
- **No install, no signup, no backend** — just open and use
- **Responsive design** — works on desktop and mobile

---

## 🔍 What It Detects

| Indicator | Weight | Severity |
|---|---|---|
| Spoofed / Lookalike Domain | 25 pts | 🔴 High |
| SPF Fail / Softfail | 20 pts | 🔴 High |
| Suspicious / Shortened URLs | 20 pts | 🔴 High |
| Credential / Info Harvesting | 20 pts | 🔴 High |
| DKIM Signature Invalid | 18 pts | 🔴 High |
| DMARC Fail | 18 pts | 🔴 High |
| Urgency / Scare Tactics | 15 pts | 🟡 Medium |
| Dangerous Attachment Mentioned | 15 pts | 🟡 Medium |
| Reply-To Mismatch | 12 pts | 🟡 Medium |
| HTML / Unicode Obfuscation | 10 pts | 🟡 Medium |
| Generic / Impersonal Greeting | 8 pts | 🟢 Low |

---

## 📊 Threat Score Tiers

| Score | Verdict | Meaning |
|---|---|---|
| 70 – 100 | 🚨 Likely Phishing | Multiple strong indicators. Do not interact. |
| 40 – 69 | ⚠️ Suspicious | Several warning signs. Verify before acting. |
| 15 – 39 | 🔎 Low Risk | Minor indicators. Likely safe but stay alert. |
| 0 – 14 | 🛡️ Looks Clean | No significant indicators detected. |

---

## 🚀 How to Use

1. Go to **[r4hul-s3thi.github.io/phishing-email-analyser](https://r4hul-s3thi.github.io/phishing-email-analyser)**
2. Paste the **email body** (required)
3. Optionally paste **raw email headers** for deeper analysis
4. Optionally enter the **sender address**
5. Click **Analyse Email** — results appear instantly

### Getting Raw Headers

| Client | Steps |
|---|---|
| Gmail | Open email → ⋮ (three dots) → **Show original** |
| Outlook | File → **Properties** → Internet headers |
| Apple Mail | View → **Message** → **All Headers** |
| Thunderbird | View → **Message Source** |

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Fonts | Inter + JetBrains Mono (Google Fonts) |
| Hosting | GitHub Pages |
| Backend | None — 100% client-side |

---

## 📁 Project Structure

```
phishing-email-analyser/
├── index.html      # Main UI
├── style.css       # Dark cybersecurity theme
├── analyser.js     # All 11 detection checks + scoring logic
└── README.md       # This file
```

---

## 🌐 Deploy Your Own

This project is a single-page static site — deploy anywhere in seconds.

### GitHub Pages (Recommended)

```bash
git clone https://github.com/r4hul-s3thi/phishing-email-analyser.git
cd phishing-email-analyser
# Push to your own repo, then:
# Settings → Pages → Branch: main → / (root) → Save
```

Your tool will be live at:
```
https://<your-username>.github.io/phishing-email-analyser
```

### Other Platforms

| Platform | Command |
|---|---|
| Netlify | Drag & drop the folder into [netlify.com/drop](https://app.netlify.com/drop) |
| Vercel | `vercel --prod` in the project folder |
| Cloudflare Pages | Connect repo → Framework: None → Build: skip |

---

## 📄 License

MIT — free to use, modify, and distribute.

---

<div align="center">

Built by [r4hul-s3thi](https://github.com/r4hul-s3thi)

⭐ Star this repo if you found it useful!

</div>
