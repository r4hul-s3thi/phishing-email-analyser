# ⚠️ PhishGuard — Phishing Email Analyser

A real, fully client-side phishing email analysis tool. Paste any suspicious email and get an instant threat score with a detailed breakdown of phishing indicators.

**🔗 Live Tool → [r4hul-s3thi.github.io/phishing-email-analyser](https://r4hul-s3thi.github.io/phishing-email-analyser)**

---

## What It Detects

| Indicator | Weight |
|---|---|
| SPF Fail / Softfail | 20 pts |
| DKIM Signature Invalid | 18 pts |
| DMARC Fail | 18 pts |
| Spoofed / Lookalike Domain | 25 pts |
| Urgency / Scare Tactics | 15 pts |
| Suspicious / Shortened URLs | 20 pts |
| Credential / Info Harvesting | 20 pts |
| Reply-To Mismatch | 12 pts |
| Generic / Impersonal Greeting | 8 pts |
| Dangerous Attachment Mentioned | 15 pts |
| HTML / Unicode Obfuscation | 10 pts |

## Threat Score

| Score | Verdict |
|---|---|
| 70–100 | 🚨 Likely Phishing |
| 40–69 | ⚠️ Suspicious |
| 15–39 | 🔎 Low Risk |
| 0–14 | 🛡️ Looks Clean |

## How to Use

1. Paste raw email headers (optional but recommended)
2. Paste the full email body
3. Optionally enter the sender address
4. Click **Analyse Email**

> Runs 100% in your browser — no data is sent anywhere.

---

## Deploy on GitHub Pages

1. Push this repo to GitHub
2. Go to **Settings → Pages**
3. Set source to `main` branch, `/ (root)`
4. Your tool is live at `https://<username>.github.io/phishing-email-analyser`

---

Built by [r4hul-s3thi](https://github.com/r4hul-s3thi)
