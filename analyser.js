// ─── Phishing Indicators ────────────────────────────────────────────────────

const INDICATORS = [
  {
    id: 'spf_fail',
    name: 'SPF Fail / Softfail',
    weight: 20,
    severity: 'high',
    icon: '📛',
    desc: 'SPF record check failed — sender domain is not authorised to send this email.',
    check: ({ headers }) => /received-spf:\s*(fail|softfail)/i.test(headers)
  },
  {
    id: 'dkim_fail',
    name: 'DKIM Signature Invalid',
    weight: 18,
    severity: 'high',
    icon: '🔑',
    desc: 'DKIM signature is missing or failed — email integrity cannot be verified.',
    check: ({ headers }) =>
      /dkim=fail/i.test(headers) ||
      (headers.length > 10 && !/dkim-signature/i.test(headers))
  },
  {
    id: 'dmarc_fail',
    name: 'DMARC Fail',
    weight: 18,
    severity: 'high',
    icon: '🚫',
    desc: 'DMARC policy check failed — this email may be spoofed.',
    check: ({ headers }) => /dmarc=fail/i.test(headers)
  },
  {
    id: 'spoofed_sender',
    name: 'Spoofed / Lookalike Domain',
    weight: 25,
    severity: 'high',
    icon: '🎭',
    desc: 'Sender domain mimics a trusted brand using typosquatting or lookalike tricks.',
    check: ({ sender, body }) => {
      const combined = (sender + ' ' + body).toLowerCase();
      const patterns = [
        /paypa[l1]-/i, /g[o0]{2}gle/i, /micros[o0]ft/i, /app[l1]e-/i,
        /github-[a-z]/i, /amazon-[a-z]/i, /netf[l1]ix/i, /[a-z]+-secure\./i,
        /[a-z]+-login\./i, /[a-z]+-verify\./i, /[a-z]+-support\./i,
        /[a-z]+-account\./i, /[a-z]+-update\./i
      ];
      return patterns.some(p => p.test(combined));
    }
  },
  {
    id: 'urgency',
    name: 'Urgency / Scare Tactics',
    weight: 15,
    severity: 'medium',
    icon: '⏰',
    desc: 'Email uses urgency, fear, or pressure to force immediate action.',
    check: ({ body }) => {
      const triggers = [
        'immediately', 'urgent', 'act now', 'account suspended', 'verify now',
        'limited time', 'expires', 'unauthorized access', 'suspicious activity',
        'your account will be', 'action required', 'confirm your identity',
        'click here to restore', 'failure to', 'within 24 hours', 'within 48 hours'
      ];
      const lower = body.toLowerCase();
      return triggers.filter(t => lower.includes(t)).length >= 2;
    }
  },
  {
    id: 'suspicious_links',
    name: 'Suspicious / Shortened URLs',
    weight: 20,
    severity: 'high',
    icon: '🔗',
    desc: 'Email contains shortened, obfuscated, or suspicious URLs.',
    check: ({ body }) => {
      const shorteners = /\b(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|rb\.gy|cutt\.ly|is\.gd|buff\.ly)\b/i;
      const suspiciousUrl = /https?:\/\/[^\s]*(-login|-verify|-secure|-account|-update|-confirm)[^\s]*/i;
      const ipUrl = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i;
      return shorteners.test(body) || suspiciousUrl.test(body) || ipUrl.test(body);
    }
  },
  {
    id: 'credential_request',
    name: 'Credential / Info Harvesting',
    weight: 20,
    severity: 'high',
    icon: '🪤',
    desc: 'Email asks for passwords, OTPs, card numbers, or personal information.',
    check: ({ body }) => {
      const lower = body.toLowerCase();
      const terms = [
        'enter your password', 'confirm your password', 'enter your otp',
        'credit card', 'card number', 'social security', 'bank account',
        'enter your pin', 'verify your identity', 'provide your details',
        'update your payment', 'billing information'
      ];
      return terms.some(t => lower.includes(t));
    }
  },
  {
    id: 'mismatched_reply',
    name: 'Reply-To Mismatch',
    weight: 12,
    severity: 'medium',
    icon: '↩️',
    desc: 'Reply-To address differs from the From address — a classic spoofing trick.',
    check: ({ headers }) => {
      const fromMatch = headers.match(/^from:.*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,})/im);
      const replyMatch = headers.match(/^reply-to:.*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,})/im);
      if (!fromMatch || !replyMatch) return false;
      const fromDomain = fromMatch[1].split('@')[1].toLowerCase();
      const replyDomain = replyMatch[1].split('@')[1].toLowerCase();
      return fromDomain !== replyDomain;
    }
  },
  {
    id: 'generic_greeting',
    name: 'Generic / Impersonal Greeting',
    weight: 8,
    severity: 'low',
    icon: '👤',
    desc: 'Uses generic greetings like "Dear Customer" instead of your real name.',
    check: ({ body }) => {
      const lower = body.toLowerCase();
      return ['dear customer', 'dear user', 'dear account holder',
        'dear valued', 'hello user', 'hi customer'].some(g => lower.includes(g));
    }
  },
  {
    id: 'attachment_warning',
    name: 'Dangerous Attachment Mentioned',
    weight: 15,
    severity: 'medium',
    icon: '📎',
    desc: 'Email references potentially dangerous file types (.exe, .zip, .docm, etc.).',
    check: ({ body }) =>
      /\.(exe|zip|rar|docm|xlsm|js|vbs|bat|cmd|ps1|iso|img)\b/i.test(body)
  },
  {
    id: 'html_obfuscation',
    name: 'HTML / Unicode Obfuscation',
    weight: 10,
    severity: 'medium',
    icon: '🧩',
    desc: 'Email uses HTML entities or unicode tricks to hide malicious content.',
    check: ({ body }) =>
      /&#x[0-9a-f]+;|&#\d+;|\\u[0-9a-f]{4}/i.test(body) ||
      (body.match(/&#/g) || []).length > 3
  }
];

// ─── Scoring & Verdict ───────────────────────────────────────────────────────

function getVerdict(score) {
  if (score >= 70) return {
    label: 'Likely Phishing',
    desc: 'Multiple strong phishing indicators detected. Do NOT click any links or provide any information.',
    icon: '🚨',
    color: 'var(--red)'
  };
  if (score >= 40) return {
    label: 'Suspicious',
    desc: 'Several warning signs found. Treat this email with caution and verify through official channels.',
    icon: '⚠️',
    color: 'var(--yellow)'
  };
  if (score >= 15) return {
    label: 'Low Risk',
    desc: 'A few minor indicators found. Likely safe, but stay alert.',
    icon: '🔎',
    color: 'var(--accent)'
  };
  return {
    label: 'Looks Clean',
    desc: 'No significant phishing indicators detected. Always stay cautious.',
    icon: '🛡️',
    color: 'var(--green)'
  };
}

// ─── Main Analyse Function ───────────────────────────────────────────────────

function analyse() {
  const headers = document.getElementById('headers').value.trim();
  const body = document.getElementById('body').value.trim();
  const sender = document.getElementById('sender').value.trim();

  if (!body) {
    alert('Please paste the email body to analyse.');
    return;
  }

  const input = { headers, body, sender };
  const triggered = [];
  const clean = [];

  for (const ind of INDICATORS) {
    if (ind.check(input)) triggered.push(ind);
    else clean.push(ind);
  }

  // Cap score at 100
  const rawScore = triggered.reduce((sum, i) => sum + i.weight, 0);
  const score = Math.min(rawScore, 100);
  const verdict = getVerdict(score);

  renderResults(score, verdict, triggered, clean);
}

// ─── Render ──────────────────────────────────────────────────────────────────

function renderResults(score, verdict, triggered, clean) {
  document.querySelector('.input-section').classList.add('hidden');
  const results = document.getElementById('results');
  results.classList.remove('hidden');

  // Score ring animation
  const ring = document.getElementById('ringFill');
  const circumference = 314;
  const offset = circumference - (score / 100) * circumference;
  setTimeout(() => {
    ring.style.strokeDashoffset = offset;
    ring.style.stroke = verdict.color;
  }, 100);

  // Animate score number
  const scoreEl = document.getElementById('scoreNum');
  scoreEl.style.color = verdict.color;
  let current = 0;
  const step = Math.ceil(score / 40);
  const timer = setInterval(() => {
    current = Math.min(current + step, score);
    scoreEl.textContent = current;
    if (current >= score) clearInterval(timer);
  }, 25);

  // Verdict
  document.getElementById('verdictIcon').textContent = verdict.icon;
  document.getElementById('verdictLabel').textContent = verdict.label;
  document.getElementById('verdictLabel').style.color = verdict.color;
  document.getElementById('verdictDesc').textContent = verdict.desc;

  // Finding cards (triggered only)
  const grid = document.getElementById('findingsGrid');
  grid.innerHTML = '';
  if (triggered.length === 0) {
    grid.innerHTML = '<p style="color:var(--muted);font-size:0.9rem;">No phishing indicators triggered.</p>';
  } else {
    triggered.forEach((ind, i) => {
      const card = document.createElement('div');
      card.className = `finding-card ${ind.severity}`;
      card.style.animationDelay = `${i * 0.07}s`;
      card.innerHTML = `
        <div class="finding-icon">${ind.icon}</div>
        <div>
          <div class="finding-title">${ind.name}</div>
          <div class="finding-desc">${ind.desc}</div>
        </div>`;
      grid.appendChild(card);
    });
  }

  // Indicator breakdown
  const list = document.getElementById('indicatorList');
  list.innerHTML = '';
  [...triggered, ...clean].forEach((ind, i) => {
    const isTriggered = triggered.includes(ind);
    const item = document.createElement('div');
    item.className = 'indicator-item';
    item.style.animationDelay = `${i * 0.04}s`;
    item.innerHTML = `
      <div class="indicator-dot ${isTriggered ? 'triggered' : 'clean'}"></div>
      <span class="indicator-name">${ind.icon} ${ind.name}</span>
      <span class="indicator-weight">+${ind.weight}pts</span>
      <span class="badge ${isTriggered ? 'triggered' : 'clean'}">${isTriggered ? 'Triggered' : 'Clear'}</span>`;
    list.appendChild(item);
  });
}

// ─── Reset ───────────────────────────────────────────────────────────────────

function reset() {
  document.getElementById('headers').value = '';
  document.getElementById('body').value = '';
  document.getElementById('sender').value = '';
  document.getElementById('results').classList.add('hidden');
  document.querySelector('.input-section').classList.remove('hidden');
  document.getElementById('ringFill').style.strokeDashoffset = '314';
  document.getElementById('scoreNum').textContent = '0';
}
