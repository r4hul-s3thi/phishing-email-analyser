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
      return triggers.filter(t => body.toLowerCase().includes(t)).length >= 2;
    }
  },
  {
    id: 'suspicious_links',
    name: 'Suspicious / Shortened URLs',
    weight: 20,
    severity: 'high',
    icon: '🔗',
    desc: 'Email contains shortened, obfuscated, or IP-based URLs.',
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
      const terms = [
        'enter your password', 'confirm your password', 'enter your otp',
        'credit card', 'card number', 'social security', 'bank account',
        'enter your pin', 'verify your identity', 'provide your details',
        'update your payment', 'billing information'
      ];
      return terms.some(t => body.toLowerCase().includes(t));
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
      return fromMatch[1].split('@')[1].toLowerCase() !== replyMatch[1].split('@')[1].toLowerCase();
    }
  },
  {
    id: 'generic_greeting',
    name: 'Generic / Impersonal Greeting',
    weight: 8,
    severity: 'low',
    icon: '👤',
    desc: 'Uses generic greetings like "Dear Customer" instead of your real name.',
    check: ({ body }) =>
      ['dear customer', 'dear user', 'dear account holder', 'dear valued', 'hello user', 'hi customer']
        .some(g => body.toLowerCase().includes(g))
  },
  {
    id: 'attachment_warning',
    name: 'Dangerous Attachment Mentioned',
    weight: 15,
    severity: 'medium',
    icon: '📎',
    desc: 'Email references potentially dangerous file types (.exe, .zip, .docm, etc.).',
    check: ({ body }) => /\.(exe|zip|rar|docm|xlsm|js|vbs|bat|cmd|ps1|iso|img)\b/i.test(body)
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

// ─── Verdict Config ──────────────────────────────────────────────────────────

function getVerdict(score) {
  if (score >= 70) return {
    label: 'Likely Phishing',
    desc: 'Multiple strong phishing indicators detected. Do NOT click any links or provide any information. Report and delete this email.',
    icon: '🚨',
    color: 'var(--red)',
    bannerBg: 'rgba(239,68,68,0.07)',
    bannerBorder: 'rgba(239,68,68,0.2)'
  };
  if (score >= 40) return {
    label: 'Suspicious',
    desc: 'Several warning signs found. Treat this email with caution and verify through official channels before taking any action.',
    icon: '⚠️',
    color: 'var(--yellow)',
    bannerBg: 'rgba(245,158,11,0.07)',
    bannerBorder: 'rgba(245,158,11,0.2)'
  };
  if (score >= 15) return {
    label: 'Low Risk',
    desc: 'A few minor indicators found. Likely safe, but always verify the sender before clicking links.',
    icon: '🔎',
    color: 'var(--accent)',
    bannerBg: 'rgba(6,182,212,0.06)',
    bannerBorder: 'rgba(6,182,212,0.15)'
  };
  return {
    label: 'Looks Clean',
    desc: 'No significant phishing indicators detected. Always stay cautious with unexpected emails.',
    icon: '🛡️',
    color: 'var(--green)',
    bannerBg: 'rgba(16,185,129,0.06)',
    bannerBorder: 'rgba(16,185,129,0.15)'
  };
}

// ─── Analyse ─────────────────────────────────────────────────────────────────

function analyse() {
  const headers = document.getElementById('headers').value.trim();
  const body    = document.getElementById('body').value.trim();
  const sender  = document.getElementById('sender').value.trim();

  if (!body) {
    shakeBtn();
    return;
  }

  const input = { headers, body, sender };
  const triggered = [], clean = [];

  for (const ind of INDICATORS) {
    (ind.check(input) ? triggered : clean).push(ind);
  }

  const score   = Math.min(triggered.reduce((s, i) => s + i.weight, 0), 100);
  const verdict = getVerdict(score);

  // Update steps
  document.getElementById('step1').classList.remove('active');
  document.getElementById('step1').classList.add('done');
  document.getElementById('step1').querySelector('.step-num').textContent = '✓';
  document.getElementById('step2').classList.add('done');
  document.getElementById('step2').querySelector('.step-num').textContent = '✓';
  document.getElementById('step3').classList.add('active');

  renderResults(score, verdict, triggered, clean);
}

// ─── Render ──────────────────────────────────────────────────────────────────

function renderResults(score, verdict, triggered, clean) {
  document.getElementById('inputPanel').classList.add('hidden');
  document.getElementById('resultsPanel').classList.remove('hidden');

  // Verdict banner styling
  const banner = document.getElementById('verdictBanner');
  banner.style.background = verdict.bannerBg;
  banner.style.borderColor = verdict.bannerBorder;

  document.getElementById('verdictIcon').textContent = verdict.icon;
  document.getElementById('verdictLabel').textContent = verdict.label;
  document.getElementById('verdictLabel').style.color = verdict.color;
  document.getElementById('verdictDesc').textContent = verdict.desc;

  // Score ring
  const ring = document.getElementById('ringFill');
  const circumference = 201;
  setTimeout(() => {
    ring.style.strokeDashoffset = circumference - (score / 100) * circumference;
    ring.style.stroke = verdict.color;
  }, 80);

  // Animate score counter
  const scoreEl = document.getElementById('scoreNum');
  scoreEl.style.color = verdict.color;
  let cur = 0;
  const step = Math.max(1, Math.ceil(score / 50));
  const t = setInterval(() => {
    cur = Math.min(cur + step, score);
    scoreEl.textContent = cur;
    if (cur >= score) clearInterval(t);
  }, 20);

  // Triggered count badge
  document.getElementById('triggeredCount').textContent = triggered.length;

  // Finding cards
  const grid = document.getElementById('findingsGrid');
  grid.innerHTML = '';
  if (triggered.length === 0) {
    grid.innerHTML = '<p style="color:var(--text3);font-size:0.85rem;padding:0.5rem 0;">No phishing indicators triggered.</p>';
  } else {
    triggered.forEach((ind, i) => {
      const card = document.createElement('div');
      card.className = `finding-card ${ind.severity}`;
      card.style.animationDelay = `${i * 0.06}s`;
      card.innerHTML = `
        <div class="finding-icon">${ind.icon}</div>
        <div>
          <div class="finding-title">${ind.name}</div>
          <div class="finding-desc">${ind.desc}</div>
        </div>`;
      grid.appendChild(card);
    });
  }

  // Full indicator table
  const table = document.getElementById('indicatorList');
  table.innerHTML = '';
  [...triggered, ...clean].forEach((ind, i) => {
    const hit = triggered.includes(ind);
    const row = document.createElement('div');
    row.className = 'indicator-row';
    row.style.animationDelay = `${i * 0.03}s`;
    row.innerHTML = `
      <div class="ind-dot ${hit ? 'triggered' : 'clean'}"></div>
      <span class="ind-name">${ind.icon} ${ind.name}</span>
      <span class="ind-weight">+${ind.weight}pts</span>
      <span class="ind-badge ${hit ? 'triggered' : 'clean'}">${hit ? 'Triggered' : 'Clear'}</span>`;
    table.appendChild(row);
  });
}

// ─── Reset ───────────────────────────────────────────────────────────────────

function reset() {
  document.getElementById('headers').value = '';
  document.getElementById('body').value = '';
  document.getElementById('sender').value = '';

  document.getElementById('resultsPanel').classList.add('hidden');
  document.getElementById('inputPanel').classList.remove('hidden');

  document.getElementById('ringFill').style.strokeDashoffset = '201';
  document.getElementById('scoreNum').textContent = '0';

  // Reset steps
  ['step1','step2','step3'].forEach(id => {
    const el = document.getElementById(id);
    el.classList.remove('active','done');
  });
  document.getElementById('step1').classList.add('active');
  document.getElementById('step1').querySelector('.step-num').textContent = '1';
  document.getElementById('step2').querySelector('.step-num').textContent = '2';
  document.getElementById('step3').querySelector('.step-num').textContent = '3';
}

// ─── Shake button on empty submit ────────────────────────────────────────────

function shakeBtn() {
  const btn = document.getElementById('analyseBtn');
  btn.style.animation = 'none';
  btn.style.transform = 'translateX(-6px)';
  setTimeout(() => btn.style.transform = 'translateX(6px)', 80);
  setTimeout(() => btn.style.transform = 'translateX(-4px)', 160);
  setTimeout(() => btn.style.transform = 'translateX(0)', 240);
  setTimeout(() => btn.style.animation = '', 300);

  const bodyField = document.getElementById('body');
  bodyField.style.borderColor = 'var(--red)';
  bodyField.style.boxShadow = '0 0 0 3px rgba(239,68,68,0.12)';
  bodyField.placeholder = '⚠ Please paste the email body first...';
  setTimeout(() => {
    bodyField.style.borderColor = '';
    bodyField.style.boxShadow = '';
    bodyField.placeholder = 'Paste the full email body here...';
  }, 2500);
}
