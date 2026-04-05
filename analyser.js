const CHECKS = [
  {
    id: 'spf',
    name: 'SPF Fail / Softfail',
    weight: 20,
    sev: 'high',
    icon: '📛',
    desc: 'SPF record check failed — the sending server is not authorised for this domain.',
    run: ({ headers }) => /received-spf:\s*(fail|softfail)/i.test(headers)
  },
  {
    id: 'dkim',
    name: 'DKIM Invalid / Missing',
    weight: 18,
    sev: 'high',
    icon: '🔑',
    desc: 'DKIM signature failed or absent — email integrity cannot be confirmed.',
    run: ({ headers }) =>
      /dkim=fail/i.test(headers) ||
      (headers.length > 10 && !/dkim-signature/i.test(headers))
  },
  {
    id: 'dmarc',
    name: 'DMARC Fail',
    weight: 18,
    sev: 'high',
    icon: '🚫',
    desc: 'DMARC policy check failed — strong indicator of a spoofed sender.',
    run: ({ headers }) => /dmarc=fail/i.test(headers)
  },
  {
    id: 'lookalike',
    name: 'Spoofed / Lookalike Domain',
    weight: 25,
    sev: 'high',
    icon: '🎭',
    desc: 'Sender domain appears to impersonate a trusted brand.',
    run: ({ sender, body }) => {
      const text = (sender + ' ' + body).toLowerCase();
      return [
        /paypa[l1]-/i, /g[o0]{2}gle/i, /micros[o0]ft/i, /app[l1]e-/i,
        /github-[a-z]/i, /amazon-[a-z]/i, /netf[l1]ix/i,
        /[a-z]+-secure\./i, /[a-z]+-login\./i, /[a-z]+-verify\./i,
        /[a-z]+-account\./i, /[a-z]+-update\./i
      ].some(p => p.test(text));
    }
  },
  {
    id: 'urgency',
    name: 'Urgency / Scare Tactics',
    weight: 15,
    sev: 'medium',
    icon: '⏰',
    desc: 'Email uses pressure language to push you into acting without thinking.',
    run: ({ body }) => {
      const lower = body.toLowerCase();
      const hits = [
        'immediately', 'urgent', 'act now', 'account suspended', 'verify now',
        'limited time', 'expires', 'unauthorized access', 'suspicious activity',
        'action required', 'confirm your identity', 'failure to',
        'within 24 hours', 'within 48 hours', 'your account will be'
      ].filter(t => lower.includes(t));
      return hits.length >= 2;
    }
  },
  {
    id: 'urls',
    name: 'Suspicious / Shortened URLs',
    weight: 20,
    sev: 'high',
    icon: '🔗',
    desc: 'Contains shortened links, IP-based URLs, or URLs with suspicious keywords.',
    run: ({ body }) =>
      /\b(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|rb\.gy|cutt\.ly|is\.gd)\b/i.test(body) ||
      /https?:\/\/[^\s]*(-login|-verify|-secure|-account|-update|-confirm)/i.test(body) ||
      /https?:\/\/\d{1,3}(\.\d{1,3}){3}/i.test(body)
  },
  {
    id: 'creds',
    name: 'Credential Harvesting',
    weight: 20,
    sev: 'high',
    icon: '🪤',
    desc: 'Asks for passwords, OTPs, card numbers, or other sensitive information.',
    run: ({ body }) => {
      const lower = body.toLowerCase();
      return [
        'enter your password', 'confirm your password', 'enter your otp',
        'credit card', 'card number', 'social security', 'bank account',
        'enter your pin', 'verify your identity', 'update your payment',
        'billing information', 'provide your details'
      ].some(t => lower.includes(t));
    }
  },
  {
    id: 'replyto',
    name: 'Reply-To Mismatch',
    weight: 12,
    sev: 'medium',
    icon: '↩️',
    desc: 'Reply-To domain differs from the From domain — a common spoofing trick.',
    run: ({ headers }) => {
      const from  = headers.match(/^from:.*?([a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-z]{2,}))/im);
      const reply = headers.match(/^reply-to:.*?([a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-z]{2,}))/im);
      if (!from || !reply) return false;
      return from[2].toLowerCase() !== reply[2].toLowerCase();
    }
  },
  {
    id: 'greeting',
    name: 'Generic Greeting',
    weight: 8,
    sev: 'low',
    icon: '👤',
    desc: 'Uses "Dear Customer" or similar — legitimate services usually know your name.',
    run: ({ body }) => {
      const lower = body.toLowerCase();
      return ['dear customer', 'dear user', 'dear account holder',
        'dear valued', 'hello user', 'hi customer'].some(g => lower.includes(g));
    }
  },
  {
    id: 'attachment',
    name: 'Dangerous Attachment',
    weight: 15,
    sev: 'medium',
    icon: '📎',
    desc: 'References a file type commonly used to deliver malware.',
    run: ({ body }) => /\.(exe|zip|rar|docm|xlsm|js|vbs|bat|cmd|ps1|iso|img)\b/i.test(body)
  },
  {
    id: 'obfuscation',
    name: 'HTML / Unicode Obfuscation',
    weight: 10,
    sev: 'medium',
    icon: '🧩',
    desc: 'Uses HTML entities or unicode escapes to hide content from filters.',
    run: ({ body }) =>
      /&#x[0-9a-f]+;|&#\d+;|\\u[0-9a-f]{4}/i.test(body) ||
      (body.match(/&#/g) || []).length > 3
  }
];

function verdict(score) {
  if (score >= 70) return { label: 'Likely Phishing', icon: '🚨', color: 'var(--red)',    desc: 'Multiple strong indicators. Do not click any links or reply. Report and delete.' };
  if (score >= 40) return { label: 'Suspicious',      icon: '⚠️',  color: 'var(--yellow)', desc: 'Several warning signs. Verify through official channels before doing anything.' };
  if (score >= 15) return { label: 'Low Risk',         icon: '🔎',  color: 'var(--cyan)',   desc: 'Minor indicators found. Probably fine, but double-check the sender.' };
  return                  { label: 'Looks Clean',      icon: '🛡️',  color: 'var(--green)',  desc: 'Nothing suspicious detected. Stay cautious with unexpected emails regardless.' };
}

function analyse() {
  const body    = document.getElementById('body').value.trim();
  const headers = document.getElementById('headers').value.trim();
  const sender  = document.getElementById('sender').value.trim();

  if (!body) {
    const ta = document.getElementById('body');
    ta.style.borderColor = 'var(--red)';
    ta.focus();
    setTimeout(() => ta.style.borderColor = '', 1800);
    return;
  }

  const input = { body, headers, sender };
  const hit = [], miss = [];

  for (const c of CHECKS) {
    (c.run(input) ? hit : miss).push(c);
  }

  const score = Math.min(hit.reduce((s, c) => s + c.weight, 0), 100);
  const v = verdict(score);

  render(score, v, hit, miss);
}

function render(score, v, hit, miss) {
  document.getElementById('inputView').classList.add('hidden');
  document.getElementById('resultsView').classList.remove('hidden');

  // score ring  (circumference = 2π × 42 ≈ 264)
  const ring = document.getElementById('ringFill');
  setTimeout(() => {
    ring.style.strokeDashoffset = 264 - (score / 100) * 264;
    ring.style.stroke = v.color;
  }, 60);

  // counter
  const el = document.getElementById('scoreNum');
  el.style.color = v.color;
  let n = 0;
  const step = Math.max(1, Math.ceil(score / 40));
  const t = setInterval(() => {
    n = Math.min(n + step, score);
    el.textContent = n;
    if (n >= score) clearInterval(t);
  }, 18);

  document.getElementById('verdictIcon').textContent  = v.icon;
  document.getElementById('verdictLabel').textContent = v.label;
  document.getElementById('verdictLabel').style.color = v.color;
  document.getElementById('verdictDesc').textContent  = v.desc;

  // triggered cards
  document.getElementById('tCount').textContent = hit.length;
  const cardList = document.getElementById('triggeredList');
  cardList.innerHTML = hit.length
    ? ''
    : '<p style="font-size:13px;color:var(--muted)">None triggered.</p>';

  hit.forEach((c, i) => {
    const d = document.createElement('div');
    d.className = `card ${c.sev}`;
    d.style.animationDelay = `${i * 0.05}s`;
    d.innerHTML = `<div class="card-icon">${c.icon}</div>
      <div><div class="card-name">${c.name}</div>
      <div class="card-desc">${c.desc}</div></div>`;
    cardList.appendChild(d);
  });

  // all indicators
  const allList = document.getElementById('allList');
  allList.innerHTML = '';
  [...hit, ...miss].forEach((c, i) => {
    const isHit = hit.includes(c);
    const row = document.createElement('div');
    row.className = 'ind-row';
    row.style.animationDelay = `${i * 0.025}s`;
    row.innerHTML = `
      <div class="dot ${isHit ? 'hit' : 'clear'}"></div>
      <span class="ind-name">${c.icon} ${c.name}</span>
      <span class="ind-pts">+${c.weight}pt</span>
      <span class="tag ${isHit ? 'hit' : 'clear'}">${isHit ? 'triggered' : 'clear'}</span>`;
    allList.appendChild(row);
  });
}

function reset() {
  document.getElementById('body').value    = '';
  document.getElementById('headers').value = '';
  document.getElementById('sender').value  = '';
  document.getElementById('resultsView').classList.add('hidden');
  document.getElementById('inputView').classList.remove('hidden');
  document.getElementById('ringFill').style.strokeDashoffset = '264';
  document.getElementById('scoreNum').textContent = '0';
}
