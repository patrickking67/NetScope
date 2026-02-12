/* ===== NetScope - Network Security Toolkit ===== */

// ---------- State ----------
const state = {
  ip: null,
  geo: null,
  speed: { ping: null, download: null, upload: null },
  breachStats: null,
  dnsResults: null,
  securityScan: null,
};

// ---------- Init ----------
document.addEventListener('DOMContentLoaded', () => {
  initNav();
  initExport();
  initBreachTabs();
  initPasswordToggle();
  initEventListeners();
  fetchIPInfo();
  fetchBreachStats();
});

// ---------- Navigation ----------
function initNav() {
  const links = document.querySelectorAll('.nav-link');
  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        links.forEach(l => l.classList.remove('active'));
        const link = document.querySelector(`.nav-link[data-section="${entry.target.id}"]`);
        if (link) link.classList.add('active');
      }
    });
  }, { threshold: 0.3, rootMargin: '-80px 0px 0px 0px' });

  document.querySelectorAll('.card[id]').forEach(section => observer.observe(section));
}

// ---------- Export Panel ----------
function initExport() {
  const trigger = document.getElementById('export-trigger');
  const panel = document.getElementById('export-panel');
  trigger.addEventListener('click', e => {
    e.stopPropagation();
    panel.classList.toggle('open');
  });
  document.addEventListener('click', e => {
    if (!panel.contains(e.target) && e.target !== trigger) {
      panel.classList.remove('open');
    }
  });
  document.getElementById('btn-copy').addEventListener('click', exportCopy);
  document.getElementById('btn-email').addEventListener('click', exportEmail);
  document.getElementById('btn-pdf').addEventListener('click', exportPDF);
}

// ---------- Breach Tabs ----------
function initBreachTabs() {
  document.querySelectorAll('.breach-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.breach-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      document.querySelectorAll('.breach-content').forEach(c => c.classList.add('hidden'));
      const target = tab.getAttribute('data-tab');
      document.querySelector(`[data-tab-content="${target}"]`).classList.remove('hidden');
    });
  });
}

// ---------- Password Toggle ----------
function initPasswordToggle() {
  const toggle = document.getElementById('toggle-password');
  const input = document.getElementById('password-input');
  toggle.addEventListener('click', () => {
    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';
    toggle.title = isPassword ? 'Hide password' : 'Show password';
  });
}

// ---------- Event Listeners ----------
function initEventListeners() {
  document.getElementById('btn-speed-test').addEventListener('click', runSpeedTest);
  document.getElementById('btn-breach-check').addEventListener('click', checkPassword);
  document.getElementById('btn-dns-lookup').addEventListener('click', dnsLookup);
  document.getElementById('btn-security-scan').addEventListener('click', runSecurityScan);
  document.getElementById('password-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') checkPassword();
  });
  document.getElementById('dns-domain').addEventListener('keydown', e => {
    if (e.key === 'Enter') dnsLookup();
  });
}

// ============================================================
// IP INFO & GEOLOCATION
// ============================================================
async function fetchIPInfo() {
  try {
    const res = await fetch('https://ipwho.is/');
    const data = await res.json();
    if (!data.success) throw new Error(data.message);
    state.ip = data.ip;
    state.geo = data;
    renderIPInfo(data);
    renderGeo(data);
  } catch (err) {
    console.error('IP fetch failed:', err);
    document.getElementById('ip-address').textContent = 'Error loading IP';
    // Fallback: try ipapi
    try {
      const res = await fetch('https://ipapi.co/json/');
      const data = await res.json();
      state.ip = data.ip;
      state.geo = data;
      renderIPInfoFallback(data);
      renderGeoFallback(data);
    } catch (e2) {
      console.error('Fallback IP fetch also failed:', e2);
    }
  }
}

function renderIPInfo(d) {
  document.getElementById('ip-address').textContent = d.ip;
  setVal('info-isp', d.connection?.isp || 'N/A');
  setVal('info-org', d.connection?.org || 'N/A');
  setVal('info-asn', d.connection?.asn ? `AS${d.connection.asn}` : 'N/A');
  setVal('info-type', d.type || 'N/A');
  setVal('info-proxy', d.security?.proxy ? 'Yes' : 'No');
  setVal('info-hosting', d.security?.hosting ? 'Yes' : 'No');
}

function renderIPInfoFallback(d) {
  document.getElementById('ip-address').textContent = d.ip;
  setVal('info-isp', d.org || 'N/A');
  setVal('info-org', d.org || 'N/A');
  setVal('info-asn', d.asn || 'N/A');
  setVal('info-type', d.version || 'N/A');
  setVal('info-proxy', 'N/A');
  setVal('info-hosting', 'N/A');
}

function renderGeo(d) {
  const el = id => document.getElementById(id);
  el('geo-country').innerHTML = `${d.flag?.emoji || ''} ${d.country || 'N/A'}`;
  setVal('geo-region', d.region || 'N/A');
  setVal('geo-city', d.city || 'N/A');
  setVal('geo-postal', d.postal || 'N/A');
  setVal('geo-coords', `${d.latitude?.toFixed(4)}, ${d.longitude?.toFixed(4)}`);
  setVal('geo-timezone', d.timezone?.id || 'N/A');
  initMap(d.latitude, d.longitude);
}

function renderGeoFallback(d) {
  setVal('geo-country', d.country_name || 'N/A');
  setVal('geo-region', d.region || 'N/A');
  setVal('geo-city', d.city || 'N/A');
  setVal('geo-postal', d.postal || 'N/A');
  setVal('geo-coords', `${d.latitude}, ${d.longitude}`);
  setVal('geo-timezone', d.timezone || 'N/A');
  initMap(d.latitude, d.longitude);
}

function initMap(lat, lng) {
  if (!lat || !lng) return;
  const map = L.map('map', {
    zoomControl: true,
    attributionControl: false,
    scrollWheelZoom: false,
  }).setView([lat, lng], 11);

  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    maxZoom: 18,
  }).addTo(map);

  L.circleMarker([lat, lng], {
    radius: 10,
    fillColor: '#3b82f6',
    color: '#3b82f6',
    weight: 2,
    opacity: 0.8,
    fillOpacity: 0.3,
  }).addTo(map);

  // Fix map rendering in hidden/animated containers
  setTimeout(() => map.invalidateSize(), 300);
}

// ============================================================
// SPEED TEST
// ============================================================
let speedTestRunning = false;

async function runSpeedTest() {
  if (speedTestRunning) return;
  speedTestRunning = true;

  const btn = document.getElementById('btn-speed-test');
  const status = document.getElementById('speed-status');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Testing...';

  try {
    // Phase 1: Latency
    status.textContent = 'Testing latency...';
    const ping = await testLatency();
    state.speed.ping = ping;
    document.getElementById('speed-ping').textContent = ping.toFixed(0);

    // Phase 2: Download
    status.textContent = 'Testing download speed...';
    const download = await testDownload();
    state.speed.download = download;
    document.getElementById('speed-download').textContent = download.toFixed(1);
    updateGauge(download);
    document.getElementById('gauge-number').textContent = download.toFixed(1);

    // Phase 3: Upload
    status.textContent = 'Testing upload speed...';
    const upload = await testUpload();
    state.speed.upload = upload;
    document.getElementById('speed-upload').textContent = upload.toFixed(1);

    status.textContent = 'Test complete';
  } catch (err) {
    console.error('Speed test error:', err);
    status.textContent = 'Speed test encountered an error. Results may be partial.';
  } finally {
    speedTestRunning = false;
    btn.disabled = false;
    btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><polygon points="5 3 19 12 5 21 5 3"/></svg> Run Again`;
  }
}

async function testLatency() {
  const results = [];
  for (let i = 0; i < 5; i++) {
    const start = performance.now();
    try {
      await fetch(`https://httpbin.org/status/200?_=${Date.now()}-${i}`, {
        method: 'HEAD',
        cache: 'no-store',
      });
    } catch {
      await fetch(`https://www.google.com/generate_204?_=${Date.now()}-${i}`, {
        method: 'HEAD',
        mode: 'no-cors',
        cache: 'no-store',
      });
    }
    results.push(performance.now() - start);
  }
  results.sort((a, b) => a - b);
  return results[Math.floor(results.length / 2)]; // median
}

async function testDownload() {
  const sizes = [500000, 1000000, 2000000, 5000000];
  let bestSpeed = 0;

  for (const size of sizes) {
    try {
      const start = performance.now();
      const res = await fetch(`https://httpbin.org/bytes/${size}?_=${Date.now()}`, {
        cache: 'no-store',
      });
      await res.arrayBuffer();
      const elapsed = (performance.now() - start) / 1000; // seconds
      const speed = (size * 8) / elapsed / 1000000; // Mbps
      if (speed > bestSpeed) bestSpeed = speed;
      updateGauge(speed);
      document.getElementById('gauge-number').textContent = speed.toFixed(1);
      // If test took too long on small size, skip larger sizes
      if (elapsed > 8) break;
    } catch {
      break;
    }
  }
  return bestSpeed || 0;
}

async function testUpload() {
  const size = 1000000; // 1MB
  const data = new Blob([new ArrayBuffer(size)]);
  try {
    const start = performance.now();
    await fetch('https://httpbin.org/post', {
      method: 'POST',
      body: data,
      cache: 'no-store',
    });
    const elapsed = (performance.now() - start) / 1000;
    return (size * 8) / elapsed / 1000000; // Mbps
  } catch {
    return 0;
  }
}

function updateGauge(speedMbps) {
  const circle = document.getElementById('gauge-circle');
  const circumference = 2 * Math.PI * 52; // 326.73
  const maxSpeed = 200; // Mbps for full gauge
  const pct = Math.min(speedMbps / maxSpeed, 1);
  const offset = circumference * (1 - pct);
  circle.style.strokeDashoffset = offset;
}

// ============================================================
// BREACH CHECK (Have I Been Pwned)
// ============================================================
async function checkPassword() {
  const input = document.getElementById('password-input');
  const password = input.value;
  if (!password) {
    showToast('Enter a password to check');
    return;
  }

  const resultEl = document.getElementById('breach-result');
  resultEl.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding: 20px;">Checking...</div>';

  try {
    // SHA-1 hash
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    const prefix = hashHex.substring(0, 5);
    const suffix = hashHex.substring(5);

    // Query HIBP k-anonymity API
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    const text = await res.text();
    const lines = text.split('\n');

    let count = 0;
    for (const line of lines) {
      const [hashSuffix, c] = line.split(':');
      if (hashSuffix.trim() === suffix) {
        count = parseInt(c.trim(), 10);
        break;
      }
    }

    if (count === 0) {
      resultEl.innerHTML = `
        <div class="breach-result--safe">
          <div class="result-icon">&#x2705;</div>
          <div class="result-text">No breaches found</div>
          <div class="result-sub">This password has not appeared in any known data breaches.</div>
        </div>`;
    } else {
      resultEl.innerHTML = `
        <div class="breach-result--danger">
          <div class="result-icon">&#x26A0;&#xFE0F;</div>
          <div class="result-text">Found in ${count.toLocaleString()} breaches</div>
          <div class="result-sub">This password has been exposed. You should change it immediately.</div>
        </div>`;
    }
  } catch (err) {
    console.error('Breach check error:', err);
    resultEl.innerHTML = '<div style="color: var(--accent-red); text-align: center; padding: 20px;">Error checking password. Please try again.</div>';
  }
}

// ---------- Breach Stats ----------
async function fetchBreachStats() {
  try {
    const res = await fetch('https://haveibeenpwned.com/api/v3/breaches');
    const breaches = await res.json();
    state.breachStats = breaches;

    const totalBreaches = breaches.length;
    const totalAccounts = breaches.reduce((sum, b) => sum + (b.PwnCount || 0), 0);
    const sorted = [...breaches].sort((a, b) => new Date(b.BreachDate) - new Date(a.BreachDate));
    const latest = sorted[0];

    document.getElementById('stat-total-breaches').textContent = totalBreaches.toLocaleString();
    document.getElementById('stat-total-accounts').textContent = formatLargeNumber(totalAccounts);
    document.getElementById('stat-latest-breach').textContent = latest?.Name || 'N/A';

    // Render recent breaches
    const listEl = document.getElementById('breach-list');
    listEl.innerHTML = sorted.slice(0, 30).map(b => `
      <div class="breach-item">
        <div>
          <div class="breach-item-name">${escapeHtml(b.Name)}</div>
          <div class="breach-item-date">${b.BreachDate}</div>
        </div>
        <div class="breach-item-count">${formatLargeNumber(b.PwnCount)}</div>
      </div>
    `).join('');
  } catch (err) {
    console.error('Failed to load breach stats:', err);
    document.getElementById('stat-total-breaches').textContent = 'N/A';
    document.getElementById('stat-total-accounts').textContent = 'N/A';
    document.getElementById('stat-latest-breach').textContent = 'N/A';
  }
}

// ============================================================
// DNS LOOKUP
// ============================================================
async function dnsLookup() {
  const domain = document.getElementById('dns-domain').value.trim();
  const type = document.getElementById('dns-type').value;
  const resultsEl = document.getElementById('dns-results');

  if (!domain) {
    showToast('Enter a domain name');
    return;
  }

  resultsEl.innerHTML = '<div style="color: var(--text-muted); padding: 10px;">Resolving...</div>';

  try {
    const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`);
    const data = await res.json();
    state.dnsResults = data;

    if (!data.Answer || data.Answer.length === 0) {
      resultsEl.innerHTML = '<div style="color: var(--text-muted); padding: 10px;">No records found.</div>';
      return;
    }

    resultsEl.innerHTML = data.Answer.map(record => `
      <div class="dns-record">
        <span class="dns-record-type">${escapeHtml(typeFromInt(record.type))}</span>
        <span class="dns-record-value">${escapeHtml(record.data)}</span>
        <span class="dns-record-ttl">TTL ${record.TTL}s</span>
      </div>
    `).join('');
  } catch (err) {
    console.error('DNS lookup error:', err);
    resultsEl.innerHTML = '<div style="color: var(--accent-red); padding: 10px;">DNS lookup failed.</div>';
  }
}

function typeFromInt(t) {
  const types = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV' };
  return types[t] || `TYPE${t}`;
}

// ============================================================
// SECURITY SCAN
// ============================================================
async function runSecurityScan() {
  const resultsEl = document.getElementById('security-results');
  const btn = document.getElementById('btn-security-scan');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Scanning...';
  resultsEl.innerHTML = '';

  const checks = [];

  // 1. DNSSEC check
  try {
    const res = await fetch('https://dns.google/resolve?name=cloudflare.com&type=A&do=1');
    const data = await res.json();
    const hasDnssec = data.AD === true;
    checks.push({
      icon: hasDnssec ? 'pass' : 'info',
      name: 'DNSSEC Validation',
      detail: hasDnssec ? 'Your DNS resolver validates DNSSEC signatures' : 'DNSSEC validation status could not be confirmed',
    });
  } catch {
    checks.push({ icon: 'warn', name: 'DNSSEC Validation', detail: 'Could not test DNSSEC' });
  }

  // 2. DNS over HTTPS check
  try {
    await fetch('https://dns.google/resolve?name=example.com&type=A');
    checks.push({
      icon: 'pass',
      name: 'DNS over HTTPS (DoH)',
      detail: 'Your browser can reach DNS-over-HTTPS endpoints',
    });
  } catch {
    checks.push({ icon: 'warn', name: 'DNS over HTTPS (DoH)', detail: 'DoH endpoints may be blocked' });
  }

  // 3. WebRTC leak check
  try {
    const ips = await checkWebRTCLeak();
    if (ips.length === 0) {
      checks.push({ icon: 'pass', name: 'WebRTC Leak Test', detail: 'No local IP addresses leaked via WebRTC' });
    } else {
      checks.push({ icon: 'warn', name: 'WebRTC Leak Test', detail: `Local IPs detected: ${ips.join(', ')}` });
    }
  } catch {
    checks.push({ icon: 'info', name: 'WebRTC Leak Test', detail: 'Could not perform WebRTC leak test' });
  }

  // 4. HTTPS check
  checks.push({
    icon: location.protocol === 'https:' ? 'pass' : 'fail',
    name: 'HTTPS Connection',
    detail: location.protocol === 'https:' ? 'You are connected via HTTPS' : 'This page is not using HTTPS',
  });

  // 5. Proxy/VPN detection
  if (state.geo) {
    const isProxy = state.geo.security?.proxy || state.geo.security?.vpn || false;
    checks.push({
      icon: 'info',
      name: 'Proxy / VPN',
      detail: isProxy ? 'A proxy or VPN connection was detected' : 'No proxy or VPN detected',
    });
  }

  // 6. Check browser connection info
  if ('connection' in navigator) {
    const conn = navigator.connection;
    checks.push({
      icon: 'info',
      name: 'Connection Type',
      detail: `${conn.effectiveType?.toUpperCase() || 'Unknown'} | Downlink: ${conn.downlink || 'N/A'} Mbps | RTT: ${conn.rtt || 'N/A'} ms`,
    });
  }

  state.securityScan = checks;
  resultsEl.innerHTML = checks.map(c => `
    <div class="security-check">
      <div class="check-icon check-icon--${c.icon}">
        ${c.icon === 'pass' ? '&#x2713;' : c.icon === 'fail' ? '&#x2717;' : c.icon === 'warn' ? '!' : 'i'}
      </div>
      <div>
        <div class="check-name">${escapeHtml(c.name)}</div>
        <div class="check-detail">${escapeHtml(c.detail)}</div>
      </div>
    </div>
  `).join('');

  btn.disabled = false;
  btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg> Run Again`;
}

async function checkWebRTCLeak() {
  return new Promise((resolve) => {
    const ips = new Set();
    try {
      const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
      pc.createDataChannel('');
      pc.createOffer().then(offer => pc.setLocalDescription(offer));
      pc.onicecandidate = event => {
        if (!event.candidate) {
          pc.close();
          resolve([...ips]);
          return;
        }
        const parts = event.candidate.candidate.split(' ');
        if (parts.length > 4) {
          const ip = parts[4];
          if (ip && !ip.endsWith('.local') && !ip.includes(':')) {
            ips.add(ip);
          }
        }
      };
      setTimeout(() => { pc.close(); resolve([...ips]); }, 4000);
    } catch {
      resolve([]);
    }
  });
}

// ============================================================
// EXPORT FUNCTIONS
// ============================================================
function buildResultsText() {
  const lines = ['=== NetScope Results ===', `Generated: ${new Date().toLocaleString()}`, ''];

  if (state.ip) {
    lines.push('--- Public IP & Network ---');
    lines.push(`IP Address: ${state.ip}`);
    if (state.geo) {
      const g = state.geo;
      lines.push(`ISP: ${g.connection?.isp || g.org || 'N/A'}`);
      lines.push(`Organization: ${g.connection?.org || g.org || 'N/A'}`);
      lines.push(`ASN: ${g.connection?.asn ? 'AS' + g.connection.asn : (g.asn || 'N/A')}`);
      lines.push(`Type: ${g.type || 'N/A'}`);
      lines.push('');
      lines.push('--- Geolocation ---');
      lines.push(`Country: ${g.country || g.country_name || 'N/A'}`);
      lines.push(`Region: ${g.region || 'N/A'}`);
      lines.push(`City: ${g.city || 'N/A'}`);
      lines.push(`Coordinates: ${g.latitude}, ${g.longitude}`);
      lines.push(`Timezone: ${g.timezone?.id || g.timezone || 'N/A'}`);
    }
    lines.push('');
  }

  if (state.speed.ping !== null) {
    lines.push('--- Speed Test ---');
    lines.push(`Ping: ${state.speed.ping?.toFixed(0) || '--'} ms`);
    lines.push(`Download: ${state.speed.download?.toFixed(1) || '--'} Mbps`);
    lines.push(`Upload: ${state.speed.upload?.toFixed(1) || '--'} Mbps`);
    lines.push('');
  }

  if (state.securityScan) {
    lines.push('--- Security Scan ---');
    state.securityScan.forEach(c => {
      const icon = c.icon === 'pass' ? '[PASS]' : c.icon === 'fail' ? '[FAIL]' : c.icon === 'warn' ? '[WARN]' : '[INFO]';
      lines.push(`${icon} ${c.name}: ${c.detail}`);
    });
    lines.push('');
  }

  lines.push('Powered by NetScope');
  return lines.join('\n');
}

function exportCopy() {
  const text = buildResultsText();
  navigator.clipboard.writeText(text).then(() => {
    showToast('Results copied to clipboard');
  }).catch(() => {
    showToast('Failed to copy');
  });
  document.getElementById('export-panel').classList.remove('open');
}

function exportEmail() {
  const text = buildResultsText();
  const subject = encodeURIComponent('NetScope - Network Security Results');
  const body = encodeURIComponent(text);
  window.open(`mailto:?subject=${subject}&body=${body}`, '_self');
  document.getElementById('export-panel').classList.remove('open');
}

function exportPDF() {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();
  const text = buildResultsText();
  const lines = doc.splitTextToSize(text, 170);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(18);
  doc.setTextColor(59, 130, 246);
  doc.text('NetScope Report', 20, 20);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10);
  doc.setTextColor(100, 100, 100);
  doc.text(`Generated: ${new Date().toLocaleString()}`, 20, 28);

  doc.setDrawColor(220, 220, 220);
  doc.line(20, 32, 190, 32);

  doc.setFontSize(10);
  doc.setTextColor(40, 40, 40);
  let y = 40;
  for (const line of lines) {
    if (y > 280) {
      doc.addPage();
      y = 20;
    }
    if (line.startsWith('---')) {
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(59, 130, 246);
      doc.text(line.replace(/---/g, '').trim(), 20, y);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(40, 40, 40);
    } else {
      doc.text(line, 20, y);
    }
    y += 6;
  }

  doc.save('netscope-report.pdf');
  showToast('PDF downloaded');
  document.getElementById('export-panel').classList.remove('open');
}

// ============================================================
// UTILITIES
// ============================================================
function setVal(id, value) {
  const el = document.getElementById(id);
  el.textContent = value;
  el.classList.remove('skeleton');
}

function showToast(msg) {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2500);
}

function formatLargeNumber(n) {
  if (n >= 1e9) return (n / 1e9).toFixed(1) + 'B';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
  return n.toLocaleString();
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
