// Dashboard JS

function esc(t) {
  return String(t).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

async function loadStats() {
  try {
    const [scoreRes, logsRes] = await Promise.all([
      fetch('/dashboard/score'),
      fetch('/dashboard/logs')
    ]);

    const score = await scoreRes.json();
    const logs = await logsRes.json();

    // Update stat cards
    document.getElementById('statTotal').textContent = score.total_attacks;
    document.getElementById('statSQL').textContent = score.by_type?.SQL_INJECTION || 0;
    document.getElementById('statXSS').textContent = score.by_type?.XSS || 0;
    document.getElementById('statCSRF').textContent = score.by_type?.CSRF || 0;
    document.getElementById('statBlocked').textContent = score.blocked || 0;

    // Update score ring
    const ring = document.getElementById('scoreRing');
    const num = document.getElementById('scoreNum');
    const level = document.getElementById('scoreLevel');
    const desc = document.getElementById('scoreDesc');

    num.textContent = score.score;
    ring.className = `score-ring ${score.level}`;

    const levelColors = { secure: 'var(--accent-green)', medium: 'var(--accent-yellow)', insecure: 'var(--accent-red)' };
    level.style.color = levelColors[score.level] || 'var(--text-primary)';
    level.textContent = score.level?.toUpperCase() || '—';

    const descs = {
      secure: `${score.blocked} of ${score.total_attacks} attacks blocked. System defenses are effective.`,
      medium: `${score.blocked} of ${score.total_attacks} attacks blocked. Some vulnerabilities remain.`,
      insecure: `Only ${score.blocked} of ${score.total_attacks} attacks blocked. Critical vulnerabilities present.`
    };
    desc.textContent = descs[score.level] || 'Run some attack simulations to see your score.';

    // Update chart
    renderChart(score.by_type || {});

    // Update logs
    renderLogs(logs);

  } catch (e) {
    console.log('Dashboard: backend not connected');
    document.getElementById('statTotal').textContent = '0';
    document.getElementById('statSQL').textContent = '0';
    document.getElementById('statXSS').textContent = '0';
    document.getElementById('statCSRF').textContent = '0';
    document.getElementById('statBlocked').textContent = '0';
  }
}

function renderChart(byType) {
  const chart = document.getElementById('attackChart');
  const total = Object.values(byType).reduce((a, b) => a + b, 0) || 1;

  const items = [
    { key: 'SQL_INJECTION', label: 'SQL Inject', cls: 'sql', color: 'var(--accent-red)' },
    { key: 'XSS', label: 'XSS', cls: 'xss', color: 'var(--accent-yellow)' },
    { key: 'CSRF', label: 'CSRF', cls: 'csrf', color: 'var(--accent-blue)' },
  ];

  if (total === 0) {
    chart.innerHTML = '<div style="text-align:center;color:var(--text-dim);font-family:var(--font-mono);font-size:0.78rem;padding:2rem">Run some attacks in the labs first!</div>';
    return;
  }

  chart.innerHTML = items.map(item => {
    const count = byType[item.key] || 0;
    const pct = Math.round((count / total) * 100);
    return `
      <div class="bar-item">
        <div class="bar-label">${item.label}</div>
        <div class="bar-track">
          <div class="bar-fill ${item.cls}" style="width:${pct}%">
            <span class="bar-val">${count}</span>
          </div>
        </div>
        <div style="font-family:var(--font-mono);font-size:0.72rem;color:var(--text-dim);width:36px;text-align:right">${pct}%</div>
      </div>
    `;
  }).join('');
}

function renderLogs(logs) {
  const tbody = document.getElementById('logsBody');
  const countEl = document.getElementById('logCount');

  if (!logs || !logs.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-dim);padding:3rem;font-family:var(--font-mono);font-size:0.78rem">No attacks logged yet. Try the labs!</td></tr>';
    if (countEl) countEl.textContent = '0 entries';
    return;
  }

  if (countEl) countEl.textContent = `${logs.length} entries`;

  tbody.innerHTML = logs.map((log, i) => {
    const typeClass = { SQL_INJECTION: 'sql', XSS: 'xss', CSRF: 'csrf' }[log.attack_type] || '';
    const typeLabel = { SQL_INJECTION: 'SQL Inject', XSS: 'XSS', CSRF: 'CSRF' }[log.attack_type] || log.attack_type;
    const time = new Date(log.created_at).toLocaleString();
    const payload = esc(String(log.payload || '').substring(0, 60));

    return `<tr>
      <td style="color:var(--text-dim)">${log.id}</td>
      <td style="white-space:nowrap">${time}</td>
      <td><span class="badge ${typeClass}">${typeLabel}</span></td>
      <td>${esc(log.ip_address || '127.0.0.1')}</td>
      <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(log.payload || '')}">${payload}</td>
      <td style="font-size:0.72rem;color:var(--text-dim)">${esc(log.endpoint || '')}</td>
      <td><span class="badge ${log.status}">${log.status}</span></td>
    </tr>`;
  }).join('');
}

async function loadLogs() {
  try {
    const res = await fetch('/dashboard/logs');
    const logs = await res.json();
    renderLogs(logs);
  } catch (e) {}
}

async function runScan() {
  const input = document.getElementById('scanInput').value;
  const resultDiv = document.getElementById('scanResult');
  const riskIndicator = document.getElementById('riskIndicator');
  const riskLevel = document.getElementById('riskLevel');
  const findings = document.getElementById('scanFindings');
  const rec = document.getElementById('scanRecommendation');

  if (!input) { alert('Enter something to scan'); return; }

  try {
    const res = await fetch('/dashboard/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input })
    });
    const data = await res.json();

    resultDiv.style.display = 'block';
    riskIndicator.className = `risk-indicator ${data.risk_level}`;
    riskLevel.className = `risk-level ${data.risk_level}`;
    riskLevel.textContent = data.risk_level;

    if (data.findings && data.findings.length) {
      findings.innerHTML = data.findings.map(f => `
        <div class="finding-item">
          <span class="badge ${f.type === 'XSS' ? 'xss' : 'sql'}">${f.type}</span>
          <span class="finding-type" style="color:${f.severity === 'HIGH' ? 'var(--accent-red)' : 'var(--accent-yellow)'}">${f.severity}</span>
          <span style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-secondary)">${f.detail}</span>
        </div>
      `).join('');
    } else {
      findings.innerHTML = '<div style="font-family:var(--font-mono);font-size:0.78rem;color:var(--accent-green)">✅ No issues detected</div>';
    }

    rec.textContent = `💡 ${data.recommendation}`;

  } catch (e) {
    resultDiv.style.display = 'block';
    riskLevel.textContent = 'ERROR';
    findings.innerHTML = '<div style="color:var(--accent-red);font-family:var(--font-mono);font-size:0.78rem">Cannot connect to server. Start FastAPI first.</div>';
  }
}

// Enter key for scanner
document.getElementById('scanInput')?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') runScan();
});

// Auto-refresh every 15s
document.addEventListener('DOMContentLoaded', () => {
  loadStats();
  setInterval(loadStats, 15000);
});
