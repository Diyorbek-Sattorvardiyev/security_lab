// SQL Injection Lab JS

function fillPayload(fieldId, text) {
  document.getElementById(fieldId).value = text;
  // Update query preview
  updateQueryPreview(text);
}

function updateQueryPreview(username) {
  const el = document.getElementById('vulnQuery');
  if (el) {
    el.innerHTML = `SELECT * FROM users WHERE username='<span style="color:#fff;background:rgba(255,51,102,0.3);padding:0.1rem 0.2rem">${escapeHtml(username)}</span>' AND password='...'`;
  }
}

function escapeHtml(text) {
  return text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

document.getElementById('vulnUser')?.addEventListener('input', (e) => {
  updateQueryPreview(e.target.value);
});

async function tryVulnLogin() {
  const username = document.getElementById('vulnUser').value;
  const password = document.getElementById('vulnPass').value || 'anything';
  const resultBox = document.getElementById('vulnResult');

  if (!username) {
    alert('Enter a username or payload first');
    return;
  }

  updateQueryPreview(username);

  try {
    const res = await fetch('/lab/sql/login-vulnerable', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();

    if (data.attack_detected) {
      resultBox.className = 'result-box show attack';
      resultBox.querySelector('.result-header').textContent = '🚨 ATTACK SUCCESSFUL';
      resultBox.querySelector('.result-body').innerHTML = `
        <strong style="color:var(--accent-red)">${data.message}</strong><br><br>
        <strong>Query executed:</strong><br>
        <code style="color:#ffb3c1;word-break:break-all">${escapeHtml(data.query || '')}</code><br><br>
        <strong>Vulnerability:</strong> ${data.vulnerability || ''}
      `;
    } else if (data.success) {
      resultBox.className = 'result-box show neutral';
      resultBox.querySelector('.result-header').textContent = '✓ LOGIN SUCCESS';
      resultBox.querySelector('.result-body').textContent = data.message;
    } else {
      resultBox.className = 'result-box show neutral';
      resultBox.querySelector('.result-header').textContent = '✗ LOGIN FAILED';
      resultBox.querySelector('.result-body').textContent = data.message || data.error || 'Invalid credentials';
    }
  } catch (e) {
    resultBox.className = 'result-box show attack';
    resultBox.querySelector('.result-header').textContent = 'ERROR';
    resultBox.querySelector('.result-body').textContent = 'Cannot connect to server. Make sure FastAPI is running.';
  }

  loadLogs();
}

async function trySecureLogin() {
  const username = document.getElementById('secUser').value;
  const password = document.getElementById('secPass').value || 'anything';
  const resultBox = document.getElementById('secResult');

  if (!username) {
    alert('Enter a username or payload first');
    return;
  }

  try {
    const res = await fetch('/lab/sql/login-secure', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();

    if (data.blocked) {
      resultBox.className = 'result-box show blocked';
      resultBox.querySelector('.result-header').textContent = '🛡️ ATTACK BLOCKED';
      resultBox.querySelector('.result-body').innerHTML = `
        <strong style="color:var(--accent-green)">${data.message}</strong><br><br>
        <strong>Defense:</strong> ${data.defense || 'Parameterized queries'}
      `;
    } else if (data.success) {
      resultBox.className = 'result-box show blocked';
      resultBox.querySelector('.result-header').textContent = '✓ SECURE LOGIN';
      resultBox.querySelector('.result-body').textContent = data.message;
    } else {
      resultBox.className = 'result-box show neutral';
      resultBox.querySelector('.result-header').textContent = '✗ LOGIN FAILED (Safe)';
      resultBox.querySelector('.result-body').textContent = data.message || 'Invalid credentials - but system is safe';
    }
  } catch (e) {
    resultBox.className = 'result-box show neutral';
    resultBox.querySelector('.result-header').textContent = 'ERROR';
    resultBox.querySelector('.result-body').textContent = 'Cannot connect to server. Make sure FastAPI is running.';
  }

  loadLogs();
}

async function loadLogs() {
  try {
    const res = await fetch('/lab/sql/logs');
    const logs = await res.json();
    const tbody = document.getElementById('logsBody');

    if (!logs.length) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-dim);padding:2rem;font-family:var(--font-mono);font-size:0.78rem">No attacks logged yet.</td></tr>';
      return;
    }

    tbody.innerHTML = logs.map(log => `
      <tr>
        <td>${new Date(log.created_at).toLocaleTimeString()}</td>
        <td>${log.ip_address}</td>
        <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHtml(log.payload)}">${escapeHtml(log.payload)}</td>
        <td><span class="badge ${log.status}">${log.status}</span></td>
      </tr>
    `).join('');
  } catch (e) {
    console.log('Could not load logs');
  }
}

// Load logs on page load
document.addEventListener('DOMContentLoaded', loadLogs);
