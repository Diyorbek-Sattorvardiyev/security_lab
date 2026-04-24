// CSRF Lab JS

let csrfToken = null;
let sessionId = null;

async function loadCsrfToken() {
  try {
    const res = await fetch('/lab/csrf/token', { credentials: 'include' });
    const data = await res.json();
    csrfToken = data.csrf_token;
    sessionId = data.session_id;
    const display = document.getElementById('csrfTokenDisplay');
    if (display) {
      display.textContent = csrfToken.substring(0, 32) + '...' + csrfToken.substring(csrfToken.length - 8);
    }
  } catch (e) {
    const display = document.getElementById('csrfTokenDisplay');
    if (display) display.textContent = 'Connect FastAPI server first';
  }
}

async function tryCsrfAttack() {
  const email = document.getElementById('vulnEmail').value;
  const bio = document.getElementById('vulnBio').value;
  const resultBox = document.getElementById('vulnCsrfResult');

  try {
    const res = await fetch('/lab/csrf/update-vulnerable', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'origin': 'http://evil.com'  // Simulating cross-origin
      },
      body: JSON.stringify({ email, bio, user_id: 1 })
    });
    const data = await res.json();

    if (data.attack_detected) {
      resultBox.className = 'result-box show attack';
      resultBox.querySelector('.result-header').textContent = '🚨 CSRF ATTACK SUCCESSFUL';
      resultBox.querySelector('.result-body').innerHTML = `
        <strong style="color:var(--accent-red)">${data.message}</strong><br><br>
        <strong>Email changed to:</strong> ${data.updated_email || email}<br><br>
        <strong>Vulnerability:</strong> ${data.vulnerability || 'No CSRF protection'}
      `;
    } else {
      resultBox.className = 'result-box show neutral';
      resultBox.querySelector('.result-header').textContent = '✓ REQUEST PROCESSED';
      resultBox.querySelector('.result-body').innerHTML = `${data.message}<br><br>
        <span style="color:var(--accent-yellow)">⚠️ ${data.warning || 'No protection active'}</span>`;
    }
  } catch (e) {
    resultBox.className = 'result-box show attack';
    resultBox.querySelector('.result-header').textContent = 'ERROR';
    resultBox.querySelector('.result-body').textContent = 'Cannot connect to server. Start FastAPI first.';
  }
}

async function trySecureUpdate() {
  const email = document.getElementById('secEmail').value;
  const bio = document.getElementById('secBio').value;
  const resultBox = document.getElementById('secCsrfResult');

  if (!csrfToken) {
    resultBox.className = 'result-box show attack';
    resultBox.querySelector('.result-header').textContent = 'NO TOKEN';
    resultBox.querySelector('.result-body').textContent = 'Load CSRF token first (connect to server)';
    return;
  }

  try {
    const res = await fetch('/lab/csrf/update-secure', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, bio, csrf_token: csrfToken }),
      credentials: 'include'
    });
    const data = await res.json();

    if (data.success) {
      resultBox.className = 'result-box show blocked';
      resultBox.querySelector('.result-header').textContent = '✅ LEGITIMATE UPDATE';
      resultBox.querySelector('.result-body').innerHTML = `
        <strong style="color:var(--accent-green)">${data.message}</strong><br><br>
        <strong>Defense:</strong> ${data.defense || 'CSRF token validated'}
      `;
    } else {
      resultBox.className = 'result-box show attack';
      resultBox.querySelector('.result-header').textContent = '🛡️ BLOCKED';
      resultBox.querySelector('.result-body').textContent = data.message;
    }
  } catch (e) {
    resultBox.className = 'result-box show neutral';
    resultBox.querySelector('.result-header').textContent = 'ERROR';
    resultBox.querySelector('.result-body').textContent = 'Cannot connect to server.';
  }
}

async function tryFakeTokenUpdate() {
  const email = document.getElementById('secEmail').value;
  const bio = document.getElementById('secBio').value;
  const resultBox = document.getElementById('secCsrfResult');
  const fakeToken = 'fake_token_' + Math.random().toString(36).substring(2, 15);

  try {
    const res = await fetch('/lab/csrf/update-secure', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, bio, csrf_token: fakeToken }),
      credentials: 'include'
    });
    const data = await res.json();

    if (data.blocked) {
      resultBox.className = 'result-box show blocked';
      resultBox.querySelector('.result-header').textContent = '🛡️ FORGED TOKEN REJECTED';
      resultBox.querySelector('.result-body').innerHTML = `
        <strong style="color:var(--accent-green)">${data.message}</strong><br><br>
        <strong>Fake token used:</strong><br>
        <code style="font-size:0.72rem;color:var(--text-dim)">${fakeToken}</code><br><br>
        <strong>Defense:</strong> ${data.defense || ''}
      `;
    }
  } catch (e) {
    resultBox.className = 'result-box show neutral';
    resultBox.querySelector('.result-header').textContent = 'ERROR';
    resultBox.querySelector('.result-body').textContent = 'Cannot connect to server.';
  }
}

document.addEventListener('DOMContentLoaded', loadCsrfToken);
