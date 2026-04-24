// ============================================
//   WEB SECURITY LAB - Main JavaScript
// ============================================

const API = '';

// ===== MODAL SYSTEM =====
function openModal(id) {
  document.getElementById(id).classList.add('active');
}

function closeModal(id) {
  document.getElementById(id).classList.remove('active');
}

// ===== AUTH =====
async function doLogin() {
  const username = document.getElementById('loginUser').value.trim();
  const password = document.getElementById('loginPass').value;
  const msgEl = document.getElementById('loginMsg');

  if (!username || !password) {
    showMsg(msgEl, 'Fill all fields', 'error');
    return;
  }

  try {
    const res = await fetch(`${API}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
      credentials: 'include'
    });
    const data = await res.json();

    if (res.ok) {
      showMsg(msgEl, `✅ Welcome, ${data.username}!`, 'success');
      localStorage.setItem('user', JSON.stringify(data));
      setTimeout(() => {
        closeModal('loginModal');
        updateNavAuth(data);
      }, 1000);
    } else {
      showMsg(msgEl, `❌ ${data.detail || 'Login failed'}`, 'error');
    }
  } catch (e) {
    showMsg(msgEl, '❌ Connection error', 'error');
  }
}

async function doRegister() {
  const username = document.getElementById('regUser').value.trim();
  const email = document.getElementById('regEmail').value.trim();
  const password = document.getElementById('regPass').value;
  const msgEl = document.getElementById('regMsg');

  if (!username || !email || !password) {
    showMsg(msgEl, 'Fill all fields', 'error');
    return;
  }

  try {
    const res = await fetch(`${API}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password }),
      credentials: 'include'
    });
    const data = await res.json();

    if (res.ok) {
      showMsg(msgEl, `✅ Account created! Welcome, ${data.username}!`, 'success');
      localStorage.setItem('user', JSON.stringify(data));
      setTimeout(() => {
        closeModal('registerModal');
        updateNavAuth(data);
      }, 1200);
    } else {
      showMsg(msgEl, `❌ ${data.detail || 'Registration failed'}`, 'error');
    }
  } catch (e) {
    showMsg(msgEl, '❌ Connection error', 'error');
  }
}

async function doLogout() {
  await fetch(`${API}/auth/logout`, { method: 'POST', credentials: 'include' });
  localStorage.removeItem('user');
  updateNavAuth(null);
}

function updateNavAuth(user) {
  const navAuth = document.getElementById('navAuth');
  if (!navAuth) return;

  if (user) {
    navAuth.innerHTML = `
      <span style="font-family:var(--font-mono);font-size:0.78rem;color:var(--accent-green)">
        ⬡ ${user.username}
      </span>
      <button class="btn-ghost" onclick="doLogout()">Logout</button>
    `;
  } else {
    navAuth.innerHTML = `
      <button class="btn-ghost" onclick="openModal('loginModal')">Login</button>
      <button class="btn-primary" onclick="openModal('registerModal')">Register</button>
    `;
  }
}

// ===== HELPERS =====
function showMsg(el, msg, type) {
  if (!el) return;
  el.textContent = msg;
  el.className = `msg-area show ${type}`;
}

function showResult(boxId, data, type) {
  const box = document.getElementById(boxId);
  if (!box) return;

  box.className = `result-box show ${type}`;
  const body = box.querySelector('.result-body');
  if (body) {
    body.innerHTML = formatResult(data);
  }
}

function formatResult(data) {
  if (typeof data === 'string') return data;
  return Object.entries(data)
    .map(([k, v]) => {
      if (typeof v === 'object') return `<strong>${k}:</strong> ${JSON.stringify(v)}`;
      return `<strong>${k}:</strong> ${v}`;
    })
    .join('<br>');
}

// ===== KEYBOARD SHORTCUTS =====
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal.active').forEach(m => m.classList.remove('active'));
  }
});

// ===== INIT =====
document.addEventListener('DOMContentLoaded', () => {
  const user = JSON.parse(localStorage.getItem('user') || 'null');
  if (user) updateNavAuth(user);

  // Animate terminal typing effect
  const terminal = document.getElementById('terminalBody');
  if (terminal) {
    const lines = terminal.querySelectorAll('.term-line');
    lines.forEach((line, i) => {
      line.style.opacity = '0';
      setTimeout(() => {
        line.style.opacity = '1';
        line.style.animation = 'fadeInUp 0.3s ease forwards';
      }, i * 400);
    });
  }
});
