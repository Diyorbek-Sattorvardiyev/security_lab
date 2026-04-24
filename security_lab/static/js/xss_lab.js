// XSS Lab JS

function fillXSS(fieldId, text) {
  document.getElementById(fieldId).value = text;
}

function escHtml(t) {
  return t.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function renderComment(c, unsafe = false) {
  const div = document.createElement('div');
  div.style.cssText = 'background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.06);border-radius:8px;padding:0.75rem 1rem;';
  const header = `<div style="display:flex;justify-content:space-between;margin-bottom:0.4rem">
    <span style="font-family:var(--font-mono);font-size:0.72rem;color:var(--accent-green)">${escHtml(c.username || 'anon')}</span>
    <span style="font-family:var(--font-mono);font-size:0.68rem;color:var(--text-dim)">${new Date(c.created_at || Date.now()).toLocaleTimeString()}</span>
  </div>`;

  if (unsafe) {
    // ⚠️ INTENTIONALLY DANGEROUS for demo
    div.innerHTML = header + `<div style="font-size:0.88rem;color:var(--text-secondary)">${c.comment}</div>`;
  } else {
    div.innerHTML = header + `<div style="font-size:0.88rem;color:var(--text-secondary)">${escHtml(c.comment)}</div>`;
  }
  return div;
}

async function postVulnComment() {
  const comment = document.getElementById('vulnComment').value;
  const username = document.getElementById('vulnName').value || 'anonymous';
  const resultBox = document.getElementById('vulnXssResult');

  if (!comment) { alert('Write something first!'); return; }

  try {
    const res = await fetch('/lab/xss/comment-vulnerable', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ comment, username })
    });
    const data = await res.json();

    if (data.attack_detected) {
      resultBox.className = 'result-box show attack';
      resultBox.querySelector('.result-header').textContent = '🚨 XSS EXECUTED';
      resultBox.querySelector('.result-body').innerHTML = `
        <strong style="color:var(--accent-red)">${data.message}</strong><br><br>
        <strong>Stored payload:</strong><br>
        <code style="color:#ffb3c1">${escHtml(data.comment || '')}</code><br><br>
        <strong>Impact:</strong> ${data.vulnerability || ''}
      `;
      // Actually execute the XSS for demo effect
      const container = document.getElementById('vulnCommentsRender');
      container.innerHTML = '';
      const fakeComment = { username, comment: comment, created_at: new Date().toISOString() };
      container.appendChild(renderComment(fakeComment, true));
    } else if (data.comments) {
      resultBox.className = 'result-box show neutral';
      resultBox.querySelector('.result-header').textContent = '✓ COMMENT POSTED';
      resultBox.querySelector('.result-body').textContent = data.message;

      const container = document.getElementById('vulnCommentsRender');
      container.innerHTML = '';
      data.comments.forEach(c => container.appendChild(renderComment(c, true)));
    }
  } catch (e) {
    resultBox.className = 'result-box show attack';
    resultBox.querySelector('.result-header').textContent = 'ERROR';
    resultBox.querySelector('.result-body').textContent = 'Cannot connect to server.';
  }
}

async function postSecureComment() {
  const comment = document.getElementById('secComment').value;
  const username = document.getElementById('secName').value || 'anonymous';
  const resultBox = document.getElementById('secXssResult');

  if (!comment) { alert('Write something first!'); return; }

  try {
    const res = await fetch('/lab/xss/comment-secure', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ comment, username })
    });
    const data = await res.json();

    if (data.blocked) {
      resultBox.className = 'result-box show blocked';
      resultBox.querySelector('.result-header').textContent = '🛡️ XSS BLOCKED';
      resultBox.querySelector('.result-body').innerHTML = `
        <strong style="color:var(--accent-green)">${data.message}</strong><br><br>
        <strong>Original:</strong> <code style="color:#ffb3c1">${escHtml(data.original || '')}</code><br>
        <strong>Sanitized:</strong> <code style="color:#b3ffda">${escHtml(data.sanitized || '')}</code><br><br>
        <strong>Defense:</strong> ${data.defense || ''}
      `;
    } else if (data.comments) {
      resultBox.className = 'result-box show blocked';
      resultBox.querySelector('.result-header').textContent = '✓ SAFE COMMENT POSTED';
      resultBox.querySelector('.result-body').textContent = data.message;

      const container = document.getElementById('secCommentsRender');
      container.innerHTML = '';
      data.comments.forEach(c => container.appendChild(renderComment(c, false)));
    }
  } catch (e) {
    resultBox.className = 'result-box show neutral';
    resultBox.querySelector('.result-header').textContent = 'ERROR';
    resultBox.querySelector('.result-body').textContent = 'Cannot connect to server.';
  }
}

document.addEventListener('DOMContentLoaded', async () => {
  try {
    const res = await fetch('/lab/xss/comments');
    const data = await res.json();

    const vulnContainer = document.getElementById('vulnCommentsRender');
    const secContainer = document.getElementById('secCommentsRender');

    if (data.unsafe?.length) {
      vulnContainer.innerHTML = '';
      data.unsafe.forEach(c => vulnContainer.appendChild(renderComment(c, true)));
    }
    if (data.safe?.length) {
      secContainer.innerHTML = '';
      data.safe.forEach(c => secContainer.appendChild(renderComment(c, false)));
    }
  } catch (e) {}
});
