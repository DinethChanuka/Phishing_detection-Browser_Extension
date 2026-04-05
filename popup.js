// popup.js
'use strict';

async function updateStats() {
  const stats = await new Promise(resolve => chrome.runtime.sendMessage({ type: 'getStats' }, resolve));
  if (!stats) return;
  const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val ?? 0; };
  set('redCount', stats.red);
  set('yellowCount', stats.yellow);
  set('greenCount', stats.green);
  set('totalCount', stats.total);
}

function checkConnection() {
  const msg = document.getElementById('statusMsg');
  if (!msg) return;
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || !tabs[0]) {
      msg.textContent = '⚠️ No active tab found.';
      msg.className = 'status-bar warn';
      return;
    }
    chrome.tabs.sendMessage(tabs[0].id, { type: 'ping' }, (response) => {
      if (chrome.runtime.lastError || !response || response.status !== 'ok') {
        msg.textContent = '⚠️ Not connected — refresh Gmail / Outlook.';
        msg.className = 'status-bar warn';
      } else {
        msg.textContent = '✅ Active & protecting your inbox';
        msg.className = 'status-bar';
      }
    });
  });
}

document.getElementById('scanBtn').addEventListener('click', () => {
  const msg = document.getElementById('statusMsg');
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || !tabs[0]) return;
    chrome.tabs.sendMessage(tabs[0].id, { type: 'forceScan' }, (response) => {
      if (chrome.runtime.lastError || !response || response.status !== 'ok') {
        if (msg) { msg.textContent = '⚠️ Could not scan — refresh the page first.'; msg.className = 'status-bar warn'; }
      } else {
        if (msg) { msg.textContent = '✅ Scan triggered!'; msg.className = 'status-bar'; }
        setTimeout(updateStats, 600);
      }
    });
  });
});

document.getElementById('optionsBtn').addEventListener('click', () => {
  chrome.runtime.openOptionsPage();
});

checkConnection();
updateStats();