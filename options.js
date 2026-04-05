// options.js
async function loadLists() {
  const { whitelist = [], blacklist = [] } = await chrome.storage.local.get(['whitelist', 'blacklist']);
  const whitelistDiv = document.getElementById('whitelistContainer');
  whitelistDiv.innerHTML = whitelist.map(d => `<div class="list-item">${escapeHtml(d)}<button class="remove-btn" data-domain="${escapeHtml(d)}" data-list="whitelist">✖</button></div>`).join('');
  const blacklistDiv = document.getElementById('blacklistContainer');
  blacklistDiv.innerHTML = blacklist.map(d => `<div class="list-item">${escapeHtml(d)}<button class="remove-btn" data-domain="${escapeHtml(d)}" data-list="blacklist">✖</button></div>`).join('');
  document.querySelectorAll('.remove-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const domain = btn.dataset.domain;
      const list = btn.dataset.list;
      const current = await chrome.storage.local.get([list]);
      const updated = current[list].filter(d => d !== domain);
      await chrome.storage.local.set({ [list]: updated });
      loadLists();
    });
  });
}

function escapeHtml(str) { return str.replace(/[&<>]/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[m])); }

document.getElementById('saveSettings').addEventListener('click', () => {
  const sensitivity = document.getElementById('sensitivity').value;
  const showLabels = document.getElementById('showLabels').checked;
  chrome.storage.sync.set({ sensitivity, showLabels }, () => alert('Settings saved'));
});

document.getElementById('clearCache').addEventListener('click', () => {
  chrome.runtime.sendMessage({ type: "clearCache" }, () => alert('Threat cache cleared'));
});

document.getElementById('addWhitelist').addEventListener('click', async () => {
  const domain = document.getElementById('whitelistInput').value.trim().toLowerCase();
  if (!domain) return;
  const { whitelist = [] } = await chrome.storage.local.get(['whitelist']);
  if (!whitelist.includes(domain)) {
    whitelist.push(domain);
    await chrome.storage.local.set({ whitelist });
    loadLists();
  }
  document.getElementById('whitelistInput').value = '';
});

document.getElementById('addBlacklist').addEventListener('click', async () => {
  const domain = document.getElementById('blacklistInput').value.trim().toLowerCase();
  if (!domain) return;
  const { blacklist = [] } = await chrome.storage.local.get(['blacklist']);
  if (!blacklist.includes(domain)) {
    blacklist.push(domain);
    await chrome.storage.local.set({ blacklist });
    loadLists();
  }
  document.getElementById('blacklistInput').value = '';
});

chrome.storage.sync.get(['sensitivity', 'showLabels'], (data) => {
  if (data.sensitivity) document.getElementById('sensitivity').value = data.sensitivity;
  if (data.showLabels !== undefined) document.getElementById('showLabels').checked = data.showLabels;
});

loadLists();