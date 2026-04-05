// content.js - Persistent risk labels with mutation observer reset fix
'use strict';
const DEBUG = false;
function log(...args) { if (DEBUG) console.log("[EmailGuard]", ...args); }

let processedRowIds = new Set();
let processedLinks = new WeakSet();
let currentSenderDomain = null;
let currentSenderEmail = null;
let activeWarnings = new WeakSet();
let showLabels = true;
let emailAnalysisCache = new Map(); // rowId -> {risk, score, components}
let scanTimeout = null;
let urlCheckInterval = null;

chrome.storage.sync.get(['showLabels'], (data) => { showLabels = data.showLabels !== false; });

function extractDomain(email) {
  const match = email.match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  return match ? match[1] : null;
}

function extractUrlsFromText(text) {
  const urlRegex = /https?:\/\/[^\s<>"']+/g;
  return (text.match(urlRegex) || []);
}

function getRowUniqueId(row, emailData) {
  const threadId = row.getAttribute('data-thread-id') || row.getAttribute('data-message-id');
  if (threadId) return `thread:${threadId}`;
  const str = `${emailData.senderEmail}|${emailData.subject}|${emailData.snippet.slice(0,100)}`;
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return `hash:${hash}`;
}

function extractEmailData(row) {
  let senderEl = row.querySelector('.yP, .zF, .bog, .gD, .go');
  let subjectEl = row.querySelector('.bog, .bqe, .y6, .xS, .iD');
  let snippetEl = row.querySelector('.y2, .y6, .H7, .xW, .iG');
  if (!senderEl) senderEl = row.querySelector('[data-app-share-remnant] .ms-font-weight-regular, ._1PqC5');
  if (!subjectEl) subjectEl = row.querySelector('.mail-message-subject, ._2rXzJ');
  if (!snippetEl) snippetEl = row.querySelector('.mail-message-snippet, ._1tLrH');
  const senderText = senderEl?.innerText || "";
  const senderEmail = senderText.match(/[^\s]+@[^\s]+/)?.[0] || "";
  const senderDomain = extractDomain(senderEmail) || "";
  const subject = subjectEl?.innerText || "";
  const snippet = snippetEl?.innerText || "";
  const snippetUrls = extractUrlsFromText(snippet);
  const linksFromRow = Array.from(row.querySelectorAll('a[href^="http"]'));
  const linkUrls = [...new Set([...linksFromRow.map(l => l.href), ...snippetUrls])];
  const emailData = { rowId: `row-${Date.now()}-${Math.random()}`, senderDomain, senderEmail, subject, snippet, linkUrls };
  const rowId = getRowUniqueId(row, emailData);
  emailData.uniqueRowId = rowId;
  return { row, emailData, rowId };
}

async function analyzeAndLabelRows() {
  try {
    const rows = [...document.querySelectorAll('.zA, .zE, .mail-list-item, [role="row"]')];
    const rowsToAnalyze = rows.filter(row => {
      const { rowId } = extractEmailData(row);
      return !processedRowIds.has(rowId);
    });
    if (rowsToAnalyze.length === 0) return;
    
    const emailsData = [];
    for (const row of rowsToAnalyze) {
      const { emailData, rowId } = extractEmailData(row);
      if (!emailData.senderDomain && !emailData.subject && emailData.linkUrls.length === 0) continue;
      emailsData.push({ row, emailData, rowId });
    }
    if (emailsData.length === 0) return;
    
    const allLinkUrls = [...new Set(emailsData.flatMap(e => e.emailData.linkUrls))];
    const linkScoreMap = new Map();
    if (allLinkUrls.length) {
      const linkBatch = allLinkUrls.map((url, idx) => ({ 
        elementId: `temp-${idx}`, 
        url,
        senderDomain: emailsData[0]?.emailData.senderDomain,
        linkText: null
      }));
      const response = await new Promise(resolve => chrome.runtime.sendMessage({ type: "analyzeLinks", links: linkBatch }, resolve));
      if (response?.results) {
        for (const [id, { score }] of response.results) {
          const url = linkBatch.find(l => l.elementId === id)?.url;
          if (url) linkScoreMap.set(url, score);
        }
      }
    }
    
    const emailsForBg = emailsData.map(({ emailData }) => ({
      ...emailData,
      linkScores: emailData.linkUrls.map(url => linkScoreMap.get(url) || 0)
    }));
    
    const response = await new Promise(resolve => chrome.runtime.sendMessage({ type: "analyzeEmails", emails: emailsForBg }, resolve));
    if (response?.results) {
      for (let i = 0; i < response.results.length; i++) {
        const { risk, score, components } = response.results[i];
        const { rowId, emailData } = emailsData[i];
        emailAnalysisCache.set(rowId, { risk, score, components, linkScores: emailsForBg[i].linkScores });
        
        let currentRow = null;
        if (rowId.startsWith('thread:')) {
          const threadId = rowId.substring(7);
          currentRow = document.querySelector(`[data-thread-id="${threadId}"], [data-message-id="${threadId}"]`);
        } else {
          const rowsNow = document.querySelectorAll('.zA, .zE, .mail-list-item, [role="row"]');
          for (const r of rowsNow) {
            const { rowId: newId } = extractEmailData(r);
            if (newId === rowId) { currentRow = r; break; }
          }
        }
        if (currentRow && showLabels) {
          addTextLabel(currentRow, risk, score);
          processedRowIds.add(rowId);
        }
      }
    }
  } catch (err) {
    log("Error in analyzeAndLabelRows:", err);
  }
}

function addTextLabel(row, risk, score) {
  // Prevent duplicate labels
  if (row.querySelector('.esh-text-label')) return;
  
  const label = document.createElement('span');
  label.className = `esh-text-label esh-label-${risk}`;
  if (risk === 'red') label.textContent = ' DANGER 🚫 ';
  else if (risk === 'yellow') label.textContent = ' SUSPICIOUS ⚠️ ';
  else label.textContent = ' SAFE ✅ ';
  label.title = `Risk: ${risk.toUpperCase()} (${score}%)`;
  label.style.cssText = `display: inline-block; margin-left: 8px; padding: 2px 8px; border-radius: 20px; font-size: 11px; font-weight: 600; font-family: system-ui, sans-serif; white-space: nowrap; cursor: pointer; transition: all 0.2s; background: ${risk === 'red' ? '#e53935' : risk === 'yellow' ? '#ffb300' : '#43a047'}; color: ${risk === 'yellow' ? '#1e1e1e' : 'white'};`;
  label.onclick = (e) => { e.stopPropagation(); alert(`Risk: ${risk.toUpperCase()} (${score}%)\nBased on sender, keywords, and links.`); };
  
  let rightCell = row.querySelector('.yW, .xW, .zA > td:last-child, .mail-list-item-cell:last-child, .ms-ListItem-primary');
  if (rightCell) rightCell.appendChild(label);
  else row.appendChild(label);
}

function refreshAllLabels() {
  const rows = document.querySelectorAll('.zA, .zE, .mail-list-item, [role="row"]');
  rows.forEach(row => { 
    if (!row.querySelector('.esh-text-label')) {
      // Re-analyze rows without labels
      const { rowId, emailData } = extractEmailData(row);
      if (!processedRowIds.has(rowId)) {
        analyzeAndLabelRows().catch(e => log(e));
      }
    }
  });
}

function scanEmailContainer(container) {
  const links = container.querySelectorAll('a[href^="http"]');
  if (!links.length) return;
  const batch = [];
  for (let link of links) {
    if (processedLinks.has(link)) continue;
    processedLinks.add(link);
    const id = `link-${Date.now()}-${Math.random()}`;
    link.setAttribute('data-esh-id', id);
    
    // Extract link text for mismatch detection
    const linkText = link.innerText || link.textContent || '';
    batch.push({ 
      elementId: id, 
      url: link.href,
      senderDomain: currentSenderDomain,
      linkText: linkText
    });
    addLinkBadge(link);
  }
  if (!batch.length) return;
  chrome.runtime.sendMessage({ type: "analyzeLinks", links: batch }, (response) => {
    if (response?.results) {
      for (let [id, { risk, score }] of response.results) {
        let link = document.querySelector(`a[data-esh-id="${id}"]`);
        if (link) updateLinkBadge(link, risk, score);
      }
    }
  });
}

function addLinkBadge(link) {
  let badge = link.nextSibling?.classList?.contains('esh-link-badge') ? link.nextSibling : null;
  if (!badge) badge = link.previousSibling?.classList?.contains('esh-link-badge') ? link.previousSibling : null;
  if (!badge) {
    badge = document.createElement('span');
    badge.className = 'esh-link-badge esh-link-gray';
    badge.textContent = '';
    link.insertAdjacentElement('afterend', badge);
  }
  return badge;
}

function updateLinkBadge(link, risk, score) {
  const badge = addLinkBadge(link);
  badge.className = `esh-link-badge esh-link-${risk}`;
  badge.title = `${risk.toUpperCase()} risk (${score}%)\nURL: ${link.href}`;
  badge.onclick = (e) => { e.stopPropagation(); alert(`Link risk: ${risk.toUpperCase()} (${score}%)\nURL: ${link.href}`); };
}

async function showEmailSummary() {
  try {
    const container = document.querySelector('.a3s, .ii.gt, .adn, .msg-body, [role="article"]');
    if (!container) return;
    
    // Try to find cached analysis for this open email
    const openThreadId = document.querySelector('[data-thread-id]')?.getAttribute('data-thread-id');
    let cached = null;
    if (openThreadId) cached = emailAnalysisCache.get(`thread:${openThreadId}`);
    if (cached) {
      addSummaryPanel(container, cached.risk, cached.score, cached.components);
      return;
    }
    
    // Otherwise re-analyze (should be rare)
    const links = Array.from(container.querySelectorAll('a[href^="http"]'));
    const linkUrls = links.map(l => l.href);
    let linkScores = [];
    if (linkUrls.length) {
      const batch = linkUrls.map((url, i) => ({ 
        elementId: `temp-${i}`, 
        url,
        senderDomain: currentSenderDomain,
        linkText: links[i]?.innerText || ''
      }));
      const resp = await new Promise(resolve => chrome.runtime.sendMessage({ type: "analyzeLinks", links: batch }, resolve));
      if (resp?.results) linkScores = resp.results.map(r => r[1].score);
    }
    const emailData = {
      rowId: 'summary',
      senderDomain: currentSenderDomain || '',
      senderEmail: currentSenderEmail || '',
      subject: document.querySelector('h2, .hP, .mail-message-subject')?.innerText || '',
      snippet: container.innerText.slice(0, 500),
      linkScores,
      linkUrls
    };
    const response = await new Promise(resolve => chrome.runtime.sendMessage({ type: "analyzeEmails", emails: [emailData] }, resolve));
    if (response?.results?.[0]) {
      const { risk, score, components } = response.results[0];
      addSummaryPanel(container, risk, score, components);
    }
  } catch (err) {
    log("Error in showEmailSummary:", err);
  }
}

function addSummaryPanel(container, risk, score, components) {
  let existing = document.querySelector('.esh-summary-panel');
  if (existing) existing.remove();
  const panel = document.createElement('div');
  panel.className = `esh-summary-panel esh-summary-${risk}`;
  panel.innerHTML = `<div class="esh-summary-header"><span>📊 Email Security Summary</span><span class="esh-summary-risk">${risk.toUpperCase()} (${score}%)</span></div><div class="esh-summary-scorebar"><div style="width:${score}%; background:${risk === 'red' ? '#e53935' : risk === 'yellow' ? '#ffb300' : '#43a047'}"></div></div><div class="esh-summary-details"><div>📧 Sender reputation: ${components.senderScore}%</div><div>🔑 Keyword analysis: ${components.keywordScore}%</div><div>🔗 Link risk: ${components.linkScore}%</div></div><div class="esh-summary-footer">⚠️ Be careful with links and password requests.</div>`;
  container.insertAdjacentElement('afterbegin', panel);
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function updateSenderDomain() {
  try {
    const gmailSender = document.querySelector('.gD, .go, .hG, [email], .sender');
    if (gmailSender) {
      const email = gmailSender.getAttribute('email') || gmailSender.innerText;
      currentSenderEmail = email;
      currentSenderDomain = extractDomain(email);
    }
    const outlookSender = document.querySelector('[title*="@"]');
    if (outlookSender) {
      const email = outlookSender.getAttribute('title');
      currentSenderEmail = email;
      currentSenderDomain = extractDomain(email);
    }
    if (currentSenderDomain) log("Sender:", currentSenderDomain);
    setTimeout(() => showEmailSummary(), 300);
  } catch (err) {
    log("Error in updateSenderDomain:", err);
  }
}

function monitorPasswordFields() {
  document.addEventListener('focusin', (e) => {
    if (e.target.type === 'password' && !activeWarnings.has(e.target)) {
      const pageDomain = location.hostname.replace(/^www\./, '');
      if (currentSenderDomain && !pageDomain.includes(currentSenderDomain) && pageDomain !== currentSenderDomain) {
        showPhishingWarning(pageDomain, currentSenderDomain);
        activeWarnings.add(e.target);
      }
    }
  });
}

function showPhishingWarning(pageDomain, senderDomain) {
  let toast = document.querySelector('.esh-warning-toast');
  if (toast) toast.remove();
  toast = document.createElement('div');
  toast.className = 'esh-warning-toast';
  toast.innerHTML = `<div>⚠️</div><div><strong>Domain mismatch!</strong><br>${pageDomain} ≠ ${senderDomain}<br>Typing password risky.</div><div><button class="esh-toast-continue">Continue</button><button class="esh-toast-dismiss">Dismiss</button></div>`;
  document.body.appendChild(toast);
  toast.querySelector('.esh-toast-continue')?.addEventListener('click', () => toast.remove());
  toast.querySelector('.esh-toast-dismiss')?.addEventListener('click', () => toast.remove());
  setTimeout(() => toast.remove(), 10000);
}

// FIXED: Simplified URL change watcher without setInterval issues
function watchForUrlChange() {
  let lastUrl = location.href;
  
  // Use a function that can be called repeatedly
  function checkUrlChange() {
    try {
      if (location.href !== lastUrl) {
        lastUrl = location.href;
        log("URL changed, resetting state");
        processedRowIds.clear();
        setTimeout(() => {
          updateSenderDomain();
          analyzeAndLabelRows();
          scanOpenedEmails();
        }, 300);
      }
    } catch (err) {
      log("Error checking URL change:", err);
    }
  }
  
  // Set up interval safely
  if (urlCheckInterval) {
    clearInterval(urlCheckInterval);
  }
  urlCheckInterval = setInterval(checkUrlChange, 500);
}

function scanOpenedEmails() {
  try {
    document.querySelectorAll('.a3s, .ii.gt, .adn, .msg-body, [role="article"]').forEach(scanEmailContainer);
  } catch (err) {
    log("Error in scanOpenedEmails:", err);
  }
}

// Debounced scan function
function scheduleScan() {
  if (scanTimeout) clearTimeout(scanTimeout);
  scanTimeout = setTimeout(() => {
    try {
      // Don't clear processedRowIds here - we want to preserve labels
      // Only re-analyze rows that don't have labels
      const rows = document.querySelectorAll('.zA, .zE, .mail-list-item, [role="row"]');
      let needsAnalysis = false;
      for (const row of rows) {
        if (!row.querySelector('.esh-text-label')) {
          const { rowId } = extractEmailData(row);
          if (!processedRowIds.has(rowId)) {
            needsAnalysis = true;
            break;
          }
        }
      }
      if (needsAnalysis) {
        analyzeAndLabelRows();
      }
      scanOpenedEmails();
    } catch (err) {
      log("Error in scheduleScan:", err);
    }
  }, 300);
}

// Message handler
chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
  if (req.type === "forceScan") { 
    processedRowIds.clear();
    analyzeAndLabelRows(); 
    scanOpenedEmails(); 
    sendResponse({ status: "ok" }); 
    return true; 
  }
  if (req.type === "ping") { 
    sendResponse({ status: "ok" }); 
    return true; 
  }
  return false;
});

// Clean up function for page unload
function cleanup() {
  if (urlCheckInterval) {
    clearInterval(urlCheckInterval);
    urlCheckInterval = null;
  }
  if (scanTimeout) {
    clearTimeout(scanTimeout);
    scanTimeout = null;
  }
}

// Initialize
function init() {
  log("Content script ready (final optimized with label persistence fix)");
  
  // Clean up any existing intervals before starting new ones
  cleanup();
  
  updateSenderDomain();
  analyzeAndLabelRows();
  scanOpenedEmails();
  
  // MutationObserver with debounce
  const observer = new MutationObserver(() => scheduleScan());
  observer.observe(document.body, { childList: true, subtree: true });
  
  monitorPasswordFields();
  watchForUrlChange();
  
  document.addEventListener('click', () => {
    setTimeout(() => { 
      updateSenderDomain(); 
      scanOpenedEmails(); 
    }, 200);
  });
  
  chrome.storage.onChanged.addListener((changes) => { 
    if (changes.showLabels) showLabels = changes.showLabels.newValue; 
  });
  
  // Periodic refresh to catch any missed labels
  setInterval(() => refreshAllLabels(), 8000);
  
  // Clean up on page unload
  window.addEventListener('beforeunload', cleanup);
}

// Start the extension
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}