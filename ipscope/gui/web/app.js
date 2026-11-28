/* IPScope desktop UI - vanilla JS SPA on top of window.pywebview.api */
'use strict';

// ------------------------------------------------------------------ icons
const svg = (d) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${d}</svg>`;
const ICONS = {
  scan: svg('<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>'),
  results: svg('<path d="M4 6h16M4 12h16M4 18h10"/>'),
  history: svg('<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5M12 7v5l3 2"/>'),
  keys: svg('<circle cx="8" cy="15" r="4"/><path d="m10.8 12.2 8.2-8.2M17 6l2 2M15 8l2 2"/>'),
  settings: svg('<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>'),
  index: svg('<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/>'),
  play: svg('<path d="m6 4 14 8-14 8z"/>'),
  stop: svg('<rect x="6" y="6" width="12" height="12" rx="1"/>'),
  file: svg('<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6"/>'),
  download: svg('<path d="M12 4v12m0 0-4-4m4 4 4-4M4 20h16"/>'),
};

// ------------------------------------------------------------------ state
const S = {
  page: 'scan',
  preset: 'default',
  meta: null,
  settings: null,
  sources: new Set(),
  targets: '',
  label: '',
  opts: {},
  logs: [],
  logCursor: 0,
  job: { state: 'idle' },
  results: { scanId: null, meta: null, filter: 'all', search: '', ip: null, roots: false, offset: 0, rows: [], total: 0,
    counts: {}, ipSearch: '', ipRows: [], ipTotal: 0, selected: new Set() },
  historyFilter: 'all',
  lastReload: 0,
};

const BUSY = ['preparing', 'running', 'stopping'];
const isBusy = () => BUSY.includes(S.job.state);
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const content = () => $('#content');

// ------------------------------------------------------------------ helpers
async function api(method, ...args) {
  const fn = window.pywebview && window.pywebview.api && window.pywebview.api[method];
  if (!fn) throw new Error('Backend not ready');
  return await fn(...args);
}

function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function errMsg(e) {
  const m = (e && (e.message || e.toString())) || 'Unknown error';
  return m.replace(/^Error:\s*/, '');
}

let toastTimer = null;
function toast(msg, kind = '') {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'show ' + kind;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.className = ''; }, kind === 'error' ? 4500 : 2600);
}

const fmtNum = (n) => Number(n || 0).toLocaleString('en-US');

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    document.execCommand('copy');
    ta.remove();
  }
}

// ------------------------------------------------------------------ modals
const modalStack = [];

function openModal(html, { onMount, onClose } = {}) {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `<div class="modal" role="dialog">${html}</div>`;
  $('#modal-root').appendChild(overlay);
  const entry = {
    el: overlay,
    close: () => {
      overlay.remove();
      const i = modalStack.indexOf(entry);
      if (i >= 0) modalStack.splice(i, 1);
      if (onClose) onClose();
    },
  };
  modalStack.push(entry);
  overlay.addEventListener('mousedown', (e) => { if (e.target === overlay) entry.close(); });
  if (onMount) onMount(overlay.querySelector('.modal'), entry);
  const first = overlay.querySelector('input:not([type=checkbox]), textarea, button.btn-accent, button.btn-red');
  if (first) setTimeout(() => first.focus(), 30);
  return entry;
}

function askConfirm(message, okLabel = 'Confirm', danger = true) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; m.close(); resolve(v); } };
    const m = openModal(`
      <div class="modal-title">${esc(okLabel)}?</div>
      <div class="modal-text">${esc(message)}</div>
      <div class="modal-actions">
        <button class="btn btn-ghost" data-act="cancel">Cancel</button>
        <button class="btn ${danger ? 'btn-red' : 'btn-accent'}" data-act="ok">${esc(okLabel)}</button>
      </div>`, {
      onMount: (el) => {
        el.querySelector('[data-act=cancel]').onclick = () => finish(false);
        el.querySelector('[data-act=ok]').onclick = () => finish(true);
      },
      onClose: () => { if (!done) { done = true; resolve(false); } },
    });
    m.confirm = () => finish(true);
  });
}

document.addEventListener('keydown', (e) => {
  const top = modalStack[modalStack.length - 1];
  if (!top) return;
  if (e.key === 'Escape') { e.preventDefault(); top.close(); }
  if (e.key === 'Enter' && e.target.tagName !== 'TEXTAREA') {
    if (top.confirm) { e.preventDefault(); top.confirm(); return; }
    const primary = top.el.querySelector('.modal-actions .btn-accent, .modal-actions .btn-red');
    if (primary) { e.preventDefault(); primary.click(); }
  }
});

// ------------------------------------------------------------------ navigation
function go(page) {
  S.page = page;
  $$('.nav-btn').forEach((b) => b.classList.toggle('active', b.dataset.page === page));
  content().scrollTop = 0;
  render();
}

function render() {
  ({ scan: renderScan, results: renderResults, history: renderHistory, index: renderIndex, keys: renderKeys, settings: renderSettings }[S.page])();
}

function header(title, subtitle, actions = '') {
  return `<div class="page-header">
    <div><div class="page-title">${esc(title)}</div><div class="page-subtitle" id="page-subtitle">${subtitle}</div></div>
    <div class="actions">${actions}</div>
  </div>`;
}

function loading(msg = 'Loading...') { return `<div class="empty-state">${esc(msg)}</div>`; }

// ================================================================== SCAN PAGE
const OPTION_DEFS = [
  ['validate', 'Validate DNS', 'Check every domain still points at the IP'],
  ['probe', 'Probe websites', 'Fetch title, server and technologies (contacts the sites)'],
  ['active', 'Contact servers directly', 'TLS certificates on 10 ports + HTTP(S) to the IP (free, finds the main site)'],
  ['use_cache', 'Use cache', 'Reuse lookups younger than the cache lifetime'],
  ['allow_private', 'Allow private IPs', 'Scan 10.x, 192.168.x and other reserved ranges'],
];

function targetCount() {
  return S.targets.split('\n').filter((l) => l.trim() && !l.trim().startsWith('#')).length;
}

const PRESET_HELP = {
  default: 'Balanced: the recommended set for everyday scans.',
  fast: 'Quickest results: only the fastest, largest data sets.',
  free: 'More results: every free data set (slower).',
  full: 'Maximum results: everything available plus direct server checks.',
  offline: 'Your local index only - instant, no internet needed.',
};
const presetLabel = (k) => k[0].toUpperCase() + k.slice(1);
const hideSrc = () => !!(S.settings && S.settings.hide_sources);

function presetTabsHtml() {
  const names = ['default', ...Object.keys(S.meta.presets || {})];
  return names.map((k) => {
    const p = k === 'default' ? { sources: [1] } : S.meta.presets[k];
    return `<button class="filter-tab ${S.preset === k ? 'active' : ''}" data-preset="${k}" ${p.sources.length ? '' : 'disabled title="Build the local index first"'}>${presetLabel(k)}</button>`;
  }).join('');
}

function modeText() {
  return S.preset ? presetLabel(S.preset) : 'Custom';
}

function applyPreset(name) {
  if (name === 'default') { setDefaultSources(); S.opts.active = !!S.settings.active; }
  else {
    const p = S.meta.presets[name];
    S.sources = new Set(p.sources);
    S.opts.active = !!p.active;
  }
  S.preset = name;
  persistSources();
}

async function persistSources() {
  try {
    S.settings = await api('save_settings', { sources: [...S.sources], preset: S.preset });
  } catch { /* not critical */ }
}

function bindPresetTabs(root, after) {
  $$('[data-preset]', root).forEach((b) => {
    b.onclick = () => {
      applyPreset(b.dataset.preset);
      after();
      toast(`Mode: ${modeText()}${S.opts.active ? ' + direct checks' : ''}`);
    };
  });
}

function renderScan() {
  const busy = isBusy();
  content().innerHTML = `
    ${header('New scan', scanSubtitle(), `
      <button class="btn btn-ghost" id="btn-import">${ICONS.file}Import file</button>
      <button class="btn ${busy ? 'btn-red' : 'btn-green'}" id="btn-scan-main">${busy ? ICONS.stop + 'Stop' : ICONS.play + 'Start scan'}</button>`)}
    <div class="split-1-2">
      <div>
        <div class="card">
          <div class="card-head"><div class="section-title">Targets</div><span class="section-sub mono" id="target-count">${targetCount()} lines</span></div>
          <textarea class="input input-mono" id="targets" rows="9" spellcheck="false"
            placeholder="8.8.8.8&#10;1.2.3.0/28&#10;AS24940&#10;example.com">${esc(S.targets)}</textarea>
          <div class="form-hint mt-8">IPs, CIDR ranges, ASNs, domains or URLs - one per line. Lines starting with # are ignored.</div>
          <div class="form-group mt-8" style="margin-bottom:0">
            <label class="form-label" for="label">Label</label>
            <input class="input" id="label" placeholder="Optional name shown in History" value="${esc(S.label)}">
          </div>
        </div>
        <div class="card">
          <div class="section-title mb-8">Options</div>
          ${OPTION_DEFS.map(([k, name, hint]) => `
            <label class="checkbox-row">
              <input type="checkbox" data-opt="${k}" ${S.opts[k] ? 'checked' : ''}>
              <span><div class="cb-text">${esc(name)}</div><div class="cb-hint">${esc(hint)}</div></span>
            </label>`).join('')}
        </div>
      </div>
      <div>
        <div class="stat-cards">
          <div class="stat-card"><div class="label">IPs</div><div class="value" id="st-ips">0<span class="of"> / 0</span></div></div>
          <div class="stat-card"><div class="label">Domains</div><div class="value" id="st-found">0</div></div>
          <div class="stat-card"><div class="label">Active</div><div class="value c-green" id="st-active">0</div></div>
          <div class="stat-card"><div class="label">Errors</div><div class="value" id="st-errors">0</div></div>
        </div>
        <div class="card">
          <div class="card-head">
            <div class="flex"><span class="dot dot-dim" id="pg-dot"></span><div class="section-title" id="pg-title">Ready</div></div>
            <div class="flex"><span class="mono c-dim" id="pg-elapsed"></span><button class="btn btn-ghost btn-xs hidden" id="pg-open">Open results</button></div>
          </div>
          <div class="health-bar lg"><div class="health-bar-fill" id="pg-bar"></div></div>
        </div>
        <div class="card">
          <div class="card-head">
            <div class="section-title">Mode</div>
            <div class="filter-tabs" id="preset-tabs">${presetTabsHtml()}</div>
          </div>
          <div class="form-hint">${esc(S.preset ? PRESET_HELP[S.preset] : 'Custom selection - change it in Settings.')}</div>
        </div>
        <div class="card">
          <div class="card-head"><div class="section-title">Log</div><button class="btn btn-ghost btn-xs" id="btn-log-clear">Clear</button></div>
          <div class="log-box" id="log-box"></div>
        </div>
      </div>
    </div>`;

  const ta = $('#targets');
  ta.oninput = () => { S.targets = ta.value; $('#target-count').textContent = `${targetCount()} lines`; };
  $('#label').oninput = (e) => { S.label = e.target.value; };
  $$('[data-opt]').forEach((cb) => { cb.onchange = () => { S.opts[cb.dataset.opt] = cb.checked; }; });
  bindPresetTabs(content(), renderScan);
  $('#btn-import').onclick = importFile;
  $('#btn-scan-main').onclick = () => (isBusy() ? stopScan() : startScan());
  $('#btn-log-clear').onclick = async () => {
    S.logs = [];
    try { await api('clear_logs'); } catch { /* ignore */ }
    drawLogs();
  };
  $('#pg-open').onclick = () => { S.results.scanId = S.job.scan_id; resetResultsView(); go('results'); };
  drawLogs();
  updateScanLive();
}

function scanSubtitle() {
  return `Mode: ${modeText()} · results are saved as each IP finishes`;
}

function updateSubtitle() {
  const sub = $('#page-subtitle');
  if (sub && S.page === 'scan') sub.textContent = scanSubtitle();
}

function sourceRow(s) {
  const locked = (s.requires_key && !s.has_key) || s.needs_index;
  const dot = s.has_key || (s.name === 'local' && !s.needs_index) ? 'dot-green' : locked ? 'dot-red' : 'dot-dim';
  const keyTag = s.name === 'local' ? (s.needs_index ? '<span class="tag yellow">no index yet</span>' : '<span class="tag green">offline</span>')
    : !s.uses_key ? '<span class="tag">free</span>'
    : s.has_key ? '<span class="tag green">key set</span>'
      : s.requires_key ? '<span class="tag yellow">key required</span>' : '<span class="tag">key optional</span>';
  return `<div class="data-row">
    <input type="checkbox" class="col-check" data-src="${esc(s.name)}" ${S.sources.has(s.name) ? 'checked' : ''} ${locked ? 'disabled' : ''}>
    <span class="col-dot"><span class="dot ${dot}"></span></span>
    <div class="flex-1">
      <div class="main mono">${esc(s.name)}</div>
      <div class="sub ellipsis">${esc(s.description)}</div>
    </div>
    ${keyTag}
    ${locked ? (s.needs_index ? '<button class="btn btn-ghost btn-xs" data-goto-index>Build index</button>' : '<button class="btn btn-ghost btn-xs" data-goto-keys>Add key</button>') : ''}
  </div>`;
}

function setDefaultSources() {
  S.sources = new Set(S.meta.sources.filter((s) => s.default && !s.active).map((s) => s.name));
}

function restoreSources() {
  // selection saved in settings, minus anything no longer usable
  const usable = new Set(S.meta.sources.filter((s) => !s.active && !((s.requires_key && !s.has_key) || s.needs_index)).map((s) => s.name));
  const p = S.settings.preset;
  if (p && p !== 'default' && S.meta.presets[p]) { S.sources = new Set(S.meta.presets[p].sources); S.preset = p; return; }
  if (Array.isArray(S.settings.sources) && p === null) {
    S.sources = new Set(S.settings.sources.filter((n) => usable.has(n)));
    S.preset = null;
    if (S.sources.size) return;
  }
  setDefaultSources();
  S.preset = 'default';
}

function applyPrivacy() {
  const hide = !!(S.settings && S.settings.hide_sources);
  document.body.classList.toggle('hide-sources', hide);
  const keysNav = $('.nav-btn[data-page="keys"]');
  if (keysNav) keysNav.classList.toggle('hidden', hide);
}

async function importFile() {
  try {
    const text = await api('pick_targets_file');
    if (text == null) return;
    const lines = text.split(/\r?\n/).map((l) => l.split(',')[0].trim()).filter(Boolean);
    S.targets = (S.targets.trim() ? S.targets.trim() + '\n' : '') + lines.join('\n');
    renderScan();
    toast(`Imported ${fmtNum(lines.length)} lines`, 'success');
  } catch (e) { toast('Error: ' + errMsg(e), 'error'); }
}

async function startScan() {
  if (S.page !== 'scan') { go('scan'); return; }
  if (!targetCount()) { toast('Add at least one target', 'error'); $('#targets').focus(); return; }
  if (!S.sources.size) { toast('Select at least one source', 'error'); return; }
  try {
    await api('start_scan', {
      targets: S.targets, label: S.label, sources: [...S.sources],
      validate: !!S.opts.validate, probe: !!S.opts.probe, active: !!S.opts.active,
      use_cache: !!S.opts.use_cache, allow_private: !!S.opts.allow_private,
    });
    S.job.state = 'preparing';
    updateBusyUi();
    toast('Scan started');
  } catch (e) { toast('Error: ' + errMsg(e), 'error'); }
}

async function stopScan() {
  const ok = await askConfirm('The scan pauses after the current requests. Finished IPs stay saved and you can resume it from History.', 'Stop');
  if (!ok) return;
  try { await api('stop_scan'); } catch (e) { toast('Error: ' + errMsg(e), 'error'); }
}

function drawLogs() {
  const box = $('#log-box');
  if (!box) return;
  if (!S.logs.length) { box.innerHTML = '<div class="c-dim">No activity yet.</div>'; return; }
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 30;
  box.innerHTML = S.logs.map((l) => `<div class="log-line ${l.level}"><span class="t">${esc(l.t)}</span>${esc(l.msg)}</div>`).join('');
  if (atBottom) box.scrollTop = box.scrollHeight;
}

const STATE_UI = {
  idle: ['dot-dim', 'Ready'], preparing: ['dot-accent pulse', 'Preparing targets...'],
  running: ['dot-accent pulse', 'Scanning'], stopping: ['dot-yellow pulse', 'Stopping...'],
  done: ['dot-green', 'Completed'], paused: ['dot-yellow', 'Paused'], error: ['dot-red', 'Failed'],
};

function updateScanLive() {
  if (S.page !== 'scan' || !$('#st-ips')) return;
  const j = S.job;
  $('#st-ips').innerHTML = `${fmtNum(j.done)}<span class="of"> / ${fmtNum(j.total)}</span>`;
  $('#st-found').textContent = fmtNum(j.found);
  $('#st-active').textContent = fmtNum(j.active);
  const er = $('#st-errors');
  er.textContent = fmtNum(j.errors);
  er.className = 'value' + (j.errors ? ' c-red' : '');
  const [dot, title] = STATE_UI[j.state] || STATE_UI.idle;
  $('#pg-dot').className = 'dot ' + dot;
  $('#pg-title').textContent = j.scan_id && j.state !== 'idle' ? `${title} · scan #${j.scan_id}` : title;
  $('#pg-elapsed').textContent = j.elapsed ? `${j.elapsed}s` : '';
  const pct = j.total ? Math.round((j.done / j.total) * 100) : 0;
  const bar = $('#pg-bar');
  bar.style.width = (j.state === 'idle' ? 0 : pct) + '%';
  bar.className = 'health-bar-fill' + (j.state === 'done' ? ' green' : j.state === 'paused' ? ' yellow' : j.state === 'error' ? ' red' : '');
  $('#pg-open').classList.toggle('hidden', !(j.scan_id && j.done > 0));
}

function updateBusyUi() {
  const busy = isBusy();
  const main = $('#btn-scan-main');
  if (main) {
    main.className = 'btn ' + (busy ? 'btn-red' : 'btn-green');
    main.innerHTML = busy ? ICONS.stop + 'Stop' : ICONS.play + 'Start scan';
  }
  const sb = $('#sidebar-btn');
  sb.className = 'btn btn-block ' + (busy ? 'btn-red' : 'btn-green');
  sb.textContent = busy ? 'Stop scan' : 'Start scan';
  const j = S.job;
  const [dot, title] = STATE_UI[j.state] || STATE_UI.idle;
  $('#status-dot').className = 'dot ' + dot;
  $('#status-text').textContent = busy && j.total ? `${title} ${fmtNum(j.done)}/${fmtNum(j.total)}` : title;
  const pct = j.total ? (j.done / j.total) * 100 : 0;
  $('#sidebar-bar').style.width = (busy ? pct : 0) + '%';
  $('.sidebar-progress').classList.toggle('hidden', !busy);
}

// ================================================================== RESULTS PAGE
// Everything is paged and filtered in SQLite; the UI only holds the visible page.
const STATUS_DOT = { active: 'dot-green', historical: 'dot-yellow', dead: 'dot-red', unknown: 'dot-dim' };
const PAGE_SIZE = 200;
const IP_PAGE = 300;

function resetResultsView() {
  const R = S.results;
  Object.assign(R, { ip: null, filter: 'all', search: '', offset: 0, rows: [], total: 0, counts: {},
    ipSearch: '', ipRows: [], ipTotal: 0 });
  R.selected.clear();
}

async function renderResults() {
  const R = S.results;
  content().innerHTML = header('Results', 'Loading...') + loading();
  let scans;
  try { scans = await api('list_scans', 200); } catch (e) {
    content().innerHTML = header('Results', '') + `<div class="empty-state">Error: ${esc(errMsg(e))}</div>`; return;
  }
  if (!scans.length) {
    content().innerHTML = header('Results', 'No scans yet') +
      '<div class="card"><div class="empty-state">Run a scan and its results show up here.</div></div>';
    return;
  }
  if (!R.scanId || !scans.some((s) => s.id === R.scanId)) { R.scanId = scans[0].id; resetResultsView(); }
  try { R.meta = await api('results_summary', R.scanId); } catch (e) {
    content().innerHTML = header('Results', '') + `<div class="empty-state">Error: ${esc(errMsg(e))}</div>`; return;
  }
  drawResults(scans);
  loadIps(true);
  loadDomains();
}

function resultsSubtitle() {
  const { scan } = S.results.meta;
  return `Scan #${scan.id}${scan.label ? ' · ' + esc(scan.label) : ''} · ${esc(scan.date)} · ${fmtNum(scan.done)}/${fmtNum(scan.total)} IPs · ${esc(scan.status)}`;
}

function statCardsHtml() {
  const { scan, summary: m } = S.results.meta;
  const validated = !!(scan.options || {}).validate;
  return `
    <div class="stat-card"><div class="label">IPs</div><div class="value">${fmtNum(m.ips)}</div></div>
    <div class="stat-card"><div class="label">Domains</div><div class="value">${fmtNum(m.domains)}</div></div>
    <div class="stat-card"><div class="label">Root domains</div><div class="value">${fmtNum(m.roots)}</div></div>
    <div class="stat-card"><div class="label">Active</div><div class="value c-green">${validated ? fmtNum(m.active) : '-'}</div></div>
    <div class="stat-card"><div class="label">CDN IPs</div><div class="value ${m.cdn_ips ? 'c-yellow' : ''}">${fmtNum(m.cdn_ips)}</div></div>`;
}

function drawResults(scans) {
  const R = S.results;
  const { scan, summary: m } = R.meta;
  const scanOpts = scans.map((s) => `<option value="${s.id}" ${s.id === R.scanId ? 'selected' : ''}>#${s.id} ${esc(s.label || '')} · ${esc(s.date)}</option>`).join('');

  content().innerHTML = `
    ${header('Results', resultsSubtitle(), `
      <select class="input input-sm" id="scan-select" style="width:260px">${scanOpts}</select>
      <button class="btn btn-accent" id="btn-export">${ICONS.download}Export</button>`)}
    <div class="stat-cards" id="res-stats">${statCardsHtml()}</div>
    <div id="cdn-warn">${cdnWarnHtml(m)}</div>
    <div class="split-side">
      <div class="card compact">
        <div class="card-head" style="padding:4px 4px 0;margin-bottom:8px">
          <div class="section-title">IPs</div><span class="section-sub mono" id="ip-total"></span></div>
        <input class="input input-sm mb-8" id="ip-search" placeholder="Filter IP, provider, ASN" value="${esc(R.ipSearch)}">
        <div class="data-list scroll" id="ip-list">${loading()}</div>
      </div>
      <div class="card">
        <div class="card-head">
          <div class="filter-tabs" id="status-tabs"></div>
          <div class="flex">
            <input class="input input-sm" id="search" placeholder="Search domain, title, tech" style="width:200px" value="${esc(R.search)}">
            <button class="btn btn-ghost btn-sm ${R.roots ? 'active' : ''}" id="btn-roots">Group by root</button>
          </div>
        </div>
        <div class="flex justify-between mb-8">
          <span class="text-xs c-dim" id="shown-count"></span>
          <div class="flex">
            <button class="btn btn-ghost btn-xs" id="btn-copy-sel">Copy selected</button>
            <button class="btn btn-ghost btn-xs" id="btn-copy-all">Copy all matching</button>
          </div>
        </div>
        <div id="domain-area">${loading()}</div>
        <div class="flex justify-between mt-8" id="pager"></div>
      </div>
    </div>`;

  $('#scan-select').onchange = (e) => { R.scanId = Number(e.target.value); resetResultsView(); renderResults(); };
  $('#btn-export').onclick = () => exportModal(scan);
  let ipDeb;
  $('#ip-search').oninput = (e) => { clearTimeout(ipDeb); ipDeb = setTimeout(() => { R.ipSearch = e.target.value; loadIps(true); }, 250); };
  let deb;
  $('#search').oninput = (e) => {
    clearTimeout(deb);
    deb = setTimeout(() => { R.search = e.target.value; R.offset = 0; loadDomains(); }, 250);
  };
  $('#btn-roots').onclick = (e) => {
    R.roots = !R.roots; R.offset = 0;
    e.currentTarget.classList.toggle('active', R.roots);
    loadDomains();
  };
  $('#btn-copy-all').onclick = copyAllMatching;
  $('#btn-copy-sel').onclick = copySelected;
}

function cdnWarnHtml(m) {
  if (!m.cdn_ips) return '';
  return `<div class="card compact warn"><div class="flex"><span class="dot dot-yellow"></span>
    <span>${fmtNum(m.cdn_ips)} IP(s) belong to a CDN (${esc((m.cdn_providers || []).join(', ') || 'CDN')}).
    Unrelated sites share CDN edge IPs and the real origin server is hidden.</span></div></div>`;
}

// ---------- IP list (paged with "Load more")
async function loadIps(reset) {
  const R = S.results;
  const seq = (R.ipSeq = (R.ipSeq || 0) + 1);
  try {
    const res = await api('results_ips', R.scanId, R.ipSearch, reset ? 0 : R.ipRows.length, IP_PAGE);
    if (seq !== R.ipSeq) return;
    R.ipRows = reset ? res.rows : R.ipRows.concat(res.rows);
    R.ipTotal = res.total;
    drawIps();
  } catch (e) {
    const el = $('#ip-list');
    if (el) el.innerHTML = `<div class="empty-state">Error: ${esc(errMsg(e))}</div>`;
  }
}

function drawIps() {
  const R = S.results;
  const list = $('#ip-list');
  if (!list) return;
  $('#ip-total').textContent = fmtNum(R.ipTotal);
  const rows = [];
  if (!R.ipSearch) {
    rows.push(`<div class="data-row clickable ${!R.ip ? 'selected' : ''}" data-ip="">
      <span class="col-dot"><span class="dot dot-accent"></span></span>
      <div class="flex-1 main">All IPs</div><span class="mono c-dim">${fmtNum(R.meta.summary.rows)}</span></div>`);
  }
  for (const i of R.ipRows) {
    const errs = Object.keys(i.errors || {}).length;
    const dot = i.category === 'cdn' ? 'dot-yellow' : errs && !i.n_domains ? 'dot-red' : i.n_domains ? 'dot-green' : 'dot-dim';
    const prov = [i.provider, i.asn ? 'AS' + i.asn : ''].filter(Boolean).join(' · ');
    rows.push(`<div class="data-row clickable ${R.ip === i.ip ? 'selected' : ''}" data-ip="${esc(i.ip)}"
        title="${esc(errs && !hideSrc() ? Object.entries(i.errors).map(([k, v]) => k + ': ' + v).join('\n') : '')}">
      <span class="col-dot"><span class="dot ${dot}"></span></span>
      <div class="flex-1"><div class="main mono">${esc(i.ip)}</div>
        <div class="sub ellipsis">${esc(prov || 'unknown provider')}${i.hosting ? ' · ' + esc(i.hosting) : ''}${errs ? ` · <span class="c-red">${errs} error${errs > 1 ? 's' : ''}</span>` : ''}</div></div>
      <span class="mono c-dim">${fmtNum(i.n_domains)}</span></div>`);
  }
  if (!R.ipRows.length) rows.push(`<div class="empty-state">${R.ipSearch ? 'No IPs match.' : 'No finished IPs yet.'}</div>`);
  if (R.ipRows.length < R.ipTotal) {
    rows.push(`<button class="btn btn-ghost btn-sm btn-block mt-8" id="ip-more">Load more · ${fmtNum(R.ipTotal - R.ipRows.length)} left</button>`);
  }
  const scroll = list.scrollTop;
  list.innerHTML = rows.join('');
  list.scrollTop = scroll;
  $$('#ip-list [data-ip]').forEach((row) => {
    row.onclick = () => {
      R.ip = row.dataset.ip || null;
      R.offset = 0;
      $$('#ip-list .data-row').forEach((r) => r.classList.toggle('selected', r === row));
      loadDomains();
    };
  });
  const more = $('#ip-more');
  if (more) more.onclick = () => { more.disabled = true; loadIps(false); };
}

// ---------- domain list (server-side paging, filters and search)
function currentFilters() {
  const R = S.results;
  return { ip: R.ip, status: R.filter, search: R.search, roots: R.roots };
}

async function loadDomains() {
  const R = S.results;
  const seq = (R.domSeq = (R.domSeq || 0) + 1);
  try {
    const res = await api('results_domains', R.scanId, currentFilters(), R.offset, PAGE_SIZE);
    if (seq !== R.domSeq) return;   // a newer request is on its way
    R.rows = res.rows; R.total = res.total; R.counts = res.counts;
    drawTabs();
    drawDomains();
  } catch (e) {
    const el = $('#domain-area');
    if (el) el.innerHTML = `<div class="empty-state">Error: ${esc(errMsg(e))}</div>`;
  }
}

function drawTabs() {
  const R = S.results;
  const el = $('#status-tabs');
  if (!el) return;
  const c = R.counts || {};
  el.innerHTML = ['all', 'active', 'historical', 'dead', 'unknown']
    .filter((st) => st === 'all' || c[st] || st === R.filter)
    .map((st) => `<button class="filter-tab ${R.filter === st ? 'active' : ''}" data-filter="${st}">${st[0].toUpperCase() + st.slice(1)}<span class="count">${fmtNum(c[st] || 0)}</span></button>`)
    .join('');
  $$('#status-tabs [data-filter]').forEach((t) => {
    t.onclick = () => { R.filter = t.dataset.filter; R.offset = 0; loadDomains(); };
  });
}

function drawDomains() {
  const R = S.results;
  const area = $('#domain-area');
  if (!area) return;
  const probe = !!(R.meta.scan.options || {}).probe;
  const scroll = area.querySelector('.data-list');
  const keepScroll = scroll ? scroll.scrollTop : 0;

  if (R.roots) {
    $('#shown-count').textContent = `${fmtNum(R.total)} root domains`;
    area.innerHTML = R.rows.length ? `
      <div class="table-header"><span class="flex-1">Root domain</span><span class="col-num">Names</span><span class="col-act"></span></div>
      <div class="data-list scroll">${R.rows.map((g) => `
        <div class="data-row">
          <div class="flex-1"><div class="main">${esc(g.root)}</div>
            <div class="sub ellipsis">${esc(g.examples.join(', '))}${g.names > g.examples.length ? ' …' : ''}</div></div>
          <span class="col-num mono c-sec">${fmtNum(g.names)}</span>
          <span class="col-act row-actions"><button class="btn btn-ghost btn-xs" data-open="${esc(g.root)}">Open</button><button class="btn btn-ghost btn-xs" data-copy="${esc(g.root)}">Copy</button></span>
        </div>`).join('')}</div>` : '<div class="empty-state">No domains match these filters.</div>';
  } else {
    updateShownCount();
    area.innerHTML = R.rows.length ? `
      <div class="table-header">
        <input type="checkbox" class="col-check" id="sel-all">
        <span class="col-dot"></span>
        <span class="flex-1">Domain</span>
        ${!R.ip ? '<span class="col-ip">IP</span>' : ''}
        ${probe ? '<span class="col-http">HTTP</span>' : ''}
        <span class="col-conf">Conf</span>
        <span class="col-src src-col">Sources</span>
        <span class="col-act"></span>
      </div>
      <div class="data-list scroll">${R.rows.map((r) => domainRow(r, probe)).join('')}</div>`
      : `<div class="empty-state">${R.search ? 'No domains match your search.' : 'No domains for this selection.'}</div>`;
    const selAll = $('#sel-all');
    if (selAll) {
      const keys = R.rows.map((r) => r.ip + '|' + r.domain);
      selAll.checked = keys.every((k) => R.selected.has(k));
      selAll.onchange = () => {
        keys.forEach((k) => (selAll.checked ? R.selected.add(k) : R.selected.delete(k)));
        $$('#domain-area [data-sel]').forEach((cb) => { cb.checked = selAll.checked; });
        updateShownCount();
      };
    }
    $$('#domain-area [data-sel]').forEach((cb) => {
      cb.onchange = () => { cb.checked ? R.selected.add(cb.dataset.sel) : R.selected.delete(cb.dataset.sel); updateShownCount(); };
    });
  }
  const list = area.querySelector('.data-list');
  if (list && keepScroll) list.scrollTop = keepScroll;
  $$('#domain-area [data-open]').forEach((b) => {
    b.onclick = async () => { try { await api('open_url', b.dataset.open); } catch (e) { toast('Error: ' + errMsg(e), 'error'); } };
  });
  $$('#domain-area [data-copy]').forEach((b) => {
    b.onclick = async () => { await copyText(b.dataset.copy); toast('Copied'); };
  });
  drawPager();
}

function updateShownCount() {
  const R = S.results;
  const el = $('#shown-count');
  if (el) el.textContent = `${fmtNum(R.total)} domains${R.selected.size ? ` · ${fmtNum(R.selected.size)} selected` : ''}`;
}

function drawPager() {
  const R = S.results;
  const el = $('#pager');
  if (!el) return;
  if (R.total <= PAGE_SIZE) { el.innerHTML = ''; return; }
  const from = R.offset + 1;
  const to = Math.min(R.offset + R.rows.length, R.total);
  const page = Math.floor(R.offset / PAGE_SIZE) + 1;
  const pages = Math.ceil(R.total / PAGE_SIZE);
  el.innerHTML = `
    <span class="text-xs c-dim mono">${fmtNum(from)}–${fmtNum(to)} of ${fmtNum(R.total)}</span>
    <div class="flex">
      <button class="btn btn-ghost btn-xs" data-pg="first" ${page === 1 ? 'disabled' : ''}>First</button>
      <button class="btn btn-ghost btn-xs" data-pg="prev" ${page === 1 ? 'disabled' : ''}>Prev</button>
      <span class="text-xs c-sec mono">${fmtNum(page)} / ${fmtNum(pages)}</span>
      <button class="btn btn-ghost btn-xs" data-pg="next" ${page >= pages ? 'disabled' : ''}>Next</button>
      <button class="btn btn-ghost btn-xs" data-pg="last" ${page >= pages ? 'disabled' : ''}>Last</button>
    </div>`;
  $$('[data-pg]', el).forEach((b) => {
    b.onclick = () => {
      const last = (pages - 1) * PAGE_SIZE;
      R.offset = { first: 0, prev: Math.max(0, R.offset - PAGE_SIZE), next: Math.min(last, R.offset + PAGE_SIZE), last }[b.dataset.pg];
      const list = $('#domain-area .data-list');
      if (list) list.scrollTop = 0;
      loadDomains();
    };
  });
}

function domainRow(r, probe) {
  const R = S.results;
  const key = r.ip + '|' + r.domain;
  const h = r.http || null;
  const confCls = r.confidence >= 70 ? 'c-green' : r.confidence >= 40 ? 'c-yellow' : 'c-red';
  let sub = '';
  if (h && h.error) sub = `<span class="c-red">${esc(h.error)}</span>`;
  else if (h) {
    sub = `${h.title ? esc(h.title) : '<span class="c-dim">no title</span>'}
      ${(h.tech || []).slice(0, 6).map((t) => `<span class="tag accent">${esc(t)}</span>`).join('')}`;
  } else if (r.status === 'historical' && r.resolved_ips && r.resolved_ips.length) {
    sub = `now on <span class="mono">${esc(r.resolved_ips.slice(0, 2).join(', '))}</span>`;
  } else if (r.last_seen) {
    sub = `last seen <span class="mono">${esc(String(r.last_seen).slice(0, 10))}</span>`;
  }
  const httpCell = !probe ? '' : `<span class="col-http mono ${h && h.status ? (h.status < 400 ? 'c-green' : 'c-red') : 'c-dim'}">${h ? (h.status || (h.error ? 'err' : '-')) : '-'}</span>`;
  return `<div class="data-row">
    <input type="checkbox" class="col-check" data-sel="${esc(key)}" ${R.selected.has(key) ? 'checked' : ''}>
    <span class="col-dot" title="${esc(r.status)}"><span class="dot ${STATUS_DOT[r.status] || 'dot-dim'}"></span></span>
    <div class="flex-1"><div class="main ellipsis">${esc(r.domain)}</div>${sub ? `<div class="sub ellipsis">${sub}</div>` : ''}</div>
    ${!R.ip ? `<span class="col-ip mono c-dim ellipsis">${esc(r.ip)}</span>` : ''}
    ${httpCell}
    <span class="col-conf mono ${confCls}">${r.confidence}</span>
    ${hideSrc() ? '' : `<span class="col-src src-col text-xs c-dim ellipsis" title="${esc((r.sources || []).join(', '))}">${esc((r.sources || []).join(', '))}</span>`}
    <span class="col-act row-actions">
      <button class="btn btn-ghost btn-xs" data-open="${esc(h && h.url ? h.url : r.domain)}">Open</button>
      <button class="btn btn-ghost btn-xs" data-copy="${esc(r.domain)}">Copy</button>
    </span>
  </div>`;
}

async function copySelected() {
  const R = S.results;
  if (!R.selected.size) { toast('Nothing selected', 'error'); return; }
  const names = [...new Set([...R.selected].map((k) => k.slice(k.indexOf('|') + 1)))].sort();
  await copyText(names.join('\n'));
  toast(`Copied ${fmtNum(names.length)} domain${names.length > 1 ? 's' : ''}`, 'success');
}

async function copyAllMatching() {
  const R = S.results;
  try {
    const res = await api('results_copy', R.scanId, currentFilters());
    if (!res.count) { toast('Nothing to copy', 'error'); return; }
    await copyText(res.text);
    toast(`Copied ${fmtNum(res.count)} ${R.roots ? 'root domains' : 'domains'}${res.truncated ? ' (limit reached - export for the full list)' : ''}`, 'success');
  } catch (e) { toast('Error: ' + errMsg(e), 'error'); }
}

async function refreshResultsLive() {
  const R = S.results;
  try {
    R.meta = await api('results_summary', R.scanId);
    const stats = $('#res-stats');
    if (!stats) return;
    stats.innerHTML = statCardsHtml();
    $('#page-subtitle').innerHTML = resultsSubtitle();
    $('#cdn-warn').innerHTML = cdnWarnHtml(R.meta.summary);
    if (!R.ipSearch && R.ipRows.length <= IP_PAGE) loadIps(true);
    loadDomains();
  } catch { /* ignore */ }
}

function exportModal(scan) {
  let fmt = 'csv';
  const validated = !!(scan.options || {}).validate;
  openModal(`
    <div class="modal-title">Export scan #${scan.id}</div>
    <div class="form-group">
      <span class="form-label">Format</span>
      <div class="filter-tabs" id="fmt-tabs">
        <button class="filter-tab active" data-fmt="csv">CSV</button>
        <button class="filter-tab" data-fmt="json">JSON</button>
        <button class="filter-tab" data-fmt="txt">TXT</button>
      </div>
      <span class="form-hint" id="fmt-hint">All columns, opens in Excel (Arabic titles included).</span>
    </div>
    <label class="checkbox-row"><input type="checkbox" id="ex-active" ${validated ? '' : 'disabled'}>
      <span><div class="cb-text">Only active domains</div><div class="cb-hint">${validated ? 'Domains that still resolve to the scanned IP' : 'This scan ran without DNS validation'}</div></span></label>
    <label class="checkbox-row"><input type="checkbox" id="ex-roots" disabled>
      <span><div class="cb-text">Root domains only</div><div class="cb-hint">TXT only: example.co.uk instead of every subdomain</div></span></label>
    <div class="modal-actions">
      <button class="btn btn-ghost" data-act="cancel">Cancel</button>
      <button class="btn btn-accent" data-act="ok">${ICONS.download}Export</button>
    </div>`, {
    onMount: (el, m) => {
      const hints = { csv: 'All columns, opens in Excel (Arabic titles included).', json: 'Full data including errors and provider info.', txt: 'One domain per line.' };
      $$('[data-fmt]', el).forEach((t) => {
        t.onclick = () => {
          fmt = t.dataset.fmt;
          $$('[data-fmt]', el).forEach((x) => x.classList.toggle('active', x === t));
          $('#fmt-hint', el).textContent = hints[fmt];
          const roots = $('#ex-roots', el);
          roots.disabled = fmt !== 'txt';
          if (roots.disabled) roots.checked = false;
        };
      });
      $('[data-act=cancel]', el).onclick = m.close;
      $('[data-act=ok]', el).onclick = async () => {
        try {
          const res = await api('export_scan', scan.id, fmt, $('#ex-active', el).checked, $('#ex-roots', el).checked);
          if (res.cancelled) return;
          m.close();
          toast(`Saved ${fmtNum(res.rows)} rows to ${res.path}`, 'success');
        } catch (e) { toast('Error: ' + errMsg(e), 'error'); }
      };
    },
  });
}

// ================================================================== HISTORY PAGE
const HIST_DOT = { done: 'dot-green', interrupted: 'dot-yellow', running: 'dot-accent' };

async function renderHistory() {
  content().innerHTML = header('History', 'Loading...') + loading();
  let scans;
  try { scans = await api('list_scans', 500); } catch (e) {
    content().innerHTML = header('History', '') + `<div class="empty-state">Error: ${esc(errMsg(e))}</div>`; return;
  }
  updateBadge(scans);
  const runningId = isBusy() ? S.job.scan_id : null;
  const statusOf = (s) => (s.id === runningId ? 'running' : s.status === 'running' ? 'interrupted' : s.status);
  const counts = { all: scans.length, done: 0, interrupted: 0, running: 0 };
  scans.forEach((s) => { counts[statusOf(s)] = (counts[statusOf(s)] || 0) + 1; });
  const shown = scans.filter((s) => S.historyFilter === 'all' || statusOf(s) === S.historyFilter);
  const labels = { all: 'All', done: 'Done', interrupted: 'Paused', running: 'Running' };

  content().innerHTML = `
    ${header('History', `${fmtNum(scans.length)} scans · ${fmtNum(counts.interrupted)} paused`, '<button class="btn btn-ghost" id="btn-refresh">Refresh</button>')}
    <div class="card">
      <div class="card-head">
        <div class="filter-tabs">${Object.keys(labels).filter((k) => k === 'all' || counts[k]).map((k) =>
          `<button class="filter-tab ${S.historyFilter === k ? 'active' : ''}" data-hf="${k}">${labels[k]}<span class="count">${fmtNum(counts[k])}</span></button>`).join('')}</div>
      </div>
      ${shown.length ? `
        <div class="table-header"><span class="col-dot"></span><span class="flex-1">Scan</span><span class="col-meta">Date</span><span class="col-meta">Progress</span><span class="col-act-lg"></span></div>
        <div class="data-list scroll">${shown.map((s) => {
          const st = statusOf(s);
          const pct = s.total ? Math.round((s.done / s.total) * 100) : 0;
          const canResume = st === 'interrupted' && !isBusy();
          return `<div class="data-row">
            <span class="col-dot"><span class="dot ${HIST_DOT[st] || 'dot-dim'} ${st === 'running' ? 'pulse' : ''}"></span></span>
            <div class="flex-1"><div class="main">#${s.id}${s.label ? ' · ' + esc(s.label) : ''}</div><div class="sub">${esc(labels[st] || st)}</div></div>
            <span class="col-meta mono c-dim">${esc(s.date)}</span>
            <span class="col-meta"><div class="mono text-xs c-sec">${fmtNum(s.done)}/${fmtNum(s.total)}</div>
              <div class="health-bar"><div class="health-bar-fill ${st === 'done' ? 'green' : st === 'interrupted' ? 'yellow' : ''}" style="width:${pct}%"></div></div></span>
            <span class="col-act-lg row-actions">
              <button class="btn btn-ghost btn-xs" data-open="${s.id}" ${s.done ? '' : 'disabled'}>Open</button>
              ${canResume ? `<button class="btn btn-green btn-xs" data-resume="${s.id}">Resume</button>` : ''}
              <button class="btn btn-red btn-xs" data-del="${s.id}" ${st === 'running' ? 'disabled' : ''}>Delete</button>
            </span></div>`;
        }).join('')}</div>`
        : `<div class="empty-state">${scans.length ? 'No scans in this filter.' : 'No scans yet. Start one from the Scan page.'}</div>`}
    </div>`;

  $('#btn-refresh').onclick = renderHistory;
  $$('[data-hf]').forEach((t) => { t.onclick = () => { S.historyFilter = t.dataset.hf; renderHistory(); }; });
  $$('[data-open]').forEach((b) => { b.onclick = () => { S.results.scanId = Number(b.dataset.open); resetResultsView(); go('results'); }; });
  $$('[data-resume]').forEach((b) => {
    b.onclick = async () => {
      try { await api('resume_scan', Number(b.dataset.resume)); S.job.state = 'preparing'; updateBusyUi(); toast('Resuming scan'); go('scan'); }
      catch (e) { toast('Error: ' + errMsg(e), 'error'); }
    };
  });
  $$('[data-del]').forEach((b) => {
    b.onclick = async () => {
      const id = Number(b.dataset.del);
      if (!(await askConfirm(`Scan #${id} and all its results will be removed. This can't be undone.`, 'Delete'))) return;
      try {
        await api('delete_scan', id);
        if (S.results.scanId === id) { S.results.scanId = null; resetResultsView(); }
        toast(`Deleted scan #${id}`);
        renderHistory();
      } catch (e) { toast('Error: ' + errMsg(e), 'error'); }
    };
  });
}

function updateBadge(scans) {
  const n = scans.filter((s) => s.status !== 'done' && !(isBusy() && s.id === S.job.scan_id)).length;
  const b = $('#badge-history');
  b.textContent = n;
  b.classList.toggle('hidden', !n);
}

async function refreshBadge() {
  try { updateBadge(await api('list_scans', 500)); } catch { /* ignore */ }
}

// ================================================================== INDEX PAGE
const IX = { state: 'idle', logs: [], cursor: 0, stats: null };

function fmtBytes(n) {
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n) + ' ' + u[i];
}

async function renderIndex() {
  content().innerHTML = header('Local index', 'Loading...') + loading();
  try { IX.stats = await api('index_stats'); } catch (e) {
    content().innerHTML = header('Local index', '') + `<div class="empty-state">Error: ${esc(errMsg(e))}</div>`; return;
  }
  const s = IX.stats;
  const running = IX.state === 'running';
  content().innerHTML = `
    ${header('Local index', 'Your own IP → domain database. Lookups are instant, offline and unlimited.', `
      <button class="btn btn-ghost" id="ix-resolve" ${running ? 'disabled' : ''}>Resolve pending</button>
      ${running ? `<button class="btn btn-red" id="ix-stop">${ICONS.stop}Stop</button>`
        : `<button class="btn btn-accent" id="ix-import">${ICONS.file}Import list</button>`}`)}
    <div class="stat-cards" id="ix-stats">${ixStatsHtml(s)}</div>
    <div class="split-1-2">
      <div>
        <div class="card">
          <div class="section-title mb-8">How it works</div>
          <div class="c-sec text-xs" style="line-height:1.7">
            <p class="mb-8">1. Import a list of domains. IPScope resolves each one and remembers which IP it points to.</p>
            <p class="mb-8">2. Every scan then asks the <span class="mono">local</span> source first. It answers from this database with no API and no limits.</p>
            <p>The more domains you import, the more complete reverse lookups get. Run <b>Resolve pending</b> again any time to continue after a stop.</p>
          </div>
        </div>
        <div class="card">
          <div class="section-title mb-8">Accepted files</div>
          <div class="data-list">
            <div class="data-row"><div class="flex-1"><div class="main">Domain list</div><div class="sub">One domain per line (.txt, .csv)</div></div><span class="tag">resolve</span></div>
            <div class="data-row"><div class="flex-1"><div class="main">DNS zone file</div><div class="sub">e.g. .com zone from ICANN CZDS</div></div><span class="tag">resolve</span></div>
            <div class="data-row"><div class="flex-1"><div class="main">Rapid7 FDNS</div><div class="sub">fdns_a.json.gz - already resolved</div></div><span class="tag green">instant</span></div>
          </div>
          <div class="form-hint mt-8">Compressed .gz files are read directly.</div>
        </div>
      </div>
      <div>
        <div class="card">
          <div class="card-head">
            <div class="flex"><span class="dot dot-dim" id="ix-dot"></span><div class="section-title" id="ix-title">Idle</div></div>
            <span class="mono c-dim" id="ix-count"></span>
          </div>
          <div class="health-bar lg"><div class="health-bar-fill" id="ix-bar"></div></div>
          <div class="form-hint mt-8 mono" style="user-select:text">${esc(s.path)}</div>
        </div>
        <div class="card">
          <div class="card-head"><div class="section-title">Log</div><button class="btn btn-ghost btn-xs" id="ix-log-clear">Clear</button></div>
          <div class="log-box" id="ix-log"></div>
        </div>
      </div>
    </div>`;

  const imp = $('#ix-import');
  if (imp) imp.onclick = async () => {
    try {
      const r = await api('index_import', null);
      if (r.cancelled) return;
      IX.state = 'running'; renderIndex();
    } catch (e) { toast('Error: ' + errMsg(e), 'error'); }
  };
  $('#ix-resolve').onclick = async () => {
    try { await api('index_resolve', false); IX.state = 'running'; renderIndex(); }
    catch (e) { toast('Error: ' + errMsg(e), 'error'); }
  };
  const stop = $('#ix-stop');
  if (stop) stop.onclick = async () => {
    if (!(await askConfirm('Indexing stops after the current batch. Everything resolved so far is kept.', 'Stop'))) return;
    try { await api('index_stop'); } catch (e) { toast('Error: ' + errMsg(e), 'error'); }
  };
  $('#ix-log-clear').onclick = () => { IX.logs = []; drawIxLog(); };
  drawIxLog();
  updateIxLive(IX.last || {});
}

function ixStatsHtml(s) {
  return `
    <div class="stat-card"><div class="label">Names</div><div class="value">${fmtNum(s.names)}</div></div>
    <div class="stat-card"><div class="label">Resolved</div><div class="value c-green">${fmtNum(s.resolved)}</div></div>
    <div class="stat-card"><div class="label">Pending</div><div class="value ${s.pending ? 'c-yellow' : ''}">${fmtNum(s.pending)}</div></div>
    <div class="stat-card"><div class="label">Failed</div><div class="value ${s.failed ? 'c-red' : ''}">${fmtNum(s.failed)}</div></div>
    <div class="stat-card"><div class="label">IP records</div><div class="value">${fmtNum(s.records)}</div></div>
    <div class="stat-card"><div class="label">Size</div><div class="value">${fmtBytes(s.size_bytes)}</div></div>`;
}

function drawIxLog() {
  const box = $('#ix-log');
  if (!box) return;
  if (!IX.logs.length) { box.innerHTML = '<div class="c-dim">No activity yet.</div>'; return; }
  box.innerHTML = IX.logs.map((l) => `<div class="log-line ${l.level}"><span class="t">${esc(l.t)}</span>${esc(l.msg)}</div>`).join('');
  box.scrollTop = box.scrollHeight;
}

const IX_UI = { idle: ['dot-dim', 'Idle'], running: ['dot-accent pulse', 'Working'], done: ['dot-green', 'Done'],
  paused: ['dot-yellow', 'Paused'], error: ['dot-red', 'Failed'] };

function updateIxLive(st) {
  if (S.page !== 'index' || !$('#ix-title')) return;
  const [dot, title] = IX_UI[st.state || 'idle'] || IX_UI.idle;
  $('#ix-dot').className = 'dot ' + dot;
  const phase = st.state === 'running' ? (st.phase === 'import' ? ' · importing' : st.phase === 'resolve' ? ' · resolving' : '') : '';
  $('#ix-title').textContent = title + phase;
  const bar = $('#ix-bar');
  if (st.state === 'running' && st.phase === 'import') {
    $('#ix-count').textContent = `${fmtNum(st.lines)} lines`;
    bar.style.width = '100%'; bar.className = 'health-bar-fill';
  } else {
    $('#ix-count').textContent = st.total ? `${fmtNum(st.done)}/${fmtNum(st.total)} · ${fmtNum(st.ok)} with IPs` : '';
    bar.style.width = (st.total ? Math.round((st.done / st.total) * 100) : 0) + '%';
    bar.className = 'health-bar-fill' + (st.state === 'done' ? ' green' : st.state === 'paused' ? ' yellow' : st.state === 'error' ? ' red' : '');
  }
}

let ixPolling = false;
let ixStatsAt = 0;
async function pollIndex() {
  if (ixPolling || (S.page !== 'index' && IX.state !== 'running')) return;
  ixPolling = true;
  try {
    const prev = IX.state;
    const st = await api('index_state', IX.cursor);
    IX.state = st.state; IX.last = st;
    if (st.logs.length) { IX.logs.push(...st.logs); IX.logs = IX.logs.slice(-800); IX.cursor = st.cursor; drawIxLog(); }
    updateIxLive(st);
    const finished = st.state !== 'running' && st.state !== 'idle' && (prev === 'running' || (st.state !== prev && st.logs.length));
    if (finished) {
      toast(st.state === 'done' ? 'Index updated' : st.state === 'paused' ? 'Indexing paused' : 'Indexing failed - see the log',
        st.state === 'error' ? 'error' : st.state === 'done' ? 'success' : '');
      try { await reloadMeta(); } catch { /* ignore */ }
      if (S.page === 'index') renderIndex();
    } else if (S.page === 'index' && st.state === 'running' && Date.now() - ixStatsAt > 3000) {
      ixStatsAt = Date.now();
      try { const s = await api('index_stats'); const el = $('#ix-stats'); if (el) el.innerHTML = ixStatsHtml(s); } catch { /* ignore */ }
    }
  } catch { /* ignore */ }
  ixPolling = false;
}

// ================================================================== KEYS PAGE
async function renderKeys() {
  content().innerHTML = header('API Keys', 'Loading...') + loading();
  let data;
  try { data = await api('keys_list'); } catch (e) {
    content().innerHTML = header('API Keys', '') + `<div class="empty-state">Error: ${esc(errMsg(e))}</div>`; return;
  }
  const set = data.items.filter((i) => i.keys.length).length;
  content().innerHTML = `
    ${header('API Keys', `${set} of ${data.items.length} sources configured · stored in ${esc(data.backend)}`)}
    <div class="split-1-2">
      <div class="card">
        <div class="section-title mb-8">How keys work</div>
        <div class="c-sec text-xs" style="line-height:1.7">
          <p class="mb-8">Keys are saved in your system's secure store (Windows Credential Manager). Nothing is written in plain text unless no secure store exists.</p>
          <p class="mb-8">Add several keys to one source and IPScope rotates to the next one when a key is rejected or runs out of quota.</p>
          <p>An environment variable such as <span class="mono">IPSCOPE_SHODAN_KEY</span> overrides the stored key.</p>
        </div>
      </div>
      <div class="card">
        <div class="section-title mb-8">Sources</div>
        ${data.items.map((i) => {
          const fromEnv = (i.from || '').startsWith('env:');
          return `<div class="setting-row">
            <div class="flex-1">
              <div class="flex"><span class="dot ${i.keys.length ? 'dot-green' : i.requires_key ? 'dot-red' : 'dot-dim'}"></span>
                <span class="name mono">${esc(i.name)}</span>
                <span class="tag ${i.requires_key ? 'yellow' : ''}">${i.requires_key ? 'required' : 'optional'}</span>
                ${fromEnv ? '<span class="tag accent">from env</span>' : ''}</div>
              <div class="desc">${esc(i.description)}</div>
              ${i.keys.length ? `<div class="mt-8">${i.keys.map((k) => `<span class="tag mono">${esc(k)}</span>`).join('')}</div>` : ''}
            </div>
            <div class="ctl">
              <button class="btn btn-ghost btn-xs" data-add="${esc(i.name)}" ${fromEnv ? 'disabled title="Set by an environment variable"' : ''}>${i.keys.length ? 'Add key' : 'Set key'}</button>
              ${i.keys.length && !fromEnv ? `<button class="btn btn-red btn-xs" data-del="${esc(i.name)}">Delete</button>` : ''}
            </div>
          </div>`;
        }).join('')}
      </div>
    </div>`;

  $$('[data-add]').forEach((b) => {
    b.onclick = () => keyModal(data.items.find((i) => i.name === b.dataset.add));
  });
  $$('[data-del]').forEach((b) => {
    b.onclick = async () => {
      const name = b.dataset.del;
      if (!(await askConfirm(`All stored keys for ${name} will be removed.`, 'Delete'))) return;
      try { await api('keys_delete', name); toast(`Deleted ${name} keys`); await reloadMeta(); renderKeys(); }
      catch (e) { toast('Error: ' + errMsg(e), 'error'); }
    };
  });
}

function keyModal(item) {
  openModal(`
    <div class="modal-title">${item.keys.length ? 'Add key' : 'Set key'} · <span class="mono">${esc(item.name)}</span></div>
    <div class="form-group">
      <label class="form-label" for="key-input">API key</label>
      <input class="input input-mono" id="key-input" type="password" autocomplete="off" spellcheck="false" placeholder="Paste the key">
      <span class="form-hint">${esc(item.description)}</span>
    </div>
    ${item.keys.length ? `<label class="checkbox-row"><input type="checkbox" id="key-keep" checked>
      <span><div class="cb-text">Keep existing keys</div><div class="cb-hint">Adds this key for rotation instead of replacing</div></span></label>` : ''}
    <label class="checkbox-row"><input type="checkbox" id="key-show">
      <span class="cb-text">Show key</span></label>
    <div class="modal-actions">
      <button class="btn btn-ghost" data-act="cancel">Cancel</button>
      <button class="btn btn-accent" data-act="ok">Save</button>
    </div>`, {
    onMount: (el, m) => {
      $('#key-show', el).onchange = (e) => { $('#key-input', el).type = e.target.checked ? 'text' : 'password'; };
      $('[data-act=cancel]', el).onclick = m.close;
      $('[data-act=ok]', el).onclick = async () => {
        const key = $('#key-input', el).value.trim();
        if (!key) { toast('Key is empty', 'error'); return; }
        const keep = $('#key-keep', el);
        try {
          const res = await api('keys_set', item.name, key, keep ? keep.checked : false);
          m.close();
          toast(`Saved · ${item.name} has ${res.count} key${res.count > 1 ? 's' : ''}`, 'success');
          await reloadMeta();
          renderKeys();
        } catch (e) { toast('Error: ' + errMsg(e), 'error'); }
      };
    },
  });
}

async function reloadMeta() {
  const before = new Set(S.meta.sources.filter((s) => s.has_key).map((s) => s.name));
  const hadIndex = S.meta.sources.some((s) => s.name === 'local' && !s.needs_index);
  S.meta = await api('get_meta');
  for (const s of S.meta.sources) {
    if (s.has_key && !before.has(s.name) && !s.active) S.sources.add(s.name);   // newly keyed: enable it
    if (s.name === 'local' && !s.needs_index && !hadIndex) S.sources.add('local');  // index just built
    if ((s.requires_key && !s.has_key) || s.needs_index) S.sources.delete(s.name);
  }
}

// ================================================================== SETTINGS PAGE
const NUM_SETTINGS = [
  ['concurrency', 'Parallel IPs', 'How many IPs are scanned at the same time', 1, 500],
  ['timeout', 'Request timeout', 'Seconds before a source request gives up', 1, 120],
  ['cache_ttl_hours', 'Cache lifetime', 'Hours a lookup is reused before asking the source again', 0, 8760],
  ['probe_limit', 'Probe limit', 'Max websites probed per IP (highest confidence first)', 1, 10000],
  ['max_hosts', 'Max IPs per scan', 'Upper limit when expanding CIDR ranges and ASNs', 1, 16777216],
];
const BOOL_SETTINGS = [
  ['validate', 'Validate DNS', 'Check every domain still points at the IP'],
  ['probe', 'Probe websites', 'Fetch title, server and technologies'],
  ['active', 'Contact servers directly', 'TLS certificates on 10 ports + HTTP(S) to the IP'],
  ['use_cache', 'Use cache', 'Reuse recent lookups'],
  ['allow_private', 'Allow private IPs', 'Include reserved ranges'],
];

const SPEED_SETTINGS = [
  ['roots_only', 'Save root domains only', 'Keep example.com instead of every subdomain (shop.example.com, mail.example.com...). Smaller results and exports'],
  ['local_first', 'Local index first', 'If your own index already knows the IP, answer from it and skip the online data sets. Much faster'],
  ['first_hit', 'Stop at the first match', 'Ask data sets one by one and stop as soon as one finds domains for the IP. Much faster, fewer results'],
  ['skip_scanned', 'Skip IPs scanned before', 'IPs that finished in an earlier scan are not scanned again'],
];
const PRIVACY_SETTINGS = [
  ['save_results_txt', 'Save every domain to results.txt', 'Adds each domain found to results.txt in the IPScope folder (%USERPROFILE%\\.ipscope). The file only grows: nothing is ever removed from it, even if you delete scans'],
  ['hide_sources', 'Hide source names', 'For screen recording: no source names in results, logs or menus (they stay here in Settings)'],
];

function settingToggle([k, name, desc]) {
  return `<div class="setting-row">
    <div><div class="name">${esc(name)}</div><div class="desc">${esc(desc)}</div></div>
    <div class="ctl"><input type="checkbox" data-bool="${k}" ${S.settings[k] ? 'checked' : ''}></div>
  </div>`;
}

async function renderSettings() {
  content().innerHTML = header('Settings', 'Loading...') + loading();
  let cache;
  try { S.settings = await api('get_settings'); cache = await api('cache_stats'); } catch (e) {
    content().innerHTML = header('Settings', '') + `<div class="empty-state">Error: ${esc(errMsg(e))}</div>`; return;
  }
  const st = S.settings;
  const cacheTotal = cache.reduce((a, c) => a + c.count, 0);
  content().innerHTML = `
    ${header('Settings', 'Applied to new scans', '<button class="btn btn-accent" id="btn-save">Save</button>')}
    <div class="split-equal">
      <div>
        <div class="card">
          <div class="section-title mb-8">Scanning</div>
          ${NUM_SETTINGS.map(([k, name, desc, min, max]) => `
            <div class="setting-row">
              <div><div class="name">${esc(name)}</div><div class="desc">${esc(desc)}</div></div>
              <div class="ctl"><input class="input input-sm input-num" type="number" data-num="${k}" min="${min}" max="${max}" value="${esc(st[k])}"></div>
            </div>`).join('')}
        </div>
        <div class="card">
          <div class="section-title mb-8">Results &amp; speed</div>
          ${SPEED_SETTINGS.map(settingToggle).join('')}
        </div>
        <div class="card">
          <div class="section-title mb-8">Defaults for new scans</div>
          ${BOOL_SETTINGS.map(settingToggle).join('')}
        </div>
        <div class="card">
          <div class="section-title mb-8">Privacy</div>
          ${PRIVACY_SETTINGS.map(settingToggle).join('')}
        </div>
      </div>
      <div>
        <div class="card">
          <div class="card-head">
            <div><div class="section-title">Sources</div><div class="section-sub" id="src-count">${S.sources.size} selected · mode: ${esc(modeText())}</div></div>
            <button class="btn btn-ghost btn-xs" data-goto-keys>API keys</button>
          </div>
          <div class="filter-tabs mb-8" id="preset-tabs">${presetTabsHtml()}</div>
          <div class="data-list scroll-sm" id="src-list">${S.meta.sources.filter((x) => !x.active).map(sourceRow).join('')}</div>
        </div>
        <div class="card">
          <div class="card-head">
            <div><div class="section-title">Cache</div><div class="section-sub">${fmtNum(cacheTotal)} cached lookups</div></div>
            <button class="btn btn-red btn-xs" id="btn-cache-clear" ${cacheTotal ? '' : 'disabled'}>Clear</button>
          </div>
          ${cache.length ? `<table class="data-table"><thead><tr><th>Source</th><th style="text-align:right">Cached IPs</th></tr></thead>
            <tbody>${cache.map((c) => `<tr><td class="mono">${esc(c.source)}</td><td class="num">${fmtNum(c.count)}</td></tr>`).join('')}</tbody></table>`
            : '<div class="empty-state">Cache is empty.</div>'}
        </div>
        <div class="card">
          <div class="card-head"><div class="section-title">Data</div><button class="btn btn-ghost btn-xs" id="btn-folder">Open folder</button></div>
          <div class="setting-row"><div class="flex-1"><div class="desc">Data folder</div><div class="mono ellipsis" style="user-select:text">${esc(S.meta.home)}</div></div></div>
          <div class="setting-row"><div class="flex-1"><div class="desc">Database</div><div class="mono ellipsis" style="user-select:text">${esc(S.meta.db)}</div></div></div>
          <div class="setting-row"><div class="flex-1"><div class="desc">Key storage</div><div class="mono ellipsis">${esc(S.meta.keyring)}</div></div></div>
        </div>
        <div class="card compact"><div class="text-xs c-dim" style="padding:4px 6px">Only scan targets you are authorized to test, and follow each data provider's terms of use.</div></div>
      </div>
    </div>`;

  $('#btn-save').onclick = saveSettings;
  const refreshSources = () => {
    $('#preset-tabs').innerHTML = presetTabsHtml();
    $('#src-list').innerHTML = S.meta.sources.filter((x) => !x.active).map(sourceRow).join('');
    $('#src-count').textContent = `${S.sources.size} selected · mode: ${modeText()}`;
    bindSourceRows();
    bindPresetTabs(content(), refreshSources);
  };
  const bindSourceRows = () => {
    $$('#src-list [data-src]').forEach((cb) => {
      cb.onchange = () => {
        cb.checked ? S.sources.add(cb.dataset.src) : S.sources.delete(cb.dataset.src);
        S.preset = null;
        $$('#preset-tabs .filter-tab').forEach((t) => t.classList.remove('active'));
        $('#src-count').textContent = `${S.sources.size} selected · mode: ${modeText()}`;
        persistSources();
      };
    });
    $$('[data-goto-keys]').forEach((b) => { b.onclick = () => go('keys'); });
    $$('[data-goto-index]').forEach((b) => { b.onclick = () => go('index'); });
  };
  bindSourceRows();
  bindPresetTabs(content(), refreshSources);
  $('#btn-folder').onclick = async () => { try { await api('open_folder'); } catch (e) { toast('Error: ' + errMsg(e), 'error'); } };
  $('#btn-cache-clear').onclick = async () => {
    if (!(await askConfirm(`All ${fmtNum(cacheTotal)} cached lookups will be removed. The next scans will query every source again.`, 'Clear'))) return;
    try { const r = await api('cache_clear'); toast(`Removed ${fmtNum(r.removed)} cached lookups`); renderSettings(); }
    catch (e) { toast('Error: ' + errMsg(e), 'error'); }
  };
}

async function saveSettings() {
  const values = {};
  for (const inp of $$('[data-num]')) {
    const v = Number(inp.value);
    if (!Number.isFinite(v) || v < Number(inp.min) || v > Number(inp.max)) {
      toast(`Invalid value: ${inp.closest('.setting-row').querySelector('.name').textContent}`, 'error');
      inp.focus();
      return;
    }
    values[inp.dataset.num] = v;
  }
  $$('[data-bool]').forEach((cb) => { values[cb.dataset.bool] = cb.checked; });
  values.sources = [...S.sources];
  values.preset = S.preset;
  try {
    S.settings = await api('save_settings', values);
    BOOL_SETTINGS.forEach(([k]) => { S.opts[k] = !!S.settings[k]; });
    applyPrivacy();
    toast('Settings saved', 'success');
  } catch (e) { toast('Error: ' + errMsg(e), 'error'); }
}

// ================================================================== polling
let polling = false;
async function poll() {
  if (polling) return;
  polling = true;
  try {
    const prev = S.job.state;
    const st = await api('get_state', S.logCursor);
    S.job = st;
    if (st.logs.length) {
      S.logs.push(...st.logs);
      if (S.logs.length > 1500) S.logs.splice(0, S.logs.length - 1500);
      S.logCursor = st.cursor;
      drawLogs();
    }
    updateBusyUi();
    updateScanLive();

    if (BUSY.includes(prev) && !BUSY.includes(st.state)) {
      if (st.state === 'done') toast(`Scan #${st.scan_id} completed · ${fmtNum(st.found)} domains`, 'success');
      else if (st.state === 'paused') toast(`Scan #${st.scan_id} paused`);
      else if (st.state === 'error') toast('Scan failed - see the log', 'error');
      refreshBadge();
      if (S.page === 'history') renderHistory();
      if (S.page === 'results' && S.results.scanId === st.scan_id) renderResults();
    } else if (isBusy() && S.page === 'results' && S.results.scanId === st.scan_id && Date.now() - S.lastReload > 4000) {
      S.lastReload = Date.now();   // live refresh while the open scan is still running
      refreshResultsLive();
    }
  } catch { /* backend busy or not ready */ }
  polling = false;
}

// ================================================================== init
async function init() {
  $$('[data-icon]').forEach((el) => { el.innerHTML = ICONS[el.dataset.icon] || ''; });
  $$('.nav-btn').forEach((b) => { b.onclick = () => go(b.dataset.page); });
  $('#sidebar-btn').onclick = () => (isBusy() ? stopScan() : startScan());
  try {
    S.meta = await api('get_meta');
    S.settings = await api('get_settings');
  } catch (e) {
    content().innerHTML = `<div class="empty-state">Error: ${esc(errMsg(e))}</div>`;
    return;
  }
  $('#brand-version').textContent = 'v' + S.meta.version;
  BOOL_SETTINGS.forEach(([k]) => { S.opts[k] = !!S.settings[k]; });
  restoreSources();
  applyPrivacy();
  render();
  refreshBadge();
  poll();
  setInterval(poll, 700);
  setInterval(pollIndex, 800);
}

if (window.pywebview && window.pywebview.api) init();
else window.addEventListener('pywebviewready', init, { once: true });
