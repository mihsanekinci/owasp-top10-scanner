'use strict';

const MODULE_LABELS = {
  A01: 'Broken Access Control',
  A02: 'Cryptographic Failures',
  A03: 'Injection (SQLi + XSS)',
  A04: 'Insecure Design',
  A05: 'Security Misconfiguration',
  A06: 'Vulnerable Components',
  A07: 'Auth Failures',
  A08: 'Data Integrity',
  A09: 'Logging & Monitoring',
  A10: 'SSRF',
};

const ALL_MODULES = Object.keys(MODULE_LABELS);

const SEVERITY_ORDER = ['Kritik', 'Yüksek', 'Orta', 'Düşük', 'Bilgilendirici'];

let currentScanId = null;
let ws = null;
let liveFindings = [];

// ---------- Sayfa başlatma ----------

function initPage() {
  buildModuleGrid();
  loadQuickTargets();
  loadLLMModels();
  loadRAGStatus();
  toggleLLMSection();
}

// ---------- LLM Model seçimi ----------

let _availableModels = [];

async function loadLLMModels() {
  const list = document.getElementById('llmModelList');
  const hint = document.getElementById('llmModelHint');
  if (!list) return;
  list.innerHTML = '<div class="empty" style="grid-column:1/-1">Ollama modelleri yükleniyor...</div>';
  try {
    const res = await fetch('/api/llm-models');
    const data = await res.json();
    if (!data.available) {
      list.innerHTML = `<div class="empty" style="grid-column:1/-1">Ollama'ya bağlanılamadı: ${data.error || 'bilinmiyor'}</div>`;
      hint.textContent = 'LLM kullanmadan da tarama yapabilirsiniz (AI Analizi toggle\'ını kapatın).';
      return;
    }
    _availableModels = data.models || [];
    if (!_availableModels.length) {
      list.innerHTML = '<div class="empty" style="grid-column:1/-1">Ollama\'da yüklü model yok. Örnek: <code>ollama pull llama3</code></div>';
      return;
    }
    // İlk modeli varsayılan olarak seç
    list.innerHTML = _availableModels.map((m, i) => `
      <label class="module-chip${i === 0 ? ' checked' : ''}" id="llmchip-${cssId(m.name)}">
        <input type="checkbox" value="${escAttr(m.name)}" ${i === 0 ? 'checked' : ''} onchange="updateLLMChip('${cssId(m.name)}')" />
        <span>${escHtml(m.name)}</span>
        <span style="color:var(--color-muted);font-size:11px">${humanSize(m.size)}</span>
      </label>
    `).join('');
    hint.textContent = `${_availableModels.length} model bulundu. Embedding modeli: ${data.embed_model_ready ? '✓ hazır (RAG aktif olabilir)' : '✗ yok (nomic-embed-text önerilir)'}`;
  } catch (e) {
    list.innerHTML = `<div class="empty" style="grid-column:1/-1">Hata: ${e.message}</div>`;
  }
}

function updateLLMChip(idSlug) {
  const chip = document.getElementById(`llmchip-${idSlug}`);
  const cb = chip.querySelector('input');
  chip.classList.toggle('checked', cb.checked);
}

function getSelectedLLMModels() {
  return [...document.querySelectorAll('#llmModelList input:checked')].map(c => c.value);
}

function toggleLLMSection() {
  const enabled = document.getElementById('llmToggle').checked;
  const section = document.getElementById('llmSection');
  if (section) section.style.opacity = enabled ? '1' : '0.45';
  if (section) section.style.pointerEvents = enabled ? 'auto' : 'none';
}

async function loadRAGStatus() {
  const txt = document.getElementById('ragStatusText');
  if (!txt) return;
  try {
    const res = await fetch('/api/rag/status');
    const data = await res.json();
    if (data.available) {
      txt.textContent = `(${data.chunk_count || 0} chunk, ${data.embed_model || ''})`;
    } else {
      txt.textContent = '(devre dışı — chromadb veya nomic-embed-text eksik)';
      const cb = document.getElementById('ragToggle');
      if (cb) { cb.checked = false; cb.disabled = true; }
    }
  } catch {
    txt.textContent = '';
  }
  updateRAGWarning();
}

function updateRAGWarning() {
  const cb = document.getElementById('ragToggle');
  const warn = document.getElementById('ragWarning');
  if (!cb || !warn) return;
  // Sadece kullanıcı kapattığında uyar (disabled = altyapı eksik, başka mesaj zaten var)
  warn.style.display = (!cb.checked && !cb.disabled) ? 'block' : 'none';
}

function humanSize(bytes) {
  if (!bytes) return '';
  const gb = bytes / 1024 / 1024 / 1024;
  if (gb >= 1) return gb.toFixed(1) + ' GB';
  const mb = bytes / 1024 / 1024;
  return mb.toFixed(0) + ' MB';
}

function cssId(name) {
  return name.replace(/[^a-zA-Z0-9]/g, '_');
}

function escAttr(s) {
  return String(s).replace(/"/g, '&quot;');
}

function buildModuleGrid() {
  const grid = document.getElementById('moduleGrid');
  if (!grid) return;
  grid.innerHTML = ALL_MODULES.map(id => `
    <label class="module-chip checked" id="chip-${id}">
      <input type="checkbox" value="${id}" checked onchange="updateChip('${id}')" />
      <span>${id}</span>
      <span style="color:var(--color-muted);font-size:11px">${MODULE_LABELS[id]}</span>
    </label>
  `).join('');
}

function updateChip(id) {
  const chip = document.getElementById(`chip-${id}`);
  const cb = chip.querySelector('input');
  chip.classList.toggle('checked', cb.checked);
}

function selectAllModules(val) {
  document.querySelectorAll('#moduleGrid input[type=checkbox]').forEach(cb => {
    cb.checked = val;
    updateChip(cb.value);
  });
}

let _testTargets = [];

async function loadQuickTargets() {
  const el = document.getElementById('quickTargets');
  if (!el) return;
  try {
    const res = await fetch('/api/targets');
    _testTargets = await res.json();
    el.innerHTML = _testTargets.map((t, i) => `
      <button class="target-btn" onclick="selectTarget(${i})">${t.name}</button>
    `).join('');
  } catch {
    el.innerHTML = '<span style="color:var(--color-muted);font-size:12px">Test ortamı yüklenmedi</span>';
  }
}

async function selectTarget(idx) {
  const t = _testTargets[idx];
  if (!t) return;
  document.getElementById('targetUrl').value = t.url;

  if (t.name === 'DVWA') {
    setStatus('DVWA otomatik setup yapılıyor (DB kurulumu + login)...');
    document.getElementById('cookieInput').value = '';
    try {
      const res = await fetch('/api/targets/dvwa/setup', { method: 'POST' });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        setStatus('DVWA setup başarısız: ' + (err.detail || res.status));
        return;
      }
      const data = await res.json();
      document.getElementById('cookieInput').value = data.cookie;
      setStatus('DVWA hazır. Tarama başlatabilirsiniz.');
    } catch (e) {
      setStatus('DVWA setup hatası: ' + e.message);
    }
    return;
  }

  if (t.note) {
    document.getElementById('cookieInput').value = t.note.replace('Cookie gerekli: ', '');
  }
}

// ---------- Tarama ----------

function getSelectedModules() {
  return [...document.querySelectorAll('#moduleGrid input:checked')].map(c => c.value);
}

async function startScan() {
  const target = document.getElementById('targetUrl').value.trim();
  if (!target) { alert('Hedef URL giriniz.'); return; }

  const modules = getSelectedModules();
  if (!modules.length) { alert('En az bir modül seçiniz.'); return; }

  const llmEnabled = document.getElementById('llmToggle').checked;
  const selectedModels = llmEnabled ? getSelectedLLMModels() : [];
  if (llmEnabled && !selectedModels.length) {
    alert('LLM açık ama hiç model seçilmedi. En az bir model seçin veya AI Analizi\'ni kapatın.');
    return;
  }

  const body = {
    target,
    modules,
    no_llm: !llmEnabled,
    cookie: document.getElementById('cookieInput').value.trim() || null,
    timeout: parseInt(document.getElementById('timeoutInput').value) || 5,
    // Tek model seçildiyse llm_model, birden fazla ise llm_models gönder
    llm_model: selectedModels.length === 1 ? selectedModels[0] : null,
    llm_models: selectedModels.length > 1 ? selectedModels : null,
    use_rag: document.getElementById('ragToggle').checked && !document.getElementById('ragToggle').disabled,
  };

  try {
    const res = await fetch('/api/scan/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (res.status === 429) { alert('Maksimum tarama limitine ulaşıldı. Lütfen bekleyin.'); return; }
    if (!res.ok) { alert('Tarama başlatılamadı.'); return; }
    const data = await res.json();
    connectWS(data.scan_id, modules);
  } catch (e) {
    alert('Sunucuya bağlanılamadı: ' + e.message);
  }
}

async function cancelScan() {
  if (!currentScanId) return;
  await fetch(`/api/scan/${currentScanId}`, { method: 'DELETE' });
}

// ---------- WebSocket ----------

function connectWS(scanId, modules) {
  currentScanId = scanId;
  liveFindings = [];

  document.getElementById('startBtn').disabled = true;
  document.getElementById('cancelBtn').style.display = 'inline-flex';
  document.getElementById('progressCard').style.display = 'block';
  document.getElementById('findingsCard').style.display = 'block';
  document.getElementById('findingList').innerHTML = '<div class="empty">Bulgular bekleniyor...</div>';
  document.getElementById('findingCount').textContent = '';
  document.getElementById('logPanel').innerHTML = '';
  document.getElementById('statusText').textContent = 'Bağlanıyor...';

  buildProgressBar(modules);

  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}/ws/${scanId}`);

  ws.onopen = () => setStatus('Taranıyor...');

  ws.onmessage = e => {
    try { handleEvent(JSON.parse(e.data), modules); } catch {}
  };

  ws.onclose = () => {
    document.getElementById('startBtn').disabled = false;
    document.getElementById('cancelBtn').style.display = 'none';
  };

  ws.onerror = () => setStatus('Bağlantı hatası');
}

function handleEvent(evt, modules) {
  switch (evt.type) {
    case 'scan_started':
      setStatus(`Tarama başladı → ${evt.target}`);
      break;

    case 'module_begin':
      setStatus(evt.description || `${evt.module} taranıyor...`);
      markProgress(modules, evt.module, 'active');
      appendLog(`[${evt.module}] ${evt.description || ''}`, 'module');
      break;

    case 'module_done':
      markProgress(modules, evt.module, 'done');
      appendLog(`[${evt.module}] Tamamlandı — ${evt.finding_count} bulgu`);
      break;

    case 'log':
      appendLog(evt.message, evt.level);
      break;

    case 'scan_complete':
      setStatus(`Tamamlandı — ${evt.total_findings} bulgu (${evt.duration}s)`);
      markProgress(modules, null, 'done');
      if (evt.report) {
        window._lastReport = evt.report;
        window._lastScanId = evt.report_id;
        if (evt.report.findings) renderFindings(evt.report.findings);
        showResultActions(evt.report_id);
      }
      loadHistory();
      break;

    case 'scan_cancelled':
      setStatus('Tarama iptal edildi.');
      break;

    case 'scan_error':
      setStatus('Hata: ' + evt.message);
      appendLog('HATA: ' + evt.message, 'ERROR');
      break;
  }
}

// ---------- Progress bar ----------

function buildProgressBar(modules) {
  const bar = document.getElementById('progressBar');
  bar.innerHTML = modules.map(m => `<div class="progress-segment" id="seg-${m}" title="${m}: ${MODULE_LABELS[m]}"></div>`).join('');
}

function markProgress(modules, activeModule, state) {
  if (state === 'done' && !activeModule) {
    modules.forEach(m => {
      const seg = document.getElementById(`seg-${m}`);
      if (seg && !seg.classList.contains('done')) seg.classList.add('done');
    });
    return;
  }
  const seg = document.getElementById(`seg-${activeModule}`);
  if (!seg) return;
  seg.className = 'progress-segment ' + state;
  document.getElementById('activeModule').textContent =
    state === 'active' ? `${activeModule}: ${MODULE_LABELS[activeModule] || ''}` : '';
}

// ---------- Log ----------

function appendLog(msg, level) {
  const panel = document.getElementById('logPanel');
  const div = document.createElement('div');
  div.className = 'log-line' + (level ? ' ' + level : '');
  div.textContent = msg;
  panel.appendChild(div);
  panel.scrollTop = panel.scrollHeight;
}

// ---------- Findings ----------

function renderFindings(findings) {
  const list = document.getElementById('findingList');
  liveFindings = findings;
  list.innerHTML = '';

  if (!findings.length) {
    list.innerHTML = '<div class="empty">Bulgu bulunamadı.</div>';
    document.getElementById('findingCount').textContent = '(0)';
    return;
  }

  document.getElementById('findingCount').textContent = `(${findings.length})`;
  findings.forEach((f, i) => list.appendChild(buildFindingCard(f, i)));
}

function buildFindingCard(f, idx) {
  const card = document.createElement('div');
  card.className = 'finding-card';
  card.innerHTML = `
    <div class="finding-header" onclick="toggleCard(this)">
      <span class="owasp-id">${f.owasp_id}</span>
      <span class="title">${escHtml(f.title)}</span>
      <span class="badge badge-${f.severity}">${f.severity}</span>
      <span class="badge badge-${f.confidence}">${f.confidence}</span>
      <span class="chevron">▶</span>
    </div>
    <div class="finding-body">
      <div class="detail-grid">
        <span class="detail-label">URL</span>
        <span class="detail-value">${escHtml(f.url)}</span>
        <span class="detail-label">Parametre</span>
        <span class="detail-value">${escHtml(f.parameter || '—')}</span>
        <span class="detail-label">Metod</span>
        <span class="detail-value">${escHtml(f.method || 'GET')}</span>
        <span class="detail-label">Payload</span>
        <span class="detail-value">${escHtml(f.payload || '—')}</span>
        ${f.response_snippet ? `
        <span class="detail-label">Yanıt</span>
        <span class="detail-value">${escHtml(f.response_snippet.substring(0, 300))}</span>
        ` : ''}
      </div>
      ${buildRAGPanel(f)}
      ${buildLLMPanel(f)}
    </div>
  `;
  return card;
}

function buildRAGPanel(f) {
  if (!f.rag_used || !f.rag_sources || !f.rag_sources.length) return '';
  return `
    <div class="llm-panel" style="border-left:3px solid #8b5cf6;background:rgba(139,92,246,.06)">
      <h4 style="color:#8b5cf6">📚 RAG — Kullanılan Bilgi Kaynakları</h4>
      <div class="llm-field" style="font-size:11px;color:var(--color-muted)">
        ${f.rag_sources.map(s => `<code>${escHtml(s)}</code>`).join(' · ')}
      </div>
    </div>
  `;
}

function buildLLMPanel(f) {
  // Çoklu LLM modu
  if (f.llm_analyses && Object.keys(f.llm_analyses).length > 0) {
    return buildMultiLLMPanel(f.llm_analyses, f.llm_comparison);
  }
  // Tek LLM modu (geriye dönük uyumlu)
  const llm = f.llm_analysis;
  if (!llm || llm.llm_hatasi) return '';
  return buildSingleLLMPanel(llm, 'AI Analizi');
}

function buildSingleLLMPanel(llm, title) {
  const onlemler = (llm.genel_onlemler || []).map(o => `<li>${escHtml(o)}</li>`).join('');
  return `
    <div class="llm-panel">
      <h4>🤖 ${escHtml(title || 'AI Analizi')}</h4>
      <div class="llm-field"><strong>Risk:</strong> <span class="badge badge-${escAttr(llm.risk_seviyesi || '')}">${escHtml(llm.risk_seviyesi || '')}</span> &nbsp; <strong>Güven:</strong> ${escHtml(llm.llm_guven || '')}</div>
      <div class="llm-field"><strong>Açıklama:</strong> ${escHtml(llm.teknik_aciklama || '')}</div>
      <div class="llm-field"><strong>Düzeltme:</strong> ${escHtml(llm.kod_duzeltme || '')}</div>
      ${onlemler ? `<div class="llm-field"><strong>Önlemler:</strong><ul style="margin:4px 0 0 16px;font-size:12px">${onlemler}</ul></div>` : ''}
    </div>
  `;
}

function buildMultiLLMPanel(analyses, comparison) {
  const models = Object.keys(analyses);
  const tabId = 'tabs_' + Math.random().toString(36).slice(2, 8);

  // Konsensüs özeti
  let consensusHtml = '';
  if (comparison) {
    const votes = comparison.risk_votes || {};
    const voteText = Object.entries(votes)
      .map(([risk, count]) => `<span class="badge badge-${escAttr(risk)}">${escHtml(risk)} ×${count}</span>`)
      .join(' ');
    consensusHtml = `
      <div style="display:flex;gap:14px;align-items:center;flex-wrap:wrap;margin-bottom:12px;padding:8px 10px;background:rgba(34,197,94,.08);border-radius:6px;border-left:3px solid #22c55e">
        <div><strong>Konsensüs:</strong> <span class="badge badge-${escAttr(comparison.risk_consensus)}">${escHtml(comparison.risk_consensus || '?')}</span></div>
        <div style="font-size:12px;color:var(--color-muted)">Oylar: ${voteText || '—'}</div>
        ${comparison.error_count ? `<div style="font-size:12px;color:#ef4444">Hatalı: ${comparison.error_count}</div>` : ''}
      </div>
    `;
  }

  // Sekme başlıkları
  const tabs = models.map((m, i) => {
    const a = analyses[m] || {};
    const errMark = a.llm_hatasi ? ' ⚠' : '';
    return `<button class="llm-tab${i === 0 ? ' active' : ''}" onclick="switchLLMTab('${tabId}', ${i}, this)">${escHtml(m)}${errMark}</button>`;
  }).join('');

  // Sekme içerikleri
  const panes = models.map((m, i) => {
    const a = analyses[m] || {};
    if (a.llm_hatasi) {
      return `
        <div class="llm-tab-pane${i === 0 ? ' active' : ''}">
          <div style="color:#ef4444;font-size:13px">⚠ Bu model yanıt veremedi: ${escHtml(a.hata_nedeni || 'bilinmiyor')}</div>
        </div>
      `;
    }
    const onlemler = (a.genel_onlemler || []).map(o => `<li>${escHtml(o)}</li>`).join('');
    return `
      <div class="llm-tab-pane${i === 0 ? ' active' : ''}">
        <div class="llm-field"><strong>Risk:</strong> <span class="badge badge-${escAttr(a.risk_seviyesi || '')}">${escHtml(a.risk_seviyesi || '')}</span> &nbsp; <strong>Güven:</strong> ${escHtml(a.llm_guven || '')}</div>
        <div class="llm-field"><strong>Açıklama:</strong> ${escHtml(a.teknik_aciklama || '')}</div>
        <div class="llm-field"><strong>Düzeltme:</strong> ${escHtml(a.kod_duzeltme || '')}</div>
        ${onlemler ? `<div class="llm-field"><strong>Önlemler:</strong><ul style="margin:4px 0 0 16px;font-size:12px">${onlemler}</ul></div>` : ''}
      </div>
    `;
  }).join('');

  return `
    <div class="llm-panel" id="${tabId}">
      <h4>🤖 Çoklu LLM Karşılaştırması <span style="color:var(--color-muted);font-weight:400;font-size:12px">(${models.length} model)</span></h4>
      ${consensusHtml}
      <div class="llm-tabs">${tabs}</div>
      <div class="llm-tab-panes">${panes}</div>
    </div>
  `;
}

function switchLLMTab(tabId, idx, btn) {
  const root = document.getElementById(tabId);
  if (!root) return;
  root.querySelectorAll('.llm-tab').forEach(t => t.classList.remove('active'));
  root.querySelectorAll('.llm-tab-pane').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  const panes = root.querySelectorAll('.llm-tab-pane');
  if (panes[idx]) panes[idx].classList.add('active');
}

function toggleCard(header) {
  header.closest('.finding-card').classList.toggle('open');
}

// ---------- Tarama Geçmişi ----------

async function loadHistory() {
  const el = document.getElementById('historyList');
  if (!el) return;
  try {
    const res = await fetch('/api/scans');
    const scans = await res.json();
    if (!scans.length) {
      el.innerHTML = '<div class="empty">Henüz tarama yapılmadı.</div>';
      return;
    }
    el.innerHTML = `
      <table style="width:100%;font-size:12px;border-collapse:collapse">
        <thead>
          <tr style="text-align:left;color:var(--color-muted);border-bottom:1px solid var(--color-border)">
            <th style="padding:6px 4px">Hedef</th>
            <th style="padding:6px 4px">Modüller</th>
            <th style="padding:6px 4px">Durum</th>
            <th style="padding:6px 4px">Bulgu</th>
            <th style="padding:6px 4px">Zaman</th>
            <th style="padding:6px 4px"></th>
          </tr>
        </thead>
        <tbody>
          ${scans.map(s => historyRow(s)).join('')}
        </tbody>
      </table>
    `;
  } catch {
    el.innerHTML = '<div class="empty">Geçmiş yüklenemedi.</div>';
  }
}

function historyRow(s) {
  const time = new Date(s.started_at * 1000).toLocaleString('tr-TR');
  const statusColor = {
    done: '#22c55e', running: 'var(--color-accent)',
    error: 'var(--color-kritik)', cancelled: 'var(--color-muted)'
  }[s.status] || 'var(--color-muted)';
  const findings = s.total_findings != null ? s.total_findings : '—';
  const mods = (s.modules || []).length === 10 ? 'Tümü' : (s.modules || []).join(',');
  return `
    <tr style="border-bottom:1px solid var(--color-border)">
      <td style="padding:8px 4px;font-family:monospace;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(s.target)}">${escHtml(s.target)}</td>
      <td style="padding:8px 4px;color:var(--color-muted)">${mods}</td>
      <td style="padding:8px 4px;color:${statusColor}">${s.status}</td>
      <td style="padding:8px 4px">${findings}</td>
      <td style="padding:8px 4px;color:var(--color-muted)">${time}</td>
      <td style="padding:8px 4px;text-align:right">
        ${s.status === 'done' ? `<a href="/report/${s.scan_id}" target="_blank" class="btn btn-ghost btn-sm">Raporu Aç</a>` : ''}
      </td>
    </tr>
  `;
}

// ---------- Sonuç aksiyon butonları ----------

function showResultActions(scanId) {
  let bar = document.getElementById('resultActions');
  if (!bar) {
    bar = document.createElement('div');
    bar.id = 'resultActions';
    bar.style.cssText = 'display:flex;gap:8px;margin-top:14px;flex-wrap:wrap';
    document.getElementById('progressCard').appendChild(bar);
  }
  bar.innerHTML = `
    <a href="/report/${scanId}" target="_blank" class="btn btn-primary btn-sm">📋 Detaylı Rapor (Yeni Sekme)</a>
    <button class="btn btn-ghost btn-sm" onclick="downloadCurrentReport()">⬇ JSON İndir</button>
    <button class="btn btn-ghost btn-sm" onclick="downloadAsText()">📄 TXT İndir</button>
    <button class="btn btn-ghost btn-sm" onclick="printReport()">🖨 Yazdır</button>
    <button class="btn btn-ghost btn-sm" onclick="copyReportToClipboard()">📋 Panoya Kopyala</button>
  `;
}

function downloadCurrentReport() {
  if (!window._lastReport) return;
  const blob = new Blob([JSON.stringify(window._lastReport, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `rapor_${window._lastScanId || 'tarama'}.json`;
  a.click();
}

function downloadAsText() {
  if (!window._lastReport) return;
  const txt = reportToText(window._lastReport);
  const blob = new Blob([txt], { type: 'text/plain;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `rapor_${window._lastScanId || 'tarama'}.txt`;
  a.click();
}

function copyReportToClipboard() {
  if (!window._lastReport) return;
  navigator.clipboard.writeText(reportToText(window._lastReport))
    .then(() => alert('Rapor panoya kopyalandı.'))
    .catch(() => alert('Kopyalama başarısız.'));
}

function printReport() {
  if (!window._lastReport) return;
  const html = reportToHtml(window._lastReport);
  const win = window.open('', '_blank');
  win.document.write(html);
  win.document.close();
  win.focus();
  setTimeout(() => win.print(), 500);
}

function reportToText(report) {
  const info = report.scan_info || {};
  const sum = report.summary || {};
  const findings = report.findings || [];
  const bd = sum.severity_breakdown || {};
  let out = '';
  out += '═══════════════════════════════════════════════════════════\n';
  out += '  AI DESTEKLI WEB ZAFIYET TARAYICISI - RAPOR\n';
  out += '═══════════════════════════════════════════════════════════\n\n';
  out += `Hedef        : ${info.target || ''}\n`;
  out += `Tarih        : ${info.timestamp || ''}\n`;
  out += `Süre         : ${info.duration_seconds || 0} saniye\n`;
  out += `Modüller     : ${(info.modules_run || []).join(', ')}\n`;
  const llmLabel = info.llm_enabled
    ? (info.llm_models && info.llm_models.length ? info.llm_models.join(', ') : (info.llm_model || ''))
    : 'Kapalı';
  out += `LLM          : ${llmLabel}\n`;
  out += `RAG          : ${info.rag_enabled ? 'Açık' : 'Kapalı'}\n`;
  out += `Toplam Bulgu : ${sum.total_findings || 0}\n\n`;
  out += `Önem Dağılımı:\n`;
  ['Kritik', 'Yüksek', 'Orta', 'Düşük', 'Bilgilendirici'].forEach(s => {
    if (bd[s]) out += `  - ${s.padEnd(15)} : ${bd[s]}\n`;
  });
  out += '\n═══════════════════════════════════════════════════════════\n';
  out += '  BULGULAR\n';
  out += '═══════════════════════════════════════════════════════════\n\n';
  findings.forEach((f, i) => {
    out += `[${i + 1}] ${f.owasp_id} | ${f.title}\n`;
    out += `    Önem     : ${f.severity}  (Güven: ${f.confidence})\n`;
    out += `    URL      : ${f.url}\n`;
    out += `    Parametre: ${f.parameter || '—'}\n`;
    out += `    Metod    : ${f.method || 'GET'}\n`;
    out += `    Payload  : ${f.payload || '—'}\n`;
    if (f.response_snippet) {
      out += `    Yanıt    : ${f.response_snippet.substring(0, 200).replace(/\n/g, ' ')}\n`;
    }
    if (f.rag_used && f.rag_sources && f.rag_sources.length) {
      out += `    RAG Kaynak: ${f.rag_sources.join(', ')}\n`;
    }
    // Çoklu LLM
    if (f.llm_analyses && Object.keys(f.llm_analyses).length) {
      if (f.llm_comparison) {
        out += `    Konsensüs : ${f.llm_comparison.risk_consensus || '?'}`;
        const votes = f.llm_comparison.risk_votes || {};
        const voteStr = Object.entries(votes).map(([k, v]) => `${k}×${v}`).join(', ');
        if (voteStr) out += ` (${voteStr})`;
        out += '\n';
      }
      Object.entries(f.llm_analyses).forEach(([model, l]) => {
        out += `    ── ${model} ──\n`;
        if (l.llm_hatasi) {
          out += `      ⚠ Yanıt alınamadı: ${l.hata_nedeni || 'bilinmiyor'}\n`;
          return;
        }
        out += `      Risk     : ${l.risk_seviyesi || ''}\n`;
        out += `      Açıklama : ${l.teknik_aciklama || ''}\n`;
        out += `      Düzeltme : ${l.kod_duzeltme || ''}\n`;
        if (l.genel_onlemler && l.genel_onlemler.length) {
          out += `      Önlemler :\n`;
          l.genel_onlemler.forEach(o => out += `        • ${o}\n`);
        }
      });
    } else if (f.llm_analysis && !f.llm_analysis.llm_hatasi) {
      const l = f.llm_analysis;
      out += `    AI ANALIZ:\n`;
      out += `      Risk     : ${l.risk_seviyesi || ''}\n`;
      out += `      Açıklama : ${l.teknik_aciklama || ''}\n`;
      out += `      Düzeltme : ${l.kod_duzeltme || ''}\n`;
      if (l.genel_onlemler && l.genel_onlemler.length) {
        out += `      Önlemler :\n`;
        l.genel_onlemler.forEach(o => out += `        • ${o}\n`);
      }
    }
    out += '\n' + '─'.repeat(63) + '\n\n';
  });
  return out;
}

function reportToHtml(report) {
  const txt = reportToText(report);
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Tarama Raporu</title>
    <style>body{font-family:monospace;font-size:12px;white-space:pre-wrap;padding:20px;line-height:1.5;}</style>
    </head><body>${escHtml(txt)}</body></html>`;
}

// ---------- Yardımcılar ----------

function setStatus(msg) {
  document.getElementById('statusText').textContent = msg;
}

function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
