/* 应急响应仪表盘共享工具函数 */

const API = {
  async get(url) {
    const resp = await fetch(url);
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({error: resp.statusText}));
      throw new Error(err.error || err.detail || resp.statusText);
    }
    return resp.json();
  },
  async post(url, data) {
    const resp = await fetch(url, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(data),
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({error: resp.statusText}));
      throw new Error(err.error || err.detail || resp.statusText);
    }
    return resp.json();
  },
  async put(url, data) {
    const resp = await fetch(url, {
      method: 'PUT',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(data),
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({error: resp.statusText}));
      throw new Error(err.error || err.detail || resp.statusText);
    }
    return resp.json();
  },
  async del(url) {
    const resp = await fetch(url, { method: 'DELETE' });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({error: resp.statusText}));
      throw new Error(err.error || err.detail || resp.statusText);
    }
    return resp.json();
  },
};

const SEVERITY_CLASS = {
  CRITICAL: 'badge-critical', HIGH: 'badge-high', MEDIUM: 'badge-medium',
  LOW: 'badge-low', INFO: 'badge-info',
};

function formatDate(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  return d.toLocaleString('zh-CN', {month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hour12: false});
}

function formatPct(v) { return (v * 100).toFixed(0) + '%'; }
function truncate(s, len) { return (s && s.length > len) ? s.slice(0, len) + '…' : s || '-'; }

function showToast(msg, type) {
  const el = document.createElement('div');
  el.className = 'toast toast-' + type;
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => { el.remove(); }, 3000);
}

function showModal(id) { document.getElementById(id).classList.add('open'); }
function hideModal(id) { document.getElementById(id).classList.remove('open'); }

function severityBadge(s) {
  const cls = SEVERITY_CLASS[s] || 'badge-info';
  return `<span class="badge ${cls}">${s}</span>`;
}

function categoryBadge(cat) {
  const colors = {
    policy: {bg:'#1a237e', txt:'#7986cb'},
    case: {bg:'#1b5e20', txt:'#81c784'},
    pattern: {bg:'#e65100', txt:'#ffb74d'},
    role_insight: {bg:'#4a148c', txt:'#ce93d8'},
    best_practice: {bg:'#01579b', txt:'#4fc3f7'},
  };
  const c = colors[cat] || {bg:'#333', txt:'#ccc'};
  const label = cat.replace(/_/g, ' ');
  return `<span class="badge" style="background:${c.bg};color:${c.txt};">${label}</span>`;
}

function healthImpactBadge(s) {
  return s === 'improved' ? '<span class="badge badge-improved">improved</span>' :
         s === 'degraded' ? '<span class="badge badge-degraded">degraded</span>' :
         '<span class="badge badge-unchanged">unchanged</span>';
}

function dispositionBadge(d) {
  const cls = d === 'auto_block' ? 'badge-critical' :
              d === 'escalate' ? 'badge-high' :
              d === 'notify_email' ? 'badge-medium' :
              d === 'auto_log' ? 'badge-low' : 'badge-info';
  return `<span class="badge ${cls}">${d}</span>`;
}

function statusBadge(s) {
  const cls = s === 'completed' ? 'badge-low' :
              s === 'failed' ? 'badge-critical' : 'badge-medium';
  return `<span class="badge ${cls}">${s}</span>`;
}

// Chart.js 暗色主题默认配置
if (typeof Chart !== 'undefined') {
  Chart.defaults.color = '#9e9e9e';
  Chart.defaults.borderColor = '#333640';
  Chart.defaults.font.family = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
}
