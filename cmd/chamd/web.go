package main

import (
	"log"
	"encoding/json"
	"net/http"
	"strconv"

	"chameleon/internal/chameleon"
)

// Локальная панель управления: http://127.0.0.1:8080
// API + современный одностраничный интерфейс с вкладками (Обзор / Серверы / Безопасность / Журнал).

func serveUI(addr string, m *Manager) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(indexHTML))
	})

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, m.Status())
	})

	mux.HandleFunc("/api/suspicious/clear", func(w http.ResponseWriter, r *http.Request) {
		if m.suspicious != nil {
			m.suspicious.Clear()
		}
		writeJSON(w, map[string]bool{"ok": true})
	})

	mux.HandleFunc("/api/servers", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			var in struct {
				Name   string `json:"name"`
				Addr   string `json:"addr"`
				PubKey string `json:"pubkey"`
			}
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Addr == "" {
				http.Error(w, `{"error":"нужен addr (host:port)"}`, http.StatusBadRequest)
				return
			}
			if _, err := chameleon.ParseNodePubKey(in.PubKey); err != nil {
				http.Error(w, `{"error":"публичный ключ ноды невалиден: `+err.Error()+`"}`, http.StatusBadRequest)
				return
			}
			i, err := m.store.Add(in.Name, in.Addr, in.PubKey)
			if err != nil {
				http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
				return
			}
			m.logf("добавлен сервер %s (%s)", in.Name, in.Addr)
			writeJSON(w, map[string]any{"index": i, "ok": true})
		case http.MethodDelete:
			i, err := strconv.Atoi(r.URL.Query().Get("id"))
			if err != nil {
				http.Error(w, `{"error":"невалидный id сервера"}`, http.StatusBadRequest)
				return
			}
			if err := m.store.Del(i); err != nil {
				http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
				return
			}
			m.logf("удалён сервер #%d", i)
			writeJSON(w, map[string]bool{"ok": true})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/connect", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ID int `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, `{"error":"нужен id сервера"}`, http.StatusBadRequest)
			return
		}
		if err := m.Connect(in.ID); err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})

	mux.HandleFunc("/api/disconnect", func(w http.ResponseWriter, r *http.Request) {
		m.Disconnect()
		writeJSON(w, map[string]bool{"ok": true})
	})

	ln, actual, err := listenTCP(m, addr, "панель")
	if err != nil {
		return err
	}
	m.SetListenAddr("ui", actual)
	log.Printf("chamd: панель слушает http://%s", actual)
	return http.Serve(ln, mux)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

const indexHTML = `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Chameleon CITP Control Center</title>
<style>
  :root {
    --bg: #090d16;
    --card-bg: #111726;
    --card-border: #1e293b;
    --text: #f1f5f9;
    --text-muted: #94a3b8;
    --accent: #38bdf8;
    --accent-glow: rgba(56, 189, 248, 0.25);
    --success: #10b981;
    --success-bg: rgba(16, 185, 129, 0.15);
    --warning: #f59e0b;
    --warning-bg: rgba(245, 158, 11, 0.15);
    --danger: #ef4444;
    --danger-bg: rgba(239, 68, 68, 0.15);
  }
  * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  body { margin: 0; background: var(--bg); color: var(--text); -webkit-font-smoothing: antialiased; }
  
  .container { max-width: 960px; margin: 0 auto; padding: 28px 20px 60px; }
  
  /* Header */
  .header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 20px; border-bottom: 1px solid var(--card-border); margin-bottom: 24px; }
  .logo-title { display: flex; align-items: center; gap: 12px; }
  .logo-icon { width: 36px; height: 36px; border-radius: 10px; background: linear-gradient(135deg, #0ea5e9, #6366f1); display: flex; align-items: center; justify-content: center; font-size: 20px; box-shadow: 0 0 15px var(--accent-glow); }
  .title-text h1 { margin: 0; font-size: 20px; font-weight: 700; letter-spacing: -0.02em; }
  .title-text span { font-size: 13px; color: var(--text-muted); }
  
  /* Navigation Tabs */
  .tabs { display: flex; gap: 8px; margin-bottom: 24px; background: #0f172a; padding: 6px; border-radius: 12px; border: 1px solid var(--card-border); }
  .tab-btn { flex: 1; padding: 10px 16px; border: 0; background: transparent; color: var(--text-muted); border-radius: 8px; font-weight: 600; font-size: 14px; cursor: pointer; transition: all 0.2s ease; display: flex; align-items: center; justify-content: center; gap: 8px; }
  .tab-btn:hover { color: var(--text); background: rgba(255, 255, 255, 0.04); }
  .tab-btn.active { background: #1e293b; color: var(--accent); box-shadow: 0 2px 8px rgba(0,0,0,0.3); }
  .tab-badge { font-size: 11px; padding: 2px 7px; border-radius: 20px; background: var(--danger-bg); color: var(--danger); font-weight: 700; }
  
  /* Tab Content */
  .tab-pane { display: none; }
  .tab-pane.active { display: block; }
  
  /* Status Banner */
  .status-banner { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 16px; padding: 24px; margin-bottom: 24px; position: relative; overflow: hidden; }
  .status-banner::before { content: ""; position: absolute; top: 0; left: 0; bottom: 0; width: 4px; background: #64748b; }
  .status-banner.connected::before { background: var(--success); box-shadow: 0 0 12px var(--success); }
  
  .status-top { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px; }
  .status-main { display: flex; align-items: center; gap: 16px; }
  .status-pill { width: 14px; height: 14px; border-radius: 50%; background: #475569; }
  .status-pill.on { background: var(--success); box-shadow: 0 0 10px var(--success); animation: pulse 2s infinite; }
  @keyframes pulse { 0%, 100% { transform: scale(1); opacity: 1; } 50% { transform: scale(1.15); opacity: 0.8; } }
  
  .status-details h2 { margin: 0 0 4px; font-size: 18px; font-weight: 700; }
  .status-details p { margin: 0; font-size: 13px; color: var(--text-muted); }
  
  .status-metrics { display: flex; gap: 20px; margin-top: 20px; padding-top: 20px; border-top: 1px solid rgba(255, 255, 255, 0.06); }
  .metric-box { flex: 1; background: rgba(15, 23, 42, 0.6); padding: 12px 16px; border-radius: 10px; border: 1px solid var(--card-border); }
  .metric-label { font-size: 12px; color: var(--text-muted); margin-bottom: 4px; }
  .metric-val { font-size: 16px; font-weight: 700; font-family: ui-monospace, monospace; color: var(--accent); }
  
  /* Cards */
  .card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 14px; padding: 20px; margin-bottom: 20px; }
  .card-title { font-size: 16px; font-weight: 700; margin: 0 0 16px; display: flex; align-items: center; justify-content: space-between; }
  
  /* Forms & Buttons */
  .input-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }
  @media(max-width: 600px) { .input-grid { grid-template-columns: 1fr; } }
  input { background: #0b1120; border: 1px solid var(--card-border); color: var(--text); border-radius: 8px; padding: 10px 14px; font-size: 14px; width: 100%; transition: border-color 0.2s; }
  input:focus { outline: none; border-color: var(--accent); }
  
  .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 10px 18px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; border: 0; transition: all 0.2s; }
  .btn-primary { background: linear-gradient(135deg, #0284c7, #2563eb); color: #fff; }
  .btn-primary:hover { opacity: 0.92; transform: translateY(-1px); }
  .btn-danger { background: var(--danger-bg); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }
  .btn-danger:hover { background: var(--danger); color: #fff; }
  .btn-ghost { background: #1e293b; color: var(--text); border: 1px solid var(--card-border); }
  .btn-ghost:hover { background: #334155; }
  .btn-sm { padding: 6px 12px; font-size: 13px; }
  
  /* Server Items */
  .server-item { display: flex; justify-content: space-between; align-items: center; padding: 14px 16px; background: rgba(15, 23, 42, 0.4); border: 1px solid var(--card-border); border-radius: 10px; margin-bottom: 10px; transition: border-color 0.2s; }
  .server-item:hover { border-color: rgba(56, 189, 248, 0.4); }
  .server-name { font-weight: 600; font-size: 15px; margin-bottom: 4px; }
  .server-addr { font-family: ui-monospace, monospace; font-size: 13px; color: var(--text-muted); }
  .actions { display: flex; gap: 8px; }
  
  /* Log / Security Console */
  .console-box { background: #060a12; border: 1px solid var(--card-border); border-radius: 10px; padding: 14px; font-family: ui-monospace, monospace; font-size: 12.5px; color: #cbd5e1; max-height: 380px; overflow-y: auto; line-height: 1.6; white-space: pre-wrap; }
  
  /* Suspicious Items Table */
  .susp-item { background: rgba(15, 23, 42, 0.6); border: 1px solid var(--card-border); border-radius: 10px; padding: 14px 16px; margin-bottom: 10px; }
  .susp-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
  .badge { display: inline-block; padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
  .badge-HIGH, .badge-CRITICAL { background: var(--danger-bg); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }
  .badge-MEDIUM { background: var(--warning-bg); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.3); }
  .badge-LOW { background: rgba(56, 189, 248, 0.15); color: var(--accent); border: 1px solid rgba(56, 189, 248, 0.3); }
  .susp-time { font-size: 12px; color: var(--text-muted); }
  .susp-desc { font-size: 13.5px; color: #e2e8f0; margin-bottom: 4px; }
  .susp-meta { font-family: ui-monospace, monospace; font-size: 12px; color: var(--text-muted); }
  
  /* Copy box */
  .code-tag { background: #1e293b; padding: 3px 6px; border-radius: 4px; font-family: ui-monospace, monospace; font-size: 13px; word-break: break-all; color: var(--accent); }
</style>
</head>
<body>

<div class="container">
  <div class="header">
    <div class="logo-title">
      <div class="logo-icon">🛡️</div>
      <div class="title-text">
        <h1>Chameleon CITP</h1>
        <span>Криптографический Intent-туннель v2.1</span>
      </div>
    </div>
    <div>
      <span class="code-tag" id="socksAddr">SOCKS5: 127.0.0.1:1080</span>
    </div>
  </div>

  <!-- Navigation Tabs -->
  <div class="tabs">
    <button class="tab-btn active" onclick="switchTab('tab-overview', this)">🌐 Панель управления</button>
    <button class="tab-btn" onclick="switchTab('tab-servers', this)">🖥️ Серверы</button>
    <button class="tab-btn" onclick="switchTab('tab-security', this)">
      🚨 Безопасность и аномалии
      <span class="tab-badge" id="suspBadge" style="display:none">0</span>
    </button>
    <button class="tab-btn" onclick="switchTab('tab-logs', this)">📜 Журнал событий</button>
  </div>

  <!-- Tab 1: Overview -->
  <div id="tab-overview" class="tab-pane active">
    <div class="status-banner" id="statusBanner">
      <div class="status-top">
        <div class="status-main">
          <div class="status-pill" id="statusPill"></div>
          <div class="status-details">
            <h2 id="statusTitle">Отключено</h2>
            <p id="statusDesc">Выберите ноду из списка серверов для подключения</p>
          </div>
        </div>
        <div id="statusActions"></div>
      </div>

      <div class="status-metrics">
        <div class="metric-box">
          <div class="metric-label">Пинг (Keepalive RTT)</div>
          <div class="metric-val" id="metricRTT">—</div>
        </div>
        <div class="metric-box">
          <div class="metric-label">Скорость загрузки ↓</div>
          <div class="metric-val" id="metricDown">—</div>
        </div>
        <div class="metric-box">
          <div class="metric-label">Скорость отдачи ↑</div>
          <div class="metric-val" id="metricUp">—</div>
        </div>
        <div class="metric-box">
          <div class="metric-label">CITP Маскировка (CBR)</div>
          <div class="metric-val" id="metricCBR">40ms</div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-title">
        <span>🔑 Аутентификация устройства</span>
      </div>
      <p style="margin:0 0 10px; font-size:13.5px; color:var(--text-muted)">
        Этот публичный ключ идентифицирует ваш клиент в белом списке серверов:
      </p>
      <div class="code-tag" id="clientPub" style="padding:10px; display:block; user-select:all;">Загрузка ключа…</div>
    </div>
  </div>

  <!-- Tab 2: Servers -->
  <div id="tab-servers" class="tab-pane">
    <div class="card">
      <div class="card-title">Добавить новую ноду Chameleon</div>
      <div class="input-grid">
        <input id="srvName" placeholder="Имя сервера (например: Нидерланды 1)">
        <input id="srvAddr" placeholder="IP:Порт (например: 198.51.100.10:8443)">
      </div>
      <div style="margin-bottom:12px">
        <input id="srvPubKey" placeholder="Публичный ключ ноды (Base64)">
      </div>
      <button class="btn btn-primary" onclick="addServer()">➕ Добавить сервер</button>
    </div>

    <div class="card">
      <div class="card-title">Доступные серверы</div>
      <div id="serversList"></div>
    </div>
  </div>

  <!-- Tab 3: Security & Anomalies -->
  <div id="tab-security" class="tab-pane">
    <div class="card">
      <div class="card-title">
        <span>🛡️ Защитный фильтр аномалий (Anti-SSRF / Rebinding / Port-Scan)</span>
        <button class="btn btn-ghost btn-sm" onclick="clearSuspicious()">Очистить историю</button>
      </div>
      <p style="font-size:13.5px; color:var(--text-muted); margin:0 0 16px;">
        Автоматический аудит подозрительных запросов, попыток сканирования локальных подсетей и аномальных DNS-ответов:
      </p>
      <div id="suspList"></div>
    </div>
  </div>

  <!-- Tab 4: Logs -->
  <div id="tab-logs" class="tab-pane">
    <div class="card">
      <div class="card-title">Системный журнал Chameleon Mux</div>
      <div class="console-box" id="systemLog"></div>
    </div>
  </div>
</div>

<script>
let prevMetrics = { up: 0, down: 0, t: 0 };

function switchTab(tabId, btn) {
  document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
  
  document.getElementById(tabId).classList.add('active');
  if (btn) btn.classList.add('active');
}

async function api(url, method = 'GET', data = null) {
  const opt = { method, headers: { 'Content-Type': 'application/json' } };
  if (data) opt.body = JSON.stringify(data);
  const res = await fetch(url, opt);
  return res.json();
}

function fmtBytes(b) {
  if (b >= 1024 * 1024) return (b / 1024 / 1024).toFixed(1) + " МБ/с";
  if (b >= 1024) return (b / 1024).toFixed(0) + " КБ/с";
  return b.toFixed(0) + " Б/с";
}

function esc(str) {
  return String(str || '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}

async function refresh() {
  try {
    const s = await api('/api/status');
    
    // Status Banner
    const banner = document.getElementById('statusBanner');
    const pill = document.getElementById('statusPill');
    const title = document.getElementById('statusTitle');
    const desc = document.getElementById('statusDesc');
    const actions = document.getElementById('statusActions');
    
    if (s.active) {
      banner.classList.add('connected');
      pill.classList.add('on');
      title.textContent = 'Подключено: ' + s.name;
      desc.textContent = 'Адрес: ' + s.addr + ' • Сеанс активен с ' + s.since;
      actions.innerHTML = '<button class="btn btn-danger btn-sm" onclick="disconnect()">Отключиться</button>';
    } else {
      banner.classList.remove('connected');
      pill.classList.remove('on');
      title.textContent = 'Отключено';
      desc.textContent = 'Выберите ноду из списка серверов для подключения';
      actions.innerHTML = '';
    }

    // Metrics
    document.getElementById('metricRTT').textContent = s.active && s.rtt_ms > 0 ? s.rtt_ms + ' мс' : '—';
    document.getElementById('metricCBR').textContent = s.cbr || '40ms';
    document.getElementById('clientPub').textContent = s.client_pubkey || 'Не задан';

    const now = Date.now();
    if (prevMetrics.t > 0 && now > prevMetrics.t && s.active) {
      const dt = (now - prevMetrics.t) / 1000;
      const downRate = Math.max(0, (s.down_bytes - prevMetrics.down) / dt);
      const upRate = Math.max(0, (s.up_bytes - prevMetrics.up) / dt);
      document.getElementById('metricDown').textContent = fmtBytes(downRate);
      document.getElementById('metricUp').textContent = fmtBytes(upRate);
    } else {
      document.getElementById('metricDown').textContent = '—';
      document.getElementById('metricUp').textContent = '—';
    }
    prevMetrics = { up: s.up_bytes, down: s.down_bytes, t: now };

    // Servers List
    const srvHtml = s.servers && s.servers.length ? s.servers.map((srv, idx) => 
      '<div class="server-item">' +
        '<div>' +
          '<div class="server-name">' + esc(srv.name) + '</div>' +
          '<div class="server-addr">' + esc(srv.addr) + (srv.pubkey ? ' 🔑' : ' ⚠️') + '</div>' +
        '</div>' +
        '<div class="actions">' +
          '<button class="btn btn-primary btn-sm" onclick="connect(' + idx + ')">Подключиться</button>' +
          '<button class="btn btn-ghost btn-sm" onclick="delServer(' + idx + ')">✕</button>' +
        '</div>' +
      '</div>'
    ).join('') : '<div style="color:var(--text-muted)">Список серверов пуст</div>';
    document.getElementById('serversList').innerHTML = srvHtml;

    // Suspicious Activity
    const suspBadge = document.getElementById('suspBadge');
    if (s.suspicious && s.suspicious.length > 0) {
      suspBadge.textContent = s.suspicious.length;
      suspBadge.style.display = 'inline-block';
      
      const suspHtml = s.suspicious.slice().reverse().map(ev => 
        '<div class="susp-item">' +
          '<div class="susp-header">' +
            '<span class="badge badge-' + ev.severity + '">' + esc(ev.category) + ' • ' + esc(ev.severity) + '</span>' +
            '<span class="susp-time">' + esc(ev.timestamp) + '</span>' +
          '</div>' +
          '<div class="susp-desc">' + esc(ev.description) + '</div>' +
          '<div class="susp-meta">Цель: ' + esc(ev.destination) + ' • Источник: ' + esc(ev.source) + '</div>' +
        '</div>'
      ).join('');
      document.getElementById('suspList').innerHTML = suspHtml;
    } else {
      suspBadge.style.display = 'none';
      document.getElementById('suspList').innerHTML = '<div style="color:var(--text-muted); padding:10px 0;">Подозрительной активности не зафиксировано. Все соединения в норме.</div>';
    }

    // System Logs
    document.getElementById('systemLog').textContent = (s.logs || []).join('\n');

  } catch(e) {
    console.error("Ошибка обновления UI:", e);
  }
}

async function addServer() {
  const name = document.getElementById('srvName').value.trim();
  const addr = document.getElementById('srvAddr').value.trim();
  const pubkey = document.getElementById('srvPubKey').value.trim();
  if (!addr) return alert('Укажите адрес сервера (IP:порт)');
  
  const res = await api('/api/servers', 'POST', { name, addr, pubkey });
  if (res.error) return alert(res.error);
  
  document.getElementById('srvName').value = '';
  document.getElementById('srvAddr').value = '';
  document.getElementById('srvPubKey').value = '';
  refresh();
}

async function connect(idx) {
  const res = await api('/api/connect', 'POST', { id: idx });
  if (res.error) alert(res.error);
  refresh();
}

async function disconnect() {
  await api('/api/disconnect', 'POST');
  refresh();
}

async function delServer(idx) {
  if (confirm('Удалить этот сервер?')) {
    await api('/api/servers?id=' + idx, 'DELETE');
    refresh();
  }
}

async function clearSuspicious() {
  await api('/api/suspicious/clear', 'POST');
  refresh();
}

refresh();
setInterval(refresh, 2500);
</script>
</body>
</html>`
