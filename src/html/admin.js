/**
 * src/html/admin.js
 * Modern Admin Dashboard for EdgeTunnel v2.1
 * Sidebar layout · Glassmorphism · Skeleton loaders · Mobile-first
 */

export function adminPage() {
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>EdgeTunnel - Admin</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#0b0e14;--bg2:#111621;--bg3:#161c2a;--bg4:#1c2435;
  --glass:rgba(17,22,33,.72);--glass2:rgba(22,28,42,.8);
  --border:rgba(255,255,255,.06);--border2:rgba(255,255,255,.1);
  --accent:#f6821f;--accent2:#ff9436;--accent-dim:rgba(246,130,31,.12);
  --text:#f1f5f9;--text2:#94a3b8;--text3:#64748b;
  --green:#22c55e;--red:#ef4444;--blue:#3b82f6;--yellow:#eab308;
  --r:10px;--r2:14px;--r3:20px;
  --shadow:0 8px 32px rgba(0,0,0,.35);
  --ease:cubic-bezier(.4,0,.2,1);
}
html,body{height:100%;overflow:hidden}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text)}

/* ── animated bg ── */
body::before{content:'';position:fixed;inset:0;z-index:-1;
  background:radial-gradient(ellipse 80% 60% at 10% 20%,rgba(246,130,31,.07),transparent 60%),
             radial-gradient(ellipse 60% 50% at 90% 80%,rgba(59,130,246,.05),transparent 60%)}

/* ── layout ── */
.layout{display:flex;height:100vh}

/* ── sidebar ── */
.sidebar{width:240px;min-width:240px;background:var(--glass2);border-right:1px solid var(--border);
  display:flex;flex-direction:column;backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);z-index:20}
.sidebar-brand{padding:1.25rem 1.1rem;display:flex;align-items:center;gap:.7rem;border-bottom:1px solid var(--border)}
.sidebar-logo{width:38px;height:38px;border-radius:var(--r);background:linear-gradient(135deg,var(--accent),#e05a00);
  display:grid;place-items:center;font-size:1.15rem;color:#fff;font-weight:800;box-shadow:0 0 20px rgba(246,130,31,.3)}
.sidebar-brand-text{display:flex;flex-direction:column}
.sidebar-brand-name{font-weight:700;font-size:.95rem;letter-spacing:-.02em}
.sidebar-brand-sub{font-size:.7rem;color:var(--text3);font-weight:500}
.sidebar-nav{flex:1;padding:.75rem .6rem;display:flex;flex-direction:column;gap:2px;overflow-y:auto}
.nav-item{display:flex;align-items:center;gap:.65rem;padding:.6rem .75rem;border-radius:var(--r);
  font-size:.85rem;font-weight:500;color:var(--text2);cursor:pointer;transition:all .15s var(--ease);
  border:1px solid transparent;text-decoration:none}
.nav-item:hover{color:var(--text);background:rgba(255,255,255,.04);border-color:var(--border)}
.nav-item.active{color:var(--accent);background:var(--accent-dim);border-color:rgba(246,130,31,.15)}
.nav-item .icon{width:18px;height:18px;flex-shrink:0;opacity:.7}
.nav-item.active .icon{opacity:1}
.sidebar-footer{padding:.75rem 1rem;border-top:1px solid var(--border)}
.sidebar-footer .btn-logout{display:flex;align-items:center;gap:.5rem;width:100%;padding:.55rem .75rem;
  border-radius:var(--r);font-size:.82rem;font-weight:500;color:var(--red);background:rgba(239,68,68,.08);
  border:1px solid rgba(239,68,68,.15);cursor:pointer;transition:all .15s var(--ease);text-decoration:none;font-family:inherit}
.sidebar-footer .btn-logout:hover{background:rgba(239,68,68,.15);border-color:rgba(239,68,68,.3)}

/* ── main ── */
.main{flex:1;display:flex;flex-direction:column;overflow:hidden}
.topbar{height:56px;min-height:56px;background:var(--glass);border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;padding:0 1.5rem;backdrop-filter:blur(16px);gap:1rem}
.topbar-left{display:flex;align-items:center;gap:1rem}
.topbar-title{font-size:1.05rem;font-weight:700;letter-spacing:-.01em}
.topbar-badge{font-size:.65rem;padding:.15rem .5rem;border-radius:99px;background:var(--accent-dim);
  color:var(--accent);border:1px solid rgba(246,130,31,.2);font-weight:600}
.topbar-right{display:flex;align-items:center;gap:.5rem}
.topbar-host{font-size:.78rem;color:var(--text3);font-family:'JetBrains Mono',monospace}
.btn{display:inline-flex;align-items:center;gap:.45rem;padding:.5rem .9rem;font-size:.82rem;font-weight:600;
  font-family:inherit;border-radius:var(--r);border:1px solid transparent;cursor:pointer;transition:all .15s var(--ease);text-decoration:none;white-space:nowrap}
.btn-accent{background:linear-gradient(135deg,var(--accent),#d96f00);color:#fff;box-shadow:0 2px 12px rgba(246,130,31,.25)}
.btn-accent:hover{box-shadow:0 4px 20px rgba(246,130,31,.4);transform:translateY(-1px)}
.btn-ghost{background:rgba(255,255,255,.04);color:var(--text);border-color:var(--border)}
.btn-ghost:hover{background:rgba(255,255,255,.08);border-color:var(--border2)}
.btn-danger{background:rgba(239,68,68,.1);color:var(--red);border-color:rgba(239,68,68,.2)}
.btn-danger:hover{background:rgba(239,68,68,.18);border-color:rgba(239,68,68,.35)}
.btn-sm{padding:.4rem .7rem;font-size:.78rem}

/* ── content ── */
.content{flex:1;overflow-y:auto;padding:1.5rem;scroll-behavior:smooth}
.content::-webkit-scrollbar{width:6px}
.content::-webkit-scrollbar-thumb{background:rgba(255,255,255,.08);border-radius:3px}
.content::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,.14)}

/* ── panels ── */
.panel{display:none;animation:panelIn .3s var(--ease)}
.panel.active{display:block}
@keyframes panelIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}

/* ── stat cards ── */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:.75rem;margin-bottom:1.25rem}
.stat{background:var(--glass);border:1px solid var(--border);border-radius:var(--r2);padding:1rem 1.1rem;
  backdrop-filter:blur(12px);transition:all .2s var(--ease)}
.stat:hover{border-color:var(--border2);transform:translateY(-1px)}
.stat-label{font-size:.72rem;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:.3rem}
.stat-val{font-size:1.15rem;font-weight:700;display:flex;align-items:center;gap:.4rem}
.stat-val code{font-family:'JetBrains Mono',monospace;font-size:.92rem;color:var(--accent)}
.stat-val .ok{color:var(--green)}

/* ── card ── */
.card{background:var(--glass);border:1px solid var(--border);border-radius:var(--r2);padding:1.25rem;
  backdrop-filter:blur(12px);margin-bottom:1rem}
.card-head{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:1rem;padding-bottom:.75rem;
  border-bottom:1px solid rgba(255,255,255,.04)}
.card-title{font-size:.95rem;font-weight:700;display:flex;align-items:center;gap:.5rem}
.card-desc{font-size:.78rem;color:var(--text3);margin-top:.2rem}

/* ── forms ── */
.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1rem}
.field{display:flex;flex-direction:column;gap:.35rem}
.field label{font-size:.8rem;font-weight:600;color:var(--text2)}
.field input,.field select,.field textarea{width:100%;padding:.55rem .75rem;background:rgba(10,14,20,.6);
  border:1px solid var(--border);border-radius:var(--r);color:var(--text);font-family:inherit;font-size:.85rem;
  transition:all .15s var(--ease)}
.field input:focus,.field select:focus,.field textarea:focus{outline:none;border-color:var(--accent);
  box-shadow:0 0 0 3px rgba(246,130,31,.12);background:rgba(10,14,20,.85)}
.field textarea{min-height:110px;font-family:'JetBrains Mono',monospace;font-size:.8rem;line-height:1.5;resize:vertical}
.field select{cursor:pointer}
.field-hint{font-size:.72rem;color:var(--text3);margin-top:.35rem;line-height:1.4}

/* ── toggle ── */
.toggle-row{display:flex;align-items:center;justify-content:space-between;padding:.7rem .85rem;
  background:rgba(10,14,20,.35);border:1px solid var(--border);border-radius:var(--r)}
.toggle-info .t-title{font-size:.85rem;font-weight:600}
.toggle-info .t-desc{font-size:.72rem;color:var(--text3)}
.switch{position:relative;width:40px;height:22px;flex-shrink:0}
.switch input{opacity:0;width:0;height:0}
.switch .slider{position:absolute;inset:0;background:rgba(255,255,255,.12);border-radius:22px;cursor:pointer;transition:.2s var(--ease)}
.switch .slider:before{content:'';position:absolute;left:3px;top:3px;width:16px;height:16px;background:#fff;
  border-radius:50%;transition:.2s var(--ease)}
.switch input:checked+.slider{background:var(--accent)}
.switch input:checked+.slider:before{transform:translateX(18px)}

/* ── link box ── */
.link-box{display:flex;align-items:center;gap:.5rem;background:rgba(10,14,20,.55);border:1px solid var(--border);
  border-radius:var(--r);padding:.5rem .7rem}
.link-text{flex:1;font-family:'JetBrains Mono',monospace;font-size:.8rem;color:var(--text2);
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* ── skeleton ── */
.skeleton{background:linear-gradient(90deg,rgba(255,255,255,.04) 25%,rgba(255,255,255,.08) 50%,rgba(255,255,255,.04) 75%);
  background-size:200% 100%;animation:shimmer 1.5s infinite;border-radius:var(--r)}
@keyframes shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}

/* ── toast ── */
#toast{position:fixed;bottom:1.5rem;right:1.5rem;padding:.7rem 1.1rem;background:var(--bg3);
  border:1px solid var(--border);border-radius:var(--r);color:#fff;font-size:.85rem;font-weight:500;
  box-shadow:var(--shadow);display:flex;align-items:center;gap:.6rem;transform:translateY(80px);
  opacity:0;transition:all .25s var(--ease);z-index:100;backdrop-filter:blur(12px)}
#toast.show{transform:none;opacity:1}
#toast.ok{border-left:3px solid var(--green)}
#toast.err{border-left:3px solid var(--red)}
#toast.info{border-left:3px solid var(--accent)}

/* ── modal ── */
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.65);backdrop-filter:blur(6px);display:none;
  place-items:center;z-index:90;padding:1rem}
.modal-bg.open{display:grid}
.modal{background:var(--bg3);border:1px solid var(--border);border-radius:var(--r3);max-width:420px;width:100%;
  padding:1.5rem;display:flex;flex-direction:column;gap:1rem;box-shadow:var(--shadow)}
.modal-head{display:flex;align-items:center;justify-content:space-between;font-weight:700;font-size:.95rem}
.modal-x{background:none;border:none;color:var(--text3);font-size:1.2rem;cursor:pointer;line-height:1}
.modal-qr{display:flex;justify-content:center;padding:.75rem;background:#fff;border-radius:var(--r)}
.modal-qr img{max-width:220px;width:100%;height:auto}

/* ── danger zone ── */
.danger-zone{border-color:rgba(239,68,68,.2)!important}
.danger-zone .card-title{color:var(--red)}

/* ── responsive ── */
@media(max-width:900px){
  .sidebar{position:fixed;left:0;top:0;bottom:0;transform:translateX(-100%);transition:transform .25s var(--ease);z-index:30}
  .sidebar.open{transform:none;box-shadow:4px 0 30px rgba(0,0,0,.5)}
  .sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:25}
  .sidebar-overlay.open{display:block}
  .menu-toggle{display:inline-flex!important}
  .stats{grid-template-columns:repeat(2,1fr)}
}
@media(max-width:500px){
  .stats{grid-template-columns:1fr}
  .form-grid{grid-template-columns:1fr}
  .topbar{padding:0 .75rem}
  .content{padding:1rem .75rem}
}
.menu-toggle{display:none;background:none;border:none;color:var(--text);font-size:1.2rem;cursor:pointer;padding:.25rem}
</style>
</head>
<body>
<div class="layout">

<!-- Sidebar Overlay (mobile) -->
<div class="sidebar-overlay" id="sidebarOverlay" onclick="toggleSidebar()"></div>

<!-- Sidebar -->
<aside class="sidebar" id="sidebar">
  <div class="sidebar-brand">
    <div class="sidebar-logo">E</div>
    <div class="sidebar-brand-text">
      <span class="sidebar-brand-name">EdgeTunnel</span>
      <span class="sidebar-brand-sub" id="sidebarHost">Loading...</span>
    </div>
  </div>
  <nav class="sidebar-nav">
    <a class="nav-item active" data-panel="overview" onclick="showPanel('overview',this)">
      <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>
      Overview
    </a>
    <a class="nav-item" data-panel="links" onclick="showPanel('links',this)">
      <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
      Node & Subscriptions
    </a>
    <a class="nav-item" data-panel="protocol" onclick="showPanel('protocol',this)">
      <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
      Protocol & Network
    </a>
    <a class="nav-item" data-panel="subscriptions" onclick="showPanel('subscriptions',this)">
      <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
      Optimal Subscriptions
    </a>
    <a class="nav-item" data-panel="cloudflare" onclick="showPanel('cloudflare',this)">
      <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/></svg>
      Cloudflare API
    </a>
  </nav>
  <div class="sidebar-footer">
    <a href="/logout" class="btn-logout">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      Logout
    </a>
  </div>
</aside>

<!-- Main -->
<div class="main">
  <!-- Topbar -->
  <header class="topbar">
    <div class="topbar-left">
      <button class="menu-toggle" onclick="toggleSidebar()">☰</button>
      <span class="topbar-title" id="topbarTitle">Overview</span>
      <span class="topbar-badge">v2.1</span>
    </div>
    <div class="topbar-right">
      <span class="topbar-host" id="topbarHost">-</span>
      <button class="btn btn-ghost btn-sm" onclick="loadAllData()">↻ Refresh</button>
      <button class="btn btn-accent btn-sm" onclick="saveAll()">Save Config</button>
    </div>
  </header>

  <!-- Content -->
  <div class="content">

    <!-- ═══ Overview ═══ -->
    <div class="panel active" id="panel-overview">
      <div class="stats" id="statsGrid">
        <div class="stat"><div class="stat-label">Protocol</div><div class="stat-val" id="s-proto"><div class="skeleton" style="width:60px;height:18px"></div></div></div>
        <div class="stat"><div class="stat-label">Transport</div><div class="stat-val" id="s-transport"><div class="skeleton" style="width:80px;height:18px"></div></div></div>
        <div class="stat"><div class="stat-label">CF Requests Today</div><div class="stat-val" id="s-cf"><div class="skeleton" style="width:100px;height:18px"></div></div></div>
        <div class="stat"><div class="stat-label">Config Loaded</div><div class="stat-val" id="s-time"><div class="skeleton" style="width:50px;height:18px"></div></div></div>
      </div>

      <div class="card">
        <div class="card-head">
          <div><div class="card-title">Primary Node Link</div><div class="card-desc">Generated from your active protocol settings</div></div>
          <button class="btn btn-ghost btn-sm" onclick="openQr()">QR Code</button>
        </div>
        <div class="link-box">
          <div class="link-text" id="nodeLink"><div class="skeleton" style="height:16px;width:100%"></div></div>
          <button class="btn btn-accent btn-sm" onclick="copy(document.getElementById('nodeLink').textContent)">Copy</button>
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <div><div class="card-title">Subscription URLs</div><div class="card-desc">Import into Clash, SingBox, Shadowrocket or V2Ray</div></div>
        </div>
        <div class="form-grid">
          <div class="field"><label>Universal</label><div class="link-box"><div class="link-text" id="subAuto">-</div><button class="btn btn-ghost btn-sm" onclick="copy(document.getElementById('subAuto').textContent)">Copy</button></div></div>
          <div class="field"><label>Clash / Meta</label><div class="link-box"><div class="link-text" id="subClash">-</div><button class="btn btn-ghost btn-sm" onclick="copy(document.getElementById('subClash').textContent)">Copy</button></div></div>
          <div class="field"><label>Sing-Box</label><div class="link-box"><div class="link-text" id="subSingbox">-</div><button class="btn btn-ghost btn-sm" onclick="copy(document.getElementById('subSingbox').textContent)">Copy</button></div></div>
          <div class="field"><label>Base64</label><div class="link-box"><div class="link-text" id="subB64">-</div><button class="btn btn-ghost btn-sm" onclick="copy(document.getElementById('subB64').textContent)">Copy</button></div></div>
        </div>
      </div>
    </div>

    <!-- ═══ Node & Subscriptions ═══ -->
    <div class="panel" id="panel-links">
      <div class="card">
        <div class="card-head"><div><div class="card-title">Connection Link</div><div class="card-desc">Copy this link into your client app</div></div></div>
        <div class="link-box"><div class="link-text" id="nodeLink2">-</div><button class="btn btn-accent btn-sm" onclick="copy(document.getElementById('nodeLink2').textContent)">Copy</button></div>
      </div>
      <div class="card">
        <div class="card-head"><div><div class="card-title">All Subscription URLs</div></div></div>
        <div class="form-grid">
          <div class="field"><label>Universal</label><div class="link-box"><div class="link-text" id="subAuto2">-</div><button class="btn btn-ghost btn-sm" onclick="copy(document.getElementById('subAuto2').textContent)">Copy</button></div></div>
          <div class="field"><label>Clash / Meta</label><div class="link-box"><div class="link-text" id="subClash2">-</div><button class="btn btn-ghost btn-sm" onclick="copy(document.getElementById('subClash2').textContent)">Copy</button></div></div>
          <div class="field"><label>Sing-Box</label><div class="link-box"><div class="link-text" id="subSingbox2">-</div><button class="btn btn-ghost btn-sm" onclick="copy(document.getElementById('subSingbox2').textContent)">Copy</button></div></div>
          <div class="field"><label>Base64</label><div class="link-box"><div class="link-text" id="subB642">-</div><button class="btn btn-ghost btn-sm" onclick="copy(document.getElementById('subB642').textContent)">Copy</button></div></div>
        </div>
      </div>
    </div>

    <!-- ═══ Protocol & Network ═══ -->
    <div class="panel" id="panel-protocol">
      <div class="card">
        <div class="card-head"><div><div class="card-title">Core Protocol</div><div class="card-desc">Tunneling protocol, transport layer, and TLS parameters</div></div></div>
        <div class="form-grid">
          <div class="field"><label>Protocol Type (Subscription)</label><select id="cfg-protocolType"><option value="all">All Protocols</option><option value="vless">VLESS</option><option value="vmess">VMess</option><option value="trojan">Trojan</option><option value="ss">Shadowsocks</option></select><p class="field-hint">Controls which protocol links appear in subscription output. All protocols are always accepted at the transport level.</p></div>
          <div class="field"><label>Transport</label><select id="cfg-transportProtocol"><option value="ws">WebSocket</option><option value="grpc">gRPC</option><option value="xhttp">XHTTP</option></select></div>
          <div class="field"><label>Node Path</label><input type="text" id="cfg-path" placeholder="/"></div>
          <div class="field"><label>Fingerprint</label><select id="cfg-fingerprint"><option value="chrome">Chrome</option><option value="firefox">Firefox</option><option value="safari">Safari</option><option value="ios">iOS</option><option value="randomized">Randomized</option></select></div>
          <div class="field"><label>TLS Fragment</label><select id="cfg-tlsFragment"><option value="">Disabled</option><option value="Shadowrocket">Shadowrocket</option><option value="Happ">Happ</option></select></div>
          <div class="field"><label>gRPC Mode</label><select id="cfg-grpcMode"><option value="gun">gun</option><option value="multi">multi</option></select></div>
        </div>
        <div style="display:flex;flex-direction:column;gap:.5rem;margin-top:.75rem">
          <div class="toggle-row"><div class="toggle-info"><div class="t-title">Skip Certificate Verify</div><div class="t-desc">Allow insecure TLS connections</div></div><label class="switch"><input type="checkbox" id="cfg-skipCertVerify"><span class="slider"></span></label></div>
          <div class="toggle-row"><div class="toggle-info"><div class="t-title">0-RTT Early Data</div><div class="t-desc">Zero Round Trip Time acceleration</div></div><label class="switch"><input type="checkbox" id="cfg-enable0RTT"><span class="slider"></span></label></div>
          <div class="toggle-row"><div class="toggle-info"><div class="t-title">Random Path</div><div class="t-desc">Randomized path prefixes for obfuscation</div></div><label class="switch"><input type="checkbox" id="cfg-randomPath"><span class="slider"></span></label></div>
          <div class="toggle-row"><div class="toggle-info"><div class="t-title">ECH (Encrypted Client Hello)</div><div class="t-desc">SNI obfuscation via DoH</div></div><label class="switch"><input type="checkbox" id="cfg-ech" onchange="toggleECH()"><span class="slider"></span></label></div>
        </div>
        <div id="echConfig" style="display:none;margin-top:.75rem">
          <div class="form-grid">
            <div class="field"><label>ECH DoH DNS</label><input type="text" id="cfg-echDns" placeholder="https://dns.alidns.com/dns-query"></div>
            <div class="field"><label>ECH SNI</label><input type="text" id="cfg-echSni" placeholder="cloudflare-ech.com"></div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-head"><div><div class="card-title">Shadowsocks Settings</div><div class="card-desc">AEAD cipher and TLS transport for SS protocol</div></div></div>
        <div class="form-grid">
          <div class="field"><label>Cipher Method</label><select id="cfg-ssCipher"><option value="aes-128-gcm">aes-128-gcm</option><option value="aes-256-gcm">aes-256-gcm</option></select></div>
          <div class="toggle-row"><div class="toggle-info"><div class="t-title">Use TLS for SS</div><div class="t-desc">Send SS over wss:// instead of ws://</div></div><label class="switch"><input type="checkbox" id="cfg-ssTls"><span class="slider"></span></label></div>
        </div>
      </div>
    </div>

    <!-- ═══ Optimal Subscriptions ═══ -->
    <div class="panel" id="panel-subscriptions">
      <div class="card">
        <div class="card-head"><div><div class="card-title">Subscription Generator</div><div class="card-desc">Configure optimal IP pools and auto-update</div></div></div>
        <div class="form-grid">
          <div class="field"><label>Subscription Name</label><input type="text" id="cfg-subname" placeholder="edgetunnel"></div>
          <div class="field"><label>Specified Port (-1 = all)</label><input type="number" id="cfg-specifiedPort" value="-1"></div>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><div><div class="card-title">Custom IP List (ADD.txt)</div><div class="card-desc">IP:PORT or domain nodes to inject</div></div><button class="btn btn-ghost btn-sm" onclick="saveAddTxt()">Save ADD.txt</button></div>
        <textarea id="cfg-addTxt" placeholder="104.16.1.1:443#CF_1&#10;104.16.2.1:443#CF_2"></textarea>
      </div>
    </div>

    <!-- ═══ Cloudflare API ═══ -->
    <div class="panel" id="panel-cloudflare">
      <div class="card">
        <div class="card-head"><div><div class="card-title">Cloudflare Credentials</div><div class="card-desc">Monitor Workers & Pages daily quota</div></div></div>
        <div class="form-grid">
          <div class="field"><label>Account Email</label><input type="email" id="cfg-cfEmail" placeholder="user@example.com"></div>
          <div class="field"><label>Global API Key</label><input type="password" id="cfg-cfApiKey" placeholder="API Key"></div>
          <div class="field"><label>Account ID</label><input type="text" id="cfg-cfAccountId" placeholder="Account ID"></div>
          <div class="field"><label>API Token (optional)</label><input type="password" id="cfg-cfApiToken" placeholder="API Token"></div>
        </div>
        <div style="display:flex;justify-content:flex-end;margin-top:.5rem"><button class="btn btn-ghost" onclick="saveCfSettings()">Save Cloudflare</button></div>
      </div>

      <div class="card danger-zone">
        <div class="card-head"><div><div class="card-title">Factory Reset</div><div class="card-desc">Restore all settings to defaults</div></div><button class="btn btn-danger btn-sm" onclick="resetDefaults()">Reset All</button></div>
      </div>
    </div>

  </div><!-- /content -->
</div><!-- /main -->
</div><!-- /layout -->

<!-- QR Modal -->
<div class="modal-bg" id="qrModal" onclick="if(event.target===this)closeQr()">
  <div class="modal">
    <div class="modal-head"><span>Node QR Code</span><button class="modal-x" onclick="closeQr()">&times;</button></div>
    <div class="modal-qr"><img id="qrImg" src="" alt="QR"></div>
    <button class="btn btn-ghost" onclick="closeQr()" style="width:100%">Close</button>
  </div>
</div>

<!-- Toast -->
<div id="toast">-</div>

<script>
let C={};

function showPanel(id,el){
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  document.getElementById('panel-'+id).classList.add('active');
  if(el)el.classList.add('active');
  document.getElementById('topbarTitle').textContent=el?el.textContent.trim():id;
  // sync links panel
  if(id==='links'){syncLinks()}
  // close sidebar on mobile
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebarOverlay').classList.remove('open');
}

function syncLinks(){
  const link=C.LINK||'-';
  const t=C.optSubGenerator?.TOKEN||'';
  const o=window.location.origin;
  document.getElementById('nodeLink2').textContent=link;
  document.getElementById('subAuto2').textContent=o+'/sub?token='+t;
  document.getElementById('subClash2').textContent=o+'/sub?token='+t+'&clash=1';
  document.getElementById('subSingbox2').textContent=o+'/sub?token='+t+'&singbox=1';
  document.getElementById('subB642').textContent=o+'/sub?token='+t+'&b64=1';
}

function toggleSidebar(){
  document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('sidebarOverlay').classList.toggle('open');
}

function showToast(m,t='ok'){
  const el=document.getElementById('toast');
  el.textContent=m;el.className='show '+t;
  setTimeout(()=>{el.className=''},3500);
}

function copy(t){
  if(!t||t==='-'||t.includes('Loading'))return;
  navigator.clipboard.writeText(t).then(()=>showToast('Copied!')).catch(()=>showToast('Copy failed','err'));
}

function openQr(){
  const link=document.getElementById('nodeLink').textContent;
  if(!link||link.includes('Loading'))return;
  document.getElementById('qrImg').src='https://api.qrserver.com/v1/create-qr-code/?size=280x280&data='+encodeURIComponent(link);
  document.getElementById('qrModal').classList.add('open');
}
function closeQr(){document.getElementById('qrModal').classList.remove('open')}
function toggleECH(){const e=document.getElementById('cfg-ech').checked;document.getElementById('echConfig').style.display=e?'':'none'}

async function loadAllData(){
  try{
    const r=await fetch('/admin/config.json');
    if(!r.ok)throw new Error('Fetch failed');
    C=await r.json();
    fillForm(C);loadAddTxt();
    showToast('Config loaded','info');
  }catch(e){showToast('Load error: '+e.message,'err')}
}

function fillForm(c){
  const host=c.HOST||window.location.hostname;
  document.getElementById('sidebarHost').textContent=host;
  document.getElementById('topbarHost').textContent=host;
  document.getElementById('s-time').innerHTML='<code>'+(c.loadTime||'-')+'</code>';

  // stats
  const p=c.protocolType||'all';
  const tp=c.transportProtocol||'ws';
  document.getElementById('s-proto').innerHTML='<code>'+p.toUpperCase()+'</code>';
  document.getElementById('s-transport').innerHTML='<code>'+(tp==='grpc'?'gRPC':tp.toUpperCase())+'</code>';

  if(c.CF?.Usage){
    const u=c.CF.Usage;
    document.getElementById('s-cf').innerHTML='<span class="ok">'+(u.total||0).toLocaleString()+'</span> / '+(u.max||100000).toLocaleString();
  }

  // links
  const link=c.LINK||'No link generated';
  document.getElementById('nodeLink').textContent=link;
  const t=c.optSubGenerator?.TOKEN||'';
  const o=window.location.origin;
  document.getElementById('subAuto').textContent=o+'/sub?token='+t;
  document.getElementById('subClash').textContent=o+'/sub?token='+t+'&clash=1';
  document.getElementById('subSingbox').textContent=o+'/sub?token='+t+'&singbox=1';
  document.getElementById('subB64').textContent=o+'/sub?token='+t+'&b64=1';

  // protocol
  document.getElementById('cfg-protocolType').value=c.protocolType||'all';
  document.getElementById('cfg-transportProtocol').value=c.transportProtocol||'ws';
  document.getElementById('cfg-path').value=c.PATH||'/';
  document.getElementById('cfg-fingerprint').value=c.Fingerprint||'chrome';
  document.getElementById('cfg-tlsFragment').value=c.TLSFragment||'';
  document.getElementById('cfg-grpcMode').value=c.gRPCmode||'gun';
  document.getElementById('cfg-skipCertVerify').checked=!!c.skipCertVerify;
  document.getElementById('cfg-enable0RTT').checked=!!c.enable0RTT;
  document.getElementById('cfg-randomPath').checked=!!c.randomPath;
  document.getElementById('cfg-ech').checked=!!c.ECH;
  const echCfg=c.ECHConfig||{};
  document.getElementById('cfg-echDns').value=echCfg.DNS||'https://dns.alidns.com/dns-query';
  document.getElementById('cfg-echSni').value=echCfg.SNI||'cloudflare-ech.com';
  toggleECH();

  // ss
  const ss=c.SS||{};
  document.getElementById('cfg-ssCipher').value=ss.cipherMethod||'aes-128-gcm';
  document.getElementById('cfg-ssTls').checked=!!ss.TLS;

  // subscriptions
  const opt=c.optSubGenerator||{};
  document.getElementById('cfg-subname').value=opt.SUBNAME||'edgetunnel';
  document.getElementById('cfg-specifiedPort').value=opt.localIPDB?.specifiedPort??-1;

  // cf
  document.getElementById('cfg-cfEmail').value=c.CF?.Email||'';
  document.getElementById('cfg-cfApiKey').value=c.CF?.GlobalAPIKey||'';
  document.getElementById('cfg-cfAccountId').value=c.CF?.AccountID||'';
  document.getElementById('cfg-cfApiToken').value=c.CF?.APIToken||'';
}

async function saveAll(){
  try{
    C.protocolType=document.getElementById('cfg-protocolType').value;
    C.transportProtocol=document.getElementById('cfg-transportProtocol').value;
    C.PATH=document.getElementById('cfg-path').value||'/';
    C.Fingerprint=document.getElementById('cfg-fingerprint').value;
    C.TLSFragment=document.getElementById('cfg-tlsFragment').value||null;
    C.gRPCmode=document.getElementById('cfg-grpcMode').value;
    C.skipCertVerify=document.getElementById('cfg-skipCertVerify').checked;
    C.enable0RTT=document.getElementById('cfg-enable0RTT').checked;
    C.randomPath=document.getElementById('cfg-randomPath').checked;
    C.ECH=document.getElementById('cfg-ech').checked;
    C.ECHConfig={DNS:document.getElementById('cfg-echDns').value||'https://dns.alidns.com/dns-query',SNI:document.getElementById('cfg-echSni').value||'cloudflare-ech.com'};
    C.SS={cipherMethod:document.getElementById('cfg-ssCipher').value,TLS:document.getElementById('cfg-ssTls').checked};
    C.optSubGenerator=C.optSubGenerator||{};
    C.optSubGenerator.SUBNAME=document.getElementById('cfg-subname').value||'edgetunnel';
    C.optSubGenerator.localIPDB=C.optSubGenerator.localIPDB||{};
    C.optSubGenerator.localIPDB.specifiedPort=parseInt(document.getElementById('cfg-specifiedPort').value,10);

    const r=await fetch('/admin/config.json',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(C)});
    if(!r.ok)throw new Error(r.status);
    showToast('Saved!');
    loadAllData();
  }catch(e){showToast('Save failed: '+e.message,'err')}
}

async function loadAddTxt(){
  try{const r=await fetch('/admin/ADD.txt');if(r.ok){const t=await r.text();document.getElementById('cfg-addTxt').value=t==='null'?'':t}}catch(e){}
}

async function saveAddTxt(){
  try{const r=await fetch('/admin/ADD.txt',{method:'POST',headers:{'Content-Type':'text/plain;charset=utf-8'},body:document.getElementById('cfg-addTxt').value});
  r.ok?showToast('ADD.txt saved!'):showToast('Save failed','err')}catch(e){showToast(e.message,'err')}
}

async function saveCfSettings(){
  try{const r=await fetch('/admin/cf.json',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
    Email:document.getElementById('cfg-cfEmail').value,GlobalAPIKey:document.getElementById('cfg-cfApiKey').value,
    AccountID:document.getElementById('cfg-cfAccountId').value,APIToken:document.getElementById('cfg-cfApiToken').value})});
  r.ok?showToast('Cloudflare saved!'):showToast('Save failed','err')}catch(e){showToast(e.message,'err')}
}

async function resetDefaults(){
  if(!confirm('Reset ALL settings to defaults?'))return;
  try{const r=await fetch('/admin/init');if(r.ok){showToast('Reset done!');loadAllData()}else showToast('Reset failed','err')}catch(e){showToast(e.message,'err')}
}

document.addEventListener('DOMContentLoaded',loadAllData);
</script>
</body>
</html>`;
}
