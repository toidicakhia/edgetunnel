/**
 * src/html/admin.js
 * Native English Admin Dashboard for EdgeTunnel
 * Complete standalone interface: Settings, Subscriptions, Proxy, Notifications, Analytics, Logs
 */

export function adminPage() {
	return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta name="robots" content="noindex, nofollow">
	<title>EdgeTunnel - Admin Dashboard</title>
	<link rel="preconnect" href="https://fonts.googleapis.com">
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
	<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
	<style>
		:root {
			--bg-base: #0a0f1d;
			--bg-surface: #111827;
			--bg-card: rgba(17, 24, 39, 0.75);
			--bg-card-hover: rgba(31, 41, 55, 0.85);
			--border: rgba(255, 255, 255, 0.08);
			--border-focus: rgba(246, 130, 31, 0.5);
			--accent: #f6821f;
			--accent-hover: #ff9436;
			--accent-glow: rgba(246, 130, 31, 0.25);
			--text-main: #f8fafc;
			--text-muted: #94a3b8;
			--text-dim: #64748b;
			--success: #10b981;
			--warning: #f59e0b;
			--danger: #ef4444;
			--radius: 12px;
			--radius-sm: 8px;
			--transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
		}

		* {
			margin: 0;
			padding: 0;
			box-sizing: border-box;
		}

		body {
			font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
			background-color: var(--bg-base);
			color: var(--text-main);
			min-height: 100vh;
			display: flex;
			flex-direction: column;
			overflow-x: hidden;
			background-image: 
				radial-gradient(at 0% 0%, rgba(246, 130, 31, 0.08) 0px, transparent 50%),
				radial-gradient(at 100% 100%, rgba(59, 130, 246, 0.05) 0px, transparent 50%);
		}

		/* Header */
		header {
			position: sticky;
			top: 0;
			z-index: 50;
			backdrop-filter: blur(16px);
			-webkit-backdrop-filter: blur(16px);
			background: rgba(10, 15, 29, 0.85);
			border-bottom: 1px solid var(--border);
			padding: 0.85rem 1.5rem;
		}

		.header-container {
			max-width: 1320px;
			margin: 0 auto;
			display: flex;
			align-items: center;
			justify-content: space-between;
			gap: 1rem;
		}

		.brand {
			display: flex;
			align-items: center;
			gap: 0.75rem;
			text-decoration: none;
			color: var(--text-main);
		}

		.brand-icon {
			width: 36px;
			height: 36px;
			background: linear-gradient(135deg, var(--accent), #ff5e00);
			border-radius: var(--radius-sm);
			display: flex;
			align-items: center;
			justify-content: center;
			font-weight: 700;
			font-size: 1.1rem;
			color: #fff;
			box-shadow: 0 0 16px var(--accent-glow);
		}

		.brand-name {
			font-size: 1.15rem;
			font-weight: 700;
			letter-spacing: -0.02em;
		}

		.brand-badge {
			font-size: 0.7rem;
			padding: 0.15rem 0.5rem;
			background: rgba(246, 130, 31, 0.15);
			color: var(--accent);
			border-radius: 9999px;
			border: 1px solid rgba(246, 130, 31, 0.3);
			font-weight: 600;
		}

		.header-actions {
			display: flex;
			align-items: center;
			gap: 0.75rem;
		}

		/* Buttons */
		.btn {
			display: inline-flex;
			align-items: center;
			justify-content: center;
			gap: 0.5rem;
			padding: 0.55rem 1.1rem;
			font-size: 0.875rem;
			font-weight: 600;
			font-family: inherit;
			border-radius: var(--radius-sm);
			border: 1px solid transparent;
			cursor: pointer;
			transition: var(--transition);
			text-decoration: none;
		}

		.btn-primary {
			background: linear-gradient(135deg, var(--accent), #e06600);
			color: #fff;
			box-shadow: 0 2px 10px var(--accent-glow);
		}

		.btn-primary:hover {
			background: linear-gradient(135deg, var(--accent-hover), #f6821f);
			box-shadow: 0 4px 16px rgba(246, 130, 31, 0.4);
			transform: translateY(-1px);
		}

		.btn-secondary {
			background: rgba(255, 255, 255, 0.05);
			color: var(--text-main);
			border: 1px solid var(--border);
		}

		.btn-secondary:hover {
			background: rgba(255, 255, 255, 0.1);
			border-color: rgba(255, 255, 255, 0.15);
			transform: translateY(-1px);
		}

		.btn-danger {
			background: rgba(239, 68, 68, 0.15);
			color: #f87171;
			border: 1px solid rgba(239, 68, 68, 0.3);
		}

		.btn-danger:hover {
			background: rgba(239, 68, 68, 0.25);
			border-color: rgba(239, 68, 68, 0.5);
			transform: translateY(-1px);
		}

		.btn-sm {
			padding: 0.35rem 0.75rem;
			font-size: 0.8rem;
		}

		/* Main Layout */
		main {
			flex: 1;
			max-width: 1320px;
			width: 100%;
			margin: 0 auto;
			padding: 1.75rem 1.5rem 3rem;
			display: flex;
			flex-direction: column;
			gap: 1.5rem;
		}

		/* Overview Grid */
		.overview-grid {
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
			gap: 1rem;
		}

		.stat-card {
			background: var(--bg-card);
			border: 1px solid var(--border);
			border-radius: var(--radius);
			padding: 1.25rem;
			display: flex;
			flex-direction: column;
			gap: 0.5rem;
			backdrop-filter: blur(12px);
			transition: var(--transition);
		}

		.stat-card:hover {
			border-color: rgba(255, 255, 255, 0.15);
			transform: translateY(-2px);
		}

		.stat-label {
			font-size: 0.8rem;
			font-weight: 500;
			color: var(--text-muted);
			text-transform: uppercase;
			letter-spacing: 0.05em;
		}

		.stat-value {
			font-size: 1.35rem;
			font-weight: 700;
			color: var(--text-main);
			display: flex;
			align-items: center;
			gap: 0.5rem;
			word-break: break-all;
		}

		.stat-value code {
			font-family: 'JetBrains Mono', monospace;
			font-size: 1rem;
			color: var(--accent);
		}

		/* Navigation Tabs */
		.tabs-container {
			display: flex;
			gap: 0.5rem;
			overflow-x: auto;
			padding-bottom: 0.5rem;
			border-bottom: 1px solid var(--border);
		}

		.tabs-container::-webkit-scrollbar {
			height: 4px;
		}

		.tabs-container::-webkit-scrollbar-thumb {
			background: rgba(255, 255, 255, 0.1);
			border-radius: 4px;
		}

		.tab-btn {
			padding: 0.65rem 1.25rem;
			background: transparent;
			border: none;
			border-bottom: 2px solid transparent;
			color: var(--text-muted);
			font-family: inherit;
			font-size: 0.9rem;
			font-weight: 600;
			cursor: pointer;
			transition: var(--transition);
			white-space: nowrap;
			display: flex;
			align-items: center;
			gap: 0.5rem;
		}

		.tab-btn:hover {
			color: var(--text-main);
			background: rgba(255, 255, 255, 0.03);
			border-radius: var(--radius-sm) var(--radius-sm) 0 0;
		}

		.tab-btn.active {
			color: var(--accent);
			border-bottom-color: var(--accent);
		}

		/* Tab Panels */
		.tab-panel {
			display: none;
			flex-direction: column;
			gap: 1.5rem;
			animation: fadeIn 0.25s ease-out;
		}

		.tab-panel.active {
			display: flex;
		}

		@keyframes fadeIn {
			from { opacity: 0; transform: translateY(6px); }
			to { opacity: 1; transform: translateY(0); }
		}

		/* Cards */
		.card {
			background: var(--bg-card);
			border: 1px solid var(--border);
			border-radius: var(--radius);
			padding: 1.5rem;
			backdrop-filter: blur(12px);
			display: flex;
			flex-direction: column;
			gap: 1.25rem;
		}

		.card-header {
			display: flex;
			align-items: center;
			justify-content: space-between;
			border-bottom: 1px solid rgba(255, 255, 255, 0.05);
			padding-bottom: 0.75rem;
		}

		.card-title {
			font-size: 1.1rem;
			font-weight: 700;
			display: flex;
			align-items: center;
			gap: 0.6rem;
		}

		.card-desc {
			font-size: 0.85rem;
			color: var(--text-muted);
		}

		/* Form Controls */
		.form-grid {
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
			gap: 1.25rem;
		}

		.form-group {
			display: flex;
			flex-direction: column;
			gap: 0.4rem;
		}

		.form-label {
			font-size: 0.85rem;
			font-weight: 600;
			color: var(--text-main);
			display: flex;
			align-items: center;
			justify-content: space-between;
		}

		.form-label span.desc {
			font-size: 0.75rem;
			font-weight: 400;
			color: var(--text-dim);
		}

		.form-control, select, textarea {
			width: 100%;
			padding: 0.65rem 0.85rem;
			background: rgba(15, 23, 42, 0.6);
			border: 1px solid var(--border);
			border-radius: var(--radius-sm);
			color: var(--text-main);
			font-family: inherit;
			font-size: 0.9rem;
			transition: var(--transition);
		}

		.form-control:focus, select:focus, textarea:focus {
			outline: none;
			border-color: var(--accent);
			box-shadow: 0 0 0 3px var(--accent-glow);
			background: rgba(15, 23, 42, 0.9);
		}

		textarea {
			resize: vertical;
			min-height: 120px;
			font-family: 'JetBrains Mono', monospace;
			font-size: 0.85rem;
			line-height: 1.5;
		}

		/* Switch Toggle */
		.toggle-group {
			display: flex;
			align-items: center;
			justify-content: space-between;
			padding: 0.75rem 1rem;
			background: rgba(15, 23, 42, 0.4);
			border: 1px solid var(--border);
			border-radius: var(--radius-sm);
		}

		.toggle-info {
			display: flex;
			flex-direction: column;
			gap: 0.2rem;
		}

		.toggle-title {
			font-size: 0.9rem;
			font-weight: 600;
		}

		.toggle-desc {
			font-size: 0.75rem;
			color: var(--text-dim);
		}

		.switch {
			position: relative;
			display: inline-block;
			width: 44px;
			height: 24px;
			flex-shrink: 0;
		}

		.switch input {
			opacity: 0;
			width: 0;
			height: 0;
		}

		.slider {
			position: absolute;
			cursor: pointer;
			top: 0;
			left: 0;
			right: 0;
			bottom: 0;
			background-color: rgba(255, 255, 255, 0.15);
			transition: var(--transition);
			border-radius: 24px;
		}

		.slider:before {
			position: absolute;
			content: "";
			height: 18px;
			width: 18px;
			left: 3px;
			bottom: 3px;
			background-color: white;
			transition: var(--transition);
			border-radius: 50%;
		}

		input:checked + .slider {
			background-color: var(--accent);
		}

		input:checked + .slider:before {
			transform: translateX(20px);
		}

		/* Link Box */
		.link-box {
			display: flex;
			align-items: center;
			gap: 0.5rem;
			background: rgba(15, 23, 42, 0.7);
			border: 1px solid var(--border);
			border-radius: var(--radius-sm);
			padding: 0.5rem 0.75rem;
		}

		.link-text {
			flex: 1;
			font-family: 'JetBrains Mono', monospace;
			font-size: 0.85rem;
			color: var(--text-muted);
			overflow: hidden;
			text-overflow: ellipsis;
			white-space: nowrap;
		}

		/* Toast Notification */
		#toast {
			position: fixed;
			bottom: 2rem;
			right: 2rem;
			padding: 0.85rem 1.25rem;
			background: rgba(17, 24, 39, 0.95);
			border: 1px solid var(--border);
			border-radius: var(--radius-sm);
			color: #fff;
			font-size: 0.9rem;
			font-weight: 500;
			box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
			backdrop-filter: blur(12px);
			display: flex;
			align-items: center;
			gap: 0.75rem;
			transform: translateY(100px);
			opacity: 0;
			transition: var(--transition);
			z-index: 100;
		}

		#toast.show {
			transform: translateY(0);
			opacity: 1;
		}

		#toast.success { border-left: 4px solid var(--success); }
		#toast.error { border-left: 4px solid var(--danger); }
		#toast.info { border-left: 4px solid var(--accent); }

		/* Modal */
		.modal-overlay {
			position: fixed;
			top: 0;
			left: 0;
			width: 100%;
			height: 100%;
			background: rgba(0, 0, 0, 0.7);
			backdrop-filter: blur(6px);
			display: none;
			align-items: center;
			justify-content: center;
			z-index: 90;
			padding: 1rem;
		}

		.modal-overlay.open {
			display: flex;
		}

		.modal-content {
			background: var(--bg-surface);
			border: 1px solid var(--border);
			border-radius: var(--radius);
			max-width: 500px;
			width: 100%;
			padding: 1.5rem;
			display: flex;
			flex-direction: column;
			gap: 1.25rem;
			box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6);
		}

		.modal-header {
			display: flex;
			align-items: center;
			justify-content: space-between;
			font-weight: 700;
			font-size: 1.1rem;
		}

		.modal-close {
			background: transparent;
			border: none;
			color: var(--text-muted);
			font-size: 1.25rem;
			cursor: pointer;
		}

		.qr-wrapper {
			display: flex;
			justify-content: center;
			padding: 1rem;
			background: #fff;
			border-radius: var(--radius-sm);
		}

		@media (max-width: 768px) {
			.header-container { flex-direction: column; align-items: stretch; }
			.header-actions { justify-content: flex-end; }
			.form-grid { grid-template-columns: 1fr; }
		}
	</style>
</head>
<body>

	<!-- Header -->
	<header>
		<div class="header-container">
			<a href="/admin" class="brand">
				<div class="brand-icon">⚡</div>
				<div>
					<div style="display: flex; align-items: center; gap: 0.5rem;">
						<span class="brand-name">EdgeTunnel</span>
						<span class="brand-badge">v2.1</span>
					</div>
					<div style="font-size: 0.75rem; color: var(--text-dim);" id="header-host">Loading host...</div>
				</div>
			</a>
			<div class="header-actions">
				<button class="btn btn-secondary btn-sm" onclick="loadAllData()" title="Reload Data">🔄 Refresh</button>
				<button class="btn btn-primary btn-sm" onclick="saveConfiguration()">💾 Save Config</button>
				<a href="/logout" class="btn btn-danger btn-sm">🚪 Logout</a>
			</div>
		</div>
	</header>

	<!-- Main -->
	<main>
		<!-- Quick Stats Overview -->
		<div class="overview-grid">
			<div class="stat-card">
				<div class="stat-label">Active Protocol</div>
				<div class="stat-value"><code id="stat-protocol">-</code></div>
			</div>
			<div class="stat-card">
				<div class="stat-label">Transport & gRPC</div>
				<div class="stat-value"><code id="stat-transport">-</code></div>
			</div>
			<div class="stat-card">
				<div class="stat-label">Cloudflare Usage (Today)</div>
				<div class="stat-value" id="stat-cf-usage"><span style="color: var(--success);">0</span> / 100k</div>
			</div>
			<div class="stat-card">
				<div class="stat-label">Config Load Time</div>
				<div class="stat-value"><code id="stat-load-time">-</code></div>
			</div>
		</div>

		<!-- Navigation Tabs -->
		<div class="tabs-container">
			<button class="tab-btn active" onclick="switchTab('nodes', this)">📋 Node Links & Subscriptions</button>
			<button class="tab-btn" onclick="switchTab('network', this)">🌐 Cloudflare & Network</button>
			<button class="tab-btn" onclick="switchTab('generator', this)">⚡ Optimal Subscriptions</button>
			<button class="tab-btn" onclick="switchTab('subconverter', this)">🔄 Subconverter</button>
			<button class="tab-btn" onclick="switchTab('proxy', this)">🔀 Reverse & Chained Proxy</button>
			<button class="tab-btn" onclick="switchTab('cloudflare', this)">☁️ Cloudflare API</button>
			<button class="tab-btn" onclick="switchTab('logs', this)">📜 Operation Logs</button>
		</div>

		<!-- Tab 1: Node Links & Subscriptions -->
		<div id="tab-nodes" class="tab-panel active">
			<div class="card">
				<div class="card-header">
					<div>
						<div class="card-title">🔗 Primary Node Link</div>
						<div class="card-desc">Direct connection string generated dynamically based on your active protocol settings</div>
					</div>
					<button class="btn btn-secondary btn-sm" onclick="openQrModal('main')">📱 Show QR Code</button>
				</div>
				<div class="link-box">
					<div class="link-text" id="primary-node-link">Loading node link...</div>
					<button class="btn btn-primary btn-sm" onclick="copyText(document.getElementById('primary-node-link').textContent)">📋 Copy</button>
				</div>
			</div>

			<div class="card">
				<div class="card-header">
					<div>
						<div class="card-title">🔄 Client Subscription URLs</div>
						<div class="card-desc">Import ready-to-use subscriptions into Clash, SingBox, Surge, Shadowrocket or V2Ray clients</div>
					</div>
				</div>
				<div class="form-grid">
					<div class="form-group">
						<label class="form-label">Universal Auto-Adaptive Subscription</label>
						<div class="link-box">
							<div class="link-text" id="sub-auto">-</div>
							<button class="btn btn-secondary btn-sm" onclick="copyText(document.getElementById('sub-auto').textContent)">Copy</button>
						</div>
					</div>
					<div class="form-group">
						<label class="form-label">Clash / Clash Meta URL</label>
						<div class="link-box">
							<div class="link-text" id="sub-clash">-</div>
							<button class="btn btn-secondary btn-sm" onclick="copyText(document.getElementById('sub-clash').textContent)">Copy</button>
						</div>
					</div>
					<div class="form-group">
						<label class="form-label">Sing-Box URL</label>
						<div class="link-box">
							<div class="link-text" id="sub-singbox">-</div>
							<button class="btn btn-secondary btn-sm" onclick="copyText(document.getElementById('sub-singbox').textContent)">Copy</button>
						</div>
					</div>
					<div class="form-group">
						<label class="form-label">Standard Base64 Subscription</label>
						<div class="link-box">
							<div class="link-text" id="sub-b64">-</div>
							<button class="btn btn-secondary btn-sm" onclick="copyText(document.getElementById('sub-b64').textContent)">Copy</button>
						</div>
					</div>
				</div>
			</div>
		</div>

		<!-- Tab 2: Cloudflare & Network Settings -->
		<div id="tab-network" class="tab-panel">
			<div class="card">
				<div class="card-header">
					<div>
						<div class="card-title">⚙️ Core Protocol & Connection Parameters</div>
						<div class="card-desc">Configure tunneling protocol, transport layer, and TLS obfuscation parameters</div>
					</div>
				</div>
				<div class="form-grid">
					<div class="form-group">
						<label class="form-label">Protocol Type</label>
						<select id="cfg-protocolType">
							<option value="vless">VLESS</option>
							<option value="vmess">VMess</option>
							<option value="ss">Shadowsocks (SS)</option>
						</select>
					</div>
					<div class="form-group">
						<label class="form-label">Transport Protocol</label>
						<select id="cfg-transportProtocol">
							<option value="ws">WebSocket (WS)</option>
							<option value="grpc">gRPC</option>
							<option value="xhttp">XHTTP / HTTP Upgrade</option>
						</select>
					</div>
					<div class="form-group">
						<label class="form-label">Node Path</label>
						<input type="text" class="form-control" id="cfg-path" placeholder="/">
					</div>
					<div class="form-group">
						<label class="form-label">Client Fingerprint</label>
						<select id="cfg-fingerprint">
							<option value="chrome">Chrome</option>
							<option value="firefox">Firefox</option>
							<option value="safari">Safari</option>
							<option value="ios">iOS</option>
							<option value="randomized">Randomized</option>
						</select>
					</div>
					<div class="form-group">
						<label class="form-label">TLS Fragment</label>
						<select id="cfg-tlsFragment">
							<option value="">None / Disabled</option>
							<option value="Shadowrocket">Shadowrocket (1,40-60,30-50,tlshello)</option>
							<option value="Happ">Happ (3,1,tlshello)</option>
						</select>
					</div>
					<div class="form-group">
						<label class="form-label">gRPC Mode</label>
						<select id="cfg-grpcMode">
							<option value="gun">gun</option>
							<option value="multi">multi</option>
						</select>
					</div>
				</div>

				<div class="form-grid" style="margin-top: 0.5rem;">
					<div class="toggle-group">
						<div class="toggle-info">
							<div class="toggle-title">Skip Certificate Verification</div>
							<div class="toggle-desc">Allow insecure TLS connections (skipCertVerify)</div>
						</div>
						<label class="switch">
							<input type="checkbox" id="cfg-skipCertVerify">
							<span class="slider"></span>
						</label>
					</div>
					<div class="toggle-group">
						<div class="toggle-info">
							<div class="toggle-title">Enable 0-RTT Connection</div>
							<div class="toggle-desc">Zero Round Trip Time early data acceleration</div>
						</div>
						<label class="switch">
							<input type="checkbox" id="cfg-enable0RTT">
							<span class="slider"></span>
						</label>
					</div>
					<div class="toggle-group">
						<div class="toggle-info">
							<div class="toggle-title">Random Path Generation</div>
							<div class="toggle-desc">Use randomized path prefixes for connection obfuscation</div>
						</div>
						<label class="switch">
							<input type="checkbox" id="cfg-randomPath">
							<span class="slider"></span>
						</label>
					</div>
					<div class="toggle-group">
						<div class="toggle-info">
							<div class="toggle-title">Encrypted Client Hello (ECH)</div>
							<div class="toggle-desc">Enable ECH SNI obfuscation with DoH</div>
						</div>
						<label class="switch">
							<input type="checkbox" id="cfg-ech">
							<span class="slider"></span>
						</label>
					</div>
				</div>
			</div>
		</div>

		<!-- Tab 3: Optimal Subscriptions -->
		<div id="tab-generator" class="tab-panel">
			<div class="card">
				<div class="card-header">
					<div>
						<div class="card-title">⚡ Optimal Subscription Generator Settings</div>
						<div class="card-desc">Configure automated optimal IP pools and subscription auto-updating</div>
					</div>
				</div>
				<div class="form-grid">
					<div class="form-group">
						<label class="form-label">Subscription Name (SUBNAME)</label>
						<input type="text" class="form-control" id="cfg-subname" placeholder="edgetunnel">
					</div>
					<div class="form-group">
						<label class="form-label">Update Interval (Hours)</label>
						<input type="number" class="form-control" id="cfg-subUpdateTime" value="3" min="1" max="72">
					</div>
					<div class="form-group">
						<label class="form-label">External Generator URL (Optional)</label>
						<input type="text" class="form-control" id="cfg-subGeneratorUrl" placeholder="https://...">
					</div>
					<div class="form-group">
						<label class="form-label">Random IP Count</label>
						<input type="number" class="form-control" id="cfg-randomCount" value="16" min="1" max="100">
					</div>
					<div class="form-group">
						<label class="form-label">Specified Port (-1 for all)</label>
						<input type="number" class="form-control" id="cfg-specifiedPort" value="-1">
					</div>
				</div>
			</div>

			<div class="card">
				<div class="card-header">
					<div>
						<div class="card-title">📝 Custom Optimal IP List (ADD.txt)</div>
						<div class="card-desc">Enter custom IP:PORT or domain nodes to inject into your subscription</div>
					</div>
					<button class="btn btn-secondary btn-sm" onclick="saveAddTxt()">Save ADD.txt</button>
				</div>
				<textarea id="cfg-addTxt" placeholder="Example:&#10;104.16.1.1:443#Optimal_CF_1&#10;104.16.2.1:443#Optimal_CF_2"></textarea>
			</div>
		</div>

		<!-- Tab 4: Subconverter -->
		<div id="tab-subconverter" class="tab-panel">
			<div class="card">
				<div class="card-header">
					<div>
						<div class="card-title">🔄 Subscription Conversion Service</div>
						<div class="card-desc">Configure subconverter backend rules and output options</div>
					</div>
				</div>
				<div class="form-grid">
					<div class="form-group" style="grid-column: 1 / -1;">
						<label class="form-label">Subconverter API Backend</label>
						<input type="text" class="form-control" id="cfg-subApi" placeholder="https://api.v1.mk">
					</div>
					<div class="form-group" style="grid-column: 1 / -1;">
						<label class="form-label">Remote Rule Configuration File (ACL4SSR)</label>
						<input type="text" class="form-control" id="cfg-subConfig" placeholder="https://raw.githubusercontent.com/...">
					</div>
				</div>

				<div class="form-grid" style="margin-top: 0.5rem;">
					<div class="toggle-group">
						<div class="toggle-info">
							<div class="toggle-title">Include Node Flag Emojis</div>
							<div class="toggle-desc">Automatically add country flags (SUBEMOJI)</div>
						</div>
						<label class="switch">
							<input type="checkbox" id="cfg-subEmoji">
							<span class="slider"></span>
						</label>
					</div>
					<div class="toggle-group">
						<div class="toggle-info">
							<div class="toggle-title">Enable UDP Forwarding</div>
							<div class="toggle-desc">Allow UDP traffic through converted nodes</div>
						</div>
						<label class="switch">
							<input type="checkbox" id="cfg-subUdp">
							<span class="slider"></span>
						</label>
					</div>
					<div class="toggle-group">
						<div class="toggle-info">
							<div class="toggle-title">Enable TLS 1.3</div>
							<div class="toggle-desc">Force TLS 1.3 protocol support in client configs</div>
						</div>
						<label class="switch">
							<input type="checkbox" id="cfg-subTls13">
							<span class="slider"></span>
						</label>
					</div>
					<div class="toggle-group">
						<div class="toggle-info">
							<div class="toggle-title">Sort Nodes by Latency/Name</div>
							<div class="toggle-desc">Enable alphabetical node sorting</div>
						</div>
						<label class="switch">
							<input type="checkbox" id="cfg-subSort">
							<span class="slider"></span>
						</label>
					</div>
				</div>
			</div>
		</div>

		<!-- Tab 5: Reverse & Chained Proxy -->
		<div id="tab-proxy" class="tab-panel">
			<div class="card">
				<div class="card-header">
					<div>
						<div class="card-title">🔀 Reverse Proxy & Outbound SOCKS5 Settings</div>
						<div class="card-desc">Configure outbound proxy forwarding to bypass Cloudflare CDN limitations</div>
					</div>
				</div>
				<div class="form-grid">
					<div class="form-group">
						<label class="form-label">Default Outbound Mode</label>
						<select id="cfg-proxyMode">
							<option value="auto">Auto (Direct connect or path specified)</option>
							<option value="socks5">SOCKS5 Outbound Proxy</option>
							<option value="http">HTTP Outbound Proxy</option>
						</select>
					</div>
					<div class="form-group">
						<label class="form-label">SOCKS5 Proxy Account (user:pass@host:port)</label>
						<input type="text" class="form-control" id="cfg-socks5Account" placeholder="user:pass@ip:port">
					</div>
					<div class="form-group" style="grid-column: 1 / -1;">
						<label class="form-label">SOCKS5 Target Whitelist (comma separated)</label>
						<input type="text" class="form-control" id="cfg-socks5Whitelist" placeholder="google.com, chatgpt.com">
					</div>
				</div>
			</div>

			<div class="card">
				<div class="card-header">
					<div>
						<div class="card-title">🔍 Proxy Connectivity Diagnostic Tool</div>
						<div class="card-desc">Test whether an outbound proxy IP/port is reachable from Cloudflare Workers</div>
					</div>
				</div>
				<div style="display: flex; gap: 0.75rem; flex-wrap: wrap;">
					<input type="text" class="form-control" id="test-proxy-input" placeholder="socks5://user:pass@ip:port or http://ip:port" style="flex: 1; min-width: 280px;">
					<button class="btn btn-primary" onclick="testProxyConnectivity()">⚡ Test Reachability</button>
				</div>
				<div id="proxy-test-result" style="display: none; padding: 1rem; background: rgba(15, 23, 42, 0.8); border-radius: var(--radius-sm); border: 1px solid var(--border); font-family: 'JetBrains Mono', monospace; font-size: 0.85rem;"></div>
			</div>
		</div>

		<!-- Tab 6: Cloudflare API -->
		<div id="tab-cloudflare" class="tab-panel">
			<div class="card">
				<div class="card-header">
					<div>
						<div class="card-title">☁️ Cloudflare Credentials & Daily Request Quota</div>
						<div class="card-desc">Connect your Cloudflare account to monitor Workers & Pages daily quota</div>
					</div>
				</div>
				<div class="form-grid">
					<div class="form-group">
						<label class="form-label">Account Email</label>
						<input type="email" class="form-control" id="cfg-cfEmail" placeholder="user@example.com">
					</div>
					<div class="form-group">
						<label class="form-label">Global API Key</label>
						<input type="password" class="form-control" id="cfg-cfApiKey" placeholder="Cloudflare Global API Key">
					</div>
					<div class="form-group">
						<label class="form-label">Account ID</label>
						<input type="text" class="form-control" id="cfg-cfAccountId" placeholder="Account ID hex">
					</div>
					<div class="form-group">
						<label class="form-label">API Token (Optional)</label>
						<input type="password" class="form-control" id="cfg-cfApiToken" placeholder="Cloudflare API Token">
					</div>
				</div>
				<div style="display: flex; justify-content: flex-end; margin-top: 0.5rem;">
					<button class="btn btn-secondary" onclick="saveCfSettings()">Save Cloudflare Credentials</button>
				</div>
			</div>
		</div>

		<!-- Tab 8: Operation Logs -->
		<div id="tab-logs" class="tab-panel">
			<div class="card">
				<div class="card-header">
					<div>
						<div class="card-title">📜 System Operation Logs</div>
						<div class="card-desc">Audit history of recent configuration changes and admin access</div>
					</div>
					<div style="display: flex; gap: 0.5rem;">
						<button class="btn btn-secondary btn-sm" onclick="loadLogs()">🔄 Refresh Logs</button>
						<button class="btn btn-danger btn-sm" onclick="clearLogs()">🗑️ Clear Logs</button>
					</div>
				</div>
				<div id="logs-container" style="background: rgba(15, 23, 42, 0.7); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 1rem; max-height: 400px; overflow-y: auto; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; line-height: 1.6; color: var(--text-muted);">
					Loading logs...
				</div>
			</div>

			<div class="card" style="border-color: rgba(239, 68, 68, 0.3);">
				<div class="card-header">
					<div>
						<div class="card-title" style="color: var(--danger);">⚠️ Factory Reset</div>
						<div class="card-desc">Restore all EdgeTunnel settings back to initial defaults</div>
					</div>
					<button class="btn btn-danger btn-sm" onclick="resetConfigDefaults()">Reset All to Defaults</button>
				</div>
			</div>
		</div>
	</main>

	<!-- QR Modal -->
	<div id="qr-modal" class="modal-overlay" onclick="if(event.target === this) closeQrModal()">
		<div class="modal-content">
			<div class="modal-header">
				<span>📱 Node QR Code</span>
				<button class="modal-close" onclick="closeQrModal()">&times;</button>
			</div>
			<div class="qr-wrapper">
				<img id="qr-image" src="" alt="QR Code" style="max-width: 250px; width: 100%; height: auto;">
			</div>
			<button class="btn btn-secondary" onclick="closeQrModal()">Close</button>
		</div>
	</div>

	<!-- Toast Message -->
	<div id="toast">Message</div>

	<script>
		let currentConfig = {};

		// Switch Tab
		function switchTab(tabId, btn) {
			document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
			document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
			const target = document.getElementById('tab-' + tabId);
			if (target) target.classList.add('active');
			if (btn) btn.classList.add('active');
		}

		// Toast Notification
		function showToast(msg, type = 'success') {
			const toast = document.getElementById('toast');
			toast.textContent = msg;
			toast.className = 'show ' + type;
			setTimeout(() => { toast.className = ''; }, 3500);
		}

		// Copy text
		function copyText(text) {
			if (!text || text === '-' || text.includes('Loading')) return;
			navigator.clipboard.writeText(text).then(() => {
				showToast('Copied to clipboard! 📋', 'success');
			}).catch(() => {
				showToast('Failed to copy', 'error');
			});
		}

		// QR Modal
		function openQrModal(type) {
			const link = document.getElementById('primary-node-link').textContent;
			if (!link || link.includes('Loading')) return;
			const qrUrl = 'https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=' + encodeURIComponent(link);
			document.getElementById('qr-image').src = qrUrl;
			document.getElementById('qr-modal').classList.add('open');
		}

		function closeQrModal() {
			document.getElementById('qr-modal').classList.remove('open');
		}

		// Load All Data
		async function loadAllData() {
			try {
				const res = await fetch('/admin/config.json');
				if (!res.ok) throw new Error('Failed to fetch config');
				currentConfig = await res.json();
				populateForm(currentConfig);
				loadAddTxt();
				loadLogs();
				showToast('Configuration loaded successfully', 'info');
			} catch (err) {
				console.error(err);
				showToast('Error loading configuration: ' + err.message, 'error');
			}
		}

		// Populate UI with Config
		function populateForm(cfg) {
			const host = cfg.HOST || window.location.hostname;
			document.getElementById('header-host').textContent = host;
			document.getElementById('stat-protocol').textContent = (cfg.protocolType || 'vless').toUpperCase();
			document.getElementById('stat-transport').textContent = (cfg.transportProtocol || 'ws').toUpperCase();
			document.getElementById('stat-load-time').textContent = cfg.loadTime || '0ms';

			if (cfg.CF?.Usage) {
				const u = cfg.CF.Usage;
				document.getElementById('stat-cf-usage').innerHTML = 
					'<span style="color: var(--success);">' + (u.total || 0).toLocaleString() + '</span> / ' + (u.max || 100000).toLocaleString();
			}

			// Node Links
			const nodeLink = cfg.LINK || 'No link generated';
			document.getElementById('primary-node-link').textContent = nodeLink;

			const token = cfg.optSubGenerator?.TOKEN || '';
			const origin = window.location.origin;
			document.getElementById('sub-auto').textContent = origin + '/sub?token=' + token;
			document.getElementById('sub-clash').textContent = origin + '/sub?token=' + token + '&clash=1';
			document.getElementById('sub-singbox').textContent = origin + '/sub?token=' + token + '&singbox=1';
			document.getElementById('sub-b64').textContent = origin + '/sub?token=' + token + '&b64=1';

			// Tab 2: Network
			document.getElementById('cfg-protocolType').value = cfg.protocolType || 'vless';
			document.getElementById('cfg-transportProtocol').value = cfg.transportProtocol || 'ws';
			document.getElementById('cfg-path').value = cfg.PATH || '/';
			document.getElementById('cfg-fingerprint').value = cfg.Fingerprint || 'chrome';
			document.getElementById('cfg-tlsFragment').value = cfg.TLSFragment || '';
			document.getElementById('cfg-grpcMode').value = cfg.gRPCmode || 'gun';
			document.getElementById('cfg-skipCertVerify').checked = !!cfg.skipCertVerify;
			document.getElementById('cfg-enable0RTT').checked = !!cfg.enable0RTT;
			document.getElementById('cfg-randomPath').checked = !!cfg.randomPath;
			document.getElementById('cfg-ech').checked = !!cfg.ECH;

			// Tab 3: Optimal Sub Generator
			const opt = cfg.optSubGenerator || {};
			document.getElementById('cfg-subname').value = opt.SUBNAME || 'edgetunnel';
			document.getElementById('cfg-subUpdateTime').value = opt.SUBUpdateTime || 3;
			document.getElementById('cfg-subGeneratorUrl').value = opt.SUB || '';
			document.getElementById('cfg-randomCount').value = opt.localIPDB?.randomCount || 16;
			document.getElementById('cfg-specifiedPort').value = opt.localIPDB?.specifiedPort ?? -1;

			// Tab 4: Subconverter
			const sc = cfg.subConverterConfig || {};
			document.getElementById('cfg-subApi').value = sc.SUBAPI || '';
			document.getElementById('cfg-subConfig').value = sc.SUBCONFIG || '';
			document.getElementById('cfg-subEmoji').checked = !!sc.SUBEMOJI;
			document.getElementById('cfg-subUdp').checked = !!sc.UDP;
			document.getElementById('cfg-subTls13').checked = !!sc.TLS13;
			document.getElementById('cfg-subSort').checked = !!sc.SORT;

			// Tab 5: Proxy
			const px = cfg.proxy || {};
			document.getElementById('cfg-proxyMode').value = px.SOCKS5?.enable ? 'socks5' : 'auto';
			document.getElementById('cfg-socks5Account').value = px.SOCKS5?.account || '';
			document.getElementById('cfg-socks5Whitelist').value = (px.SOCKS5?.whitelist || []).join(', ');

			// Tab 6: Cloudflare
			document.getElementById('cfg-cfEmail').value = cfg.CF?.Email || '';
			document.getElementById('cfg-cfApiKey').value = cfg.CF?.GlobalAPIKey || '';
			document.getElementById('cfg-cfAccountId').value = cfg.CF?.AccountID || '';
			document.getElementById('cfg-cfApiToken').value = cfg.CF?.APIToken || '';
		}

		// Save Configuration
		async function saveConfiguration() {
			try {
				currentConfig.protocolType = document.getElementById('cfg-protocolType').value;
				currentConfig.transportProtocol = document.getElementById('cfg-transportProtocol').value;
				currentConfig.PATH = document.getElementById('cfg-path').value || '/';
				currentConfig.Fingerprint = document.getElementById('cfg-fingerprint').value;
				currentConfig.TLSFragment = document.getElementById('cfg-tlsFragment').value || null;
				currentConfig.gRPCmode = document.getElementById('cfg-grpcMode').value;
				currentConfig.skipCertVerify = document.getElementById('cfg-skipCertVerify').checked;
				currentConfig.enable0RTT = document.getElementById('cfg-enable0RTT').checked;
				currentConfig.randomPath = document.getElementById('cfg-randomPath').checked;
				currentConfig.ECH = document.getElementById('cfg-ech').checked;

				currentConfig.optSubGenerator = currentConfig.optSubGenerator || {};
				currentConfig.optSubGenerator.SUBNAME = document.getElementById('cfg-subname').value || 'edgetunnel';
				currentConfig.optSubGenerator.SUBUpdateTime = parseInt(document.getElementById('cfg-subUpdateTime').value, 10) || 3;
				currentConfig.optSubGenerator.SUB = document.getElementById('cfg-subGeneratorUrl').value || null;
				currentConfig.optSubGenerator.localIPDB = currentConfig.optSubGenerator.localIPDB || {};
				currentConfig.optSubGenerator.localIPDB.randomCount = parseInt(document.getElementById('cfg-randomCount').value, 10) || 16;
				currentConfig.optSubGenerator.localIPDB.specifiedPort = parseInt(document.getElementById('cfg-specifiedPort').value, 10);

				currentConfig.subConverterConfig = currentConfig.subConverterConfig || {};
				currentConfig.subConverterConfig.SUBAPI = document.getElementById('cfg-subApi').value;
				currentConfig.subConverterConfig.SUBCONFIG = document.getElementById('cfg-subConfig').value;
				currentConfig.subConverterConfig.SUBEMOJI = document.getElementById('cfg-subEmoji').checked;
				currentConfig.subConverterConfig.UDP = document.getElementById('cfg-subUdp').checked;
				currentConfig.subConverterConfig.TLS13 = document.getElementById('cfg-subTls13').checked;
				currentConfig.subConverterConfig.SORT = document.getElementById('cfg-subSort').checked;

				currentConfig.proxy = currentConfig.proxy || {};
				currentConfig.proxy.SOCKS5 = currentConfig.proxy.SOCKS5 || {};
				currentConfig.proxy.SOCKS5.enable = document.getElementById('cfg-proxyMode').value === 'socks5' ? 'SOCKS5' : null;
				currentConfig.proxy.SOCKS5.account = document.getElementById('cfg-socks5Account').value;
				currentConfig.proxy.SOCKS5.whitelist = document.getElementById('cfg-socks5Whitelist').value
					.split(',').map(s => s.trim()).filter(Boolean);

				const res = await fetch('/admin/config.json', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify(currentConfig)
				});

				if (!res.ok) throw new Error('Save request failed: ' + res.status);
				showToast('Configuration saved successfully! 💾', 'success');
				loadAllData();
			} catch (err) {
				console.error(err);
				showToast('Failed to save config: ' + err.message, 'error');
			}
		}

		// Load ADD.txt
		async function loadAddTxt() {
			try {
				const res = await fetch('/admin/ADD.txt');
				if (res.ok) {
					const text = await res.text();
					document.getElementById('cfg-addTxt').value = text === 'null' ? '' : text;
				}
			} catch (e) {
				console.error('loadAddTxt error:', e);
			}
		}

		// Save ADD.txt
		async function saveAddTxt() {
			try {
				const val = document.getElementById('cfg-addTxt').value;
				const res = await fetch('/admin/ADD.txt', {
					method: 'POST',
					headers: { 'Content-Type': 'text/plain;charset=utf-8' },
					body: val
				});
				if (res.ok) showToast('ADD.txt saved successfully! 📝', 'success');
				else showToast('Failed to save ADD.txt', 'error');
			} catch (e) {
				showToast('Error saving ADD.txt: ' + e.message, 'error');
			}
		}

		// Save Cloudflare Settings
		async function saveCfSettings() {
			try {
				const data = {
					Email: document.getElementById('cfg-cfEmail').value,
					GlobalAPIKey: document.getElementById('cfg-cfApiKey').value,
					AccountID: document.getElementById('cfg-cfAccountId').value,
					APIToken: document.getElementById('cfg-cfApiToken').value
				};
				const res = await fetch('/admin/cf.json', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify(data)
				});
				if (res.ok) showToast('Cloudflare settings saved! ☁️', 'success');
				else showToast('Failed to save Cloudflare settings', 'error');
			} catch (e) {
				showToast('Error: ' + e.message, 'error');
			}
		}

		// Load Logs
		async function loadLogs() {
			const container = document.getElementById('logs-container');
			try {
				const res = await fetch('/admin/log.json');
				if (res.ok) {
					const logs = await res.json();
					if (Array.isArray(logs) && logs.length > 0) {
						container.innerHTML = logs.map(l => {
							const time = l.Time || l.time || '';
							const ip = l.IP || l.ip || '';
							const action = l.Action || l.action || '';
							return '<div><span style="color: var(--accent);">[' + time + ']</span> ' +
								'<span style="color: var(--success);">' + ip + '</span> - ' +
								'<strong>' + action + '</strong></div>';
						}).reverse().join('');
					} else {
						container.innerHTML = '<em>No logs recorded yet.</em>';
					}
				}
			} catch (e) {
				container.innerHTML = '<em>Failed to load logs.</em>';
			}
		}

		// Clear Logs
		async function clearLogs() {
			if (!confirm('Are you sure you want to clear all operation logs?')) return;
			try {
				const res = await fetch('/admin/log.json', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify([])
				});
				if (res.ok) {
					showToast('Logs cleared! 🗑️', 'info');
					loadLogs();
				}
			} catch (e) {
				showToast('Failed to clear logs', 'error');
			}
		}

		// Test Proxy Reachability
		async function testProxyConnectivity() {
			const input = document.getElementById('test-proxy-input').value.trim();
			if (!input) return showToast('Please enter a proxy string to test', 'error');

			const resBox = document.getElementById('proxy-test-result');
			resBox.style.display = 'block';
			resBox.innerHTML = '⏳ Testing connectivity to ' + input + '...';

			try {
				const res = await fetch('/admin/check?proxy=' + encodeURIComponent(input));
				const data = await res.json();
				if (data.success) {
					resBox.innerHTML = '<span style="color: var(--success);">✔ Reachable!</span> Response time: <strong>' + data.responseTime + 'ms</strong><br>' +
						'Egress IP: ' + data.ip + ' | Location: ' + data.loc;
				} else {
					resBox.innerHTML = '<span style="color: var(--danger);">✖ Connection Failed:</span> ' + (data.error || 'Unknown error');
				}
			} catch (err) {
				resBox.innerHTML = '<span style="color: var(--danger);">✖ Error:</span> ' + err.message;
			}
		}

		// Reset Config Defaults
		async function resetConfigDefaults() {
			if (!confirm('WARNING: This will reset all EdgeTunnel settings back to default values. Continue?')) return;
			try {
				const res = await fetch('/admin/init');
				if (res.ok) {
					showToast('Configuration restored to factory defaults! ⚡', 'success');
					loadAllData();
				} else {
					showToast('Reset failed', 'error');
				}
			} catch (err) {
				showToast('Reset error: ' + err.message, 'error');
			}
		}

		// Initial load
		document.addEventListener('DOMContentLoaded', loadAllData);
	</script>
</body>
</html>`;
}
