/**
 * src/html/errorPages.js
 * Standalone English error pages for EdgeTunnel
 */

export function noAdminPage() {
	return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="robots" content="noindex, nofollow">
	<title>Configuration Required - EdgeTunnel</title>
	<style>
		* { margin: 0; padding: 0; box-sizing: border-box; }
		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
			background: #0f172a;
			color: #f8fafc;
			min-height: 100vh;
			display: flex;
			align-items: center;
			justify-content: center;
			padding: 20px;
		}
		.card {
			background: rgba(30, 41, 59, 0.85);
			backdrop-filter: blur(20px);
			border: 1px solid rgba(255, 255, 255, 0.1);
			border-radius: 24px;
			padding: 48px 40px;
			max-width: 460px;
			width: 100%;
			text-align: center;
			box-shadow: 0 20px 60px rgba(0, 0, 0, 0.4);
		}
		.icon {
			width: 64px;
			height: 64px;
			margin: 0 auto 20px;
			background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
			border-radius: 18px;
			display: flex;
			align-items: center;
			justify-content: center;
			box-shadow: 0 10px 25px rgba(239, 68, 68, 0.3);
		}
		.icon svg { width: 32px; height: 32px; fill: white; }
		h1 { font-size: 24px; font-weight: 700; margin-bottom: 12px; }
		p { font-size: 14px; color: #94a3b8; line-height: 1.6; margin-bottom: 24px; }
		.code-box {
			background: #0f172a;
			border: 1px solid #334155;
			border-radius: 12px;
			padding: 14px 18px;
			font-family: monospace;
			font-size: 14px;
			color: #f6821f;
			margin-bottom: 24px;
		}
		.footer { font-size: 13px; color: #64748b; }
		.footer a { color: #f6821f; text-decoration: none; }
	</style>
</head>
<body>
	<div class="card">
		<div class="icon">
			<svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>
		</div>
		<h1>Admin Password Not Set</h1>
		<p>Please configure the admin password in your environment variables to enable dashboard access.</p>
		<div class="code-box">Variable: ADMIN = &lt;your_password&gt;</div>
		<div class="footer">
			Powered by <a href="https://github.com/cmliu/edgetunnel" target="_blank" rel="noopener">EdgeTunnel</a>
		</div>
	</div>
</body>
</html>`;
}

export function noKVPage() {
	return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="robots" content="noindex, nofollow">
	<title>KV Binding Required - EdgeTunnel</title>
	<style>
		* { margin: 0; padding: 0; box-sizing: border-box; }
		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
			background: #0f172a;
			color: #f8fafc;
			min-height: 100vh;
			display: flex;
			align-items: center;
			justify-content: center;
			padding: 20px;
		}
		.card {
			background: rgba(30, 41, 59, 0.85);
			backdrop-filter: blur(20px);
			border: 1px solid rgba(255, 255, 255, 0.1);
			border-radius: 24px;
			padding: 48px 40px;
			max-width: 460px;
			width: 100%;
			text-align: center;
			box-shadow: 0 20px 60px rgba(0, 0, 0, 0.4);
		}
		.icon {
			width: 64px;
			height: 64px;
			margin: 0 auto 20px;
			background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
			border-radius: 18px;
			display: flex;
			align-items: center;
			justify-content: center;
			box-shadow: 0 10px 25px rgba(245, 158, 11, 0.3);
		}
		.icon svg { width: 32px; height: 32px; fill: white; }
		h1 { font-size: 24px; font-weight: 700; margin-bottom: 12px; }
		p { font-size: 14px; color: #94a3b8; line-height: 1.6; margin-bottom: 24px; }
		.code-box {
			background: #0f172a;
			border: 1px solid #334155;
			border-radius: 12px;
			padding: 14px 18px;
			font-family: monospace;
			font-size: 14px;
			color: #f6821f;
			margin-bottom: 24px;
		}
		.footer { font-size: 13px; color: #64748b; }
		.footer a { color: #f6821f; text-decoration: none; }
	</style>
</head>
<body>
	<div class="card">
		<div class="icon">
			<svg viewBox="0 0 24 24"><path d="M4 6H2v14c0 1.1.9 2 2 2h14v-2H4V6zm16-4H8c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H8V4h12v12z"/></svg>
		</div>
		<h1>KV Namespace Not Bound</h1>
		<p>Please bind a KV Namespace with variable name <strong>KV</strong> in your Cloudflare Workers settings.</p>
		<div class="code-box">KV Binding: Variable name = KV</div>
		<div class="footer">
			Powered by <a href="https://github.com/cmliu/edgetunnel" target="_blank" rel="noopener">EdgeTunnel</a>
		</div>
	</div>
</body>
</html>`;
}
