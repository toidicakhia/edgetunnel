/**
 * src/html/login.js
 * Standalone English Login Page for EdgeTunnel
 */

export function loginPage() {
	return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="robots" content="noindex, nofollow">
	<title>EdgeTunnel - Admin Login</title>
	<style>
		* {
			margin: 0;
			padding: 0;
			box-sizing: border-box;
		}

		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
			overflow: hidden;
			background: #0f172a;
		}

		@keyframes blurOverlayAppear {
			0% { opacity: 0; backdrop-filter: blur(0px); }
			100% { opacity: 1; backdrop-filter: blur(12px); }
		}

		@keyframes containerAppear {
			0% { opacity: 0; transform: translateY(30px) scale(0.95); }
			100% { opacity: 1; transform: translateY(0) scale(1); }
		}

		@keyframes gradientShift {
			0% { background-position: 0 50%; }
			50% { background-position: 100% 50%; }
			100% { background-position: 0 50%; }
		}

		#blur-overlay {
			position: fixed;
			top: 0;
			left: 0;
			width: 100%;
			height: 100%;
			background: radial-gradient(circle at 50% 50%, rgba(246, 130, 31, 0.15) 0%, rgba(15, 23, 42, 0.8) 100%);
			backdrop-filter: blur(12px);
			z-index: -1;
			animation: blurOverlayAppear 1.5s ease-out forwards;
		}

		.page-wrapper {
			position: fixed;
			top: 0;
			left: 0;
			width: 100%;
			height: 100%;
			display: flex;
			justify-content: center;
			align-items: center;
			padding: 20px;
		}

		.card-container {
			background: rgba(30, 41, 59, 0.85);
			backdrop-filter: blur(20px);
			padding: 48px 40px;
			border-radius: 24px;
			box-shadow: 0 20px 60px rgba(0, 0, 0, 0.4), 0 0 0 1px rgba(255, 255, 255, 0.1) inset;
			width: 100%;
			max-width: 440px;
			animation: containerAppear 0.8s ease-out;
			position: relative;
			overflow: hidden;
			text-align: center;
		}

		.card-container::before {
			content: '';
			position: absolute;
			top: 0;
			left: 0;
			right: 0;
			height: 4px;
			background: linear-gradient(90deg, #faab41 0%, #f6821f 50%, #faab41 100%);
			background-size: 200% 100%;
			animation: gradientShift 3s ease infinite;
		}

		.page-header {
			margin-bottom: 32px;
		}

		.page-icon {
			width: 68px;
			height: 68px;
			margin: 0 auto 20px;
			background: linear-gradient(135deg, #faab41 0%, #f6821f 100%);
			border-radius: 20px;
			display: flex;
			align-items: center;
			justify-content: center;
			box-shadow: 0 10px 30px rgba(246, 130, 31, 0.35);
		}

		.page-icon svg {
			width: 34px;
			height: 34px;
			fill: white;
		}

		.page-title {
			font-size: 28px;
			font-weight: 700;
			color: #ffffff;
			margin: 0 0 8px;
			letter-spacing: -0.5px;
		}

		.page-subtitle {
			font-size: 14px;
			color: #94a3b8;
		}

		.page-form {
			display: flex;
			flex-direction: column;
			gap: 20px;
		}

		.form-group {
			position: relative;
			text-align: left;
		}

		.input-wrapper {
			position: relative;
		}

		.form-group input {
			width: 100%;
			padding: 16px 16px 16px 48px;
			border: 2px solid #334155;
			border-radius: 12px;
			font-size: 16px;
			color: #f8fafc;
			background-color: #0f172a;
			transition: all 0.3s ease;
		}

		.form-group input:focus {
			outline: none;
			border-color: #f6821f;
			box-shadow: 0 0 0 4px rgba(246, 130, 31, 0.15);
		}

		.input-icon {
			position: absolute;
			left: 16px;
			top: 50%;
			transform: translateY(-50%);
			width: 20px;
			height: 20px;
			fill: #64748b;
			pointer-events: none;
		}

		.btn {
			padding: 16px 20px;
			border: none;
			border-radius: 12px;
			font-size: 16px;
			font-weight: 600;
			cursor: pointer;
			transition: all 0.3s ease;
			letter-spacing: 0.5px;
		}

		.btn-primary {
			background: linear-gradient(135deg, #faab41 0%, #f6821f 100%);
			color: #ffffff;
			box-shadow: 0 4px 15px rgba(246, 130, 31, 0.35);
		}

		.btn-primary:hover {
			transform: translateY(-2px);
			box-shadow: 0 6px 20px rgba(246, 130, 31, 0.45);
		}

		.btn-primary:active {
			transform: translateY(0);
		}

		.error-msg {
			color: #ef4444;
			font-size: 14px;
			margin-top: 12px;
			display: none;
		}

		.footer-hint {
			margin-top: 32px;
			font-size: 13px;
			color: #64748b;
		}

		.footer-hint a {
			color: #f6821f;
			text-decoration: none;
			font-weight: 500;
		}
	</style>
</head>
<body>
	<div id="blur-overlay"></div>
	<div class="page-wrapper">
		<div class="card-container">
			<div class="page-header">
				<div class="page-icon">
					<svg viewBox="0 0 24 24">
						<path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>
					</svg>
				</div>
				<h1 class="page-title">Admin Login</h1>
				<p class="page-subtitle">Enter your password to access the dashboard</p>
			</div>

			<form class="page-form" id="loginForm" method="POST" action="/login">
				<div class="form-group">
					<div class="input-wrapper">
						<svg class="input-icon" viewBox="0 0 24 24">
							<path d="M12.65 10C11.83 7.67 9.61 6 7 6c-3.31 0-6 2.69-6 6s2.69 6 6 6c2.61 0 4.83-1.67 5.65-4H17v4h4v-4h2v-4H12.65zM7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z"/>
						</svg>
						<input type="password" id="password" name="password" placeholder="Enter admin password" required autocomplete="current-password" autofocus>
					</div>
				</div>
				<button type="submit" class="btn btn-primary" id="submitBtn">Sign In</button>
				<p class="error-msg" id="errorMsg">Invalid password. Please try again.</p>
			</form>

			<div class="footer-hint">
				Powered by <a href="https://github.com/cmliu/edgetunnel" target="_blank" rel="noopener">EdgeTunnel</a>
			</div>
		</div>
	</div>

	<script>
		document.getElementById('loginForm').addEventListener('submit', async function(e) {
			e.preventDefault();
			const btn = document.getElementById('submitBtn');
			const error = document.getElementById('errorMsg');
			const pwd = document.getElementById('password').value;

			btn.disabled = true;
			btn.textContent = 'Signing in...';
			error.style.display = 'none';

			try {
				const res = await fetch('/login', {
					method: 'POST',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
					body: new URLSearchParams({ password: pwd })
				});

				const data = await res.json().catch(() => null);
				if (res.ok && data?.success) {
					window.location.href = '/admin';
				} else {
					error.style.display = 'block';
					btn.disabled = false;
					btn.textContent = 'Sign In';
				}
			} catch (err) {
				error.textContent = 'Network error. Please try again.';
				error.style.display = 'block';
				btn.disabled = false;
				btn.textContent = 'Sign In';
			}
		});
	</script>
</body>
</html>`;
}
