/**
 * src/html/login.js
 * Modern Login Page for EdgeTunnel
 */

export function loginPage() {
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>EdgeTunnel - Login</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',system-ui,sans-serif;background:#0b0e14;color:#f1f5f9;height:100vh;overflow:hidden;display:grid;place-items:center}
body::before{content:'';position:fixed;inset:0;z-index:0;
  background:radial-gradient(ellipse 70% 50% at 30% 20%,rgba(246,130,31,.1),transparent 60%),
             radial-gradient(ellipse 50% 40% at 80% 80%,rgba(59,130,246,.06),transparent 60%)}

@keyframes fadeUp{from{opacity:0;transform:translateY(24px)}to{opacity:1;transform:none}}
@keyframes glow{0%,100%{box-shadow:0 0 20px rgba(246,130,31,.2)}50%{box-shadow:0 0 35px rgba(246,130,31,.35)}}
@keyframes gradientSlide{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}

.card{position:relative;z-index:1;background:rgba(17,22,33,.85);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);
  border:1px solid rgba(255,255,255,.07);border-radius:20px;padding:44px 36px 36px;width:100%;max-width:400px;
  box-shadow:0 24px 64px rgba(0,0,0,.4);animation:fadeUp .5s cubic-bezier(.4,0,.2,1);text-align:center}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;border-radius:20px 20px 0 0;
  background:linear-gradient(90deg,#f6821f,#ff9436,#f6821f);background-size:200% 100%;animation:gradientSlide 3s ease infinite}

.logo{width:64px;height:64px;margin:0 auto 24px;border-radius:16px;
  background:linear-gradient(135deg,#f6821f,#e05a00);display:grid;place-items:center;
  box-shadow:0 8px 24px rgba(246,130,31,.3);animation:glow 3s ease-in-out infinite}
.logo svg{width:32px;height:32px;fill:#fff}

h1{font-size:1.5rem;font-weight:800;letter-spacing:-.03em;margin-bottom:6px}
.sub{font-size:.85rem;color:#94a3b8;margin-bottom:32px}

.field{position:relative;text-align:left;margin-bottom:16px}
.field input{width:100%;padding:14px 14px 14px 44px;background:#0b0e14;border:1.5px solid rgba(255,255,255,.08);
  border-radius:10px;font-size:.92rem;color:#f1f5f9;font-family:inherit;transition:all .2s cubic-bezier(.4,0,.2,1)}
.field input:focus{outline:none;border-color:#f6821f;box-shadow:0 0 0 3px rgba(246,130,31,.12)}
.field input::placeholder{color:#475569}
.field .ico{position:absolute;left:14px;top:50%;transform:translateY(-50%);width:18px;height:18px;fill:#475569;pointer-events:none;transition:fill .2s}
.field input:focus~.ico{fill:#f6821f}

.btn{width:100%;padding:14px;border:none;border-radius:10px;font-size:.92rem;font-weight:700;font-family:inherit;
  cursor:pointer;transition:all .2s cubic-bezier(.4,0,.2,1);letter-spacing:.01em;
  background:linear-gradient(135deg,#f6821f,#d96f00);color:#fff;box-shadow:0 4px 16px rgba(246,130,31,.3)}
.btn:hover{box-shadow:0 6px 24px rgba(246,130,31,.45);transform:translateY(-1px)}
.btn:active{transform:translateY(0)}
.btn:disabled{opacity:.6;cursor:not-allowed;transform:none}

.error{color:#ef4444;font-size:.82rem;margin-top:14px;display:none}

.footer{margin-top:28px;font-size:.75rem;color:#475569}
.footer a{color:#f6821f;text-decoration:none;font-weight:600}

@media(max-width:440px){.card{margin:1rem;padding:32px 24px 28px;border-radius:16px}}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <svg viewBox="0 0 24 24"><path d="M13 3L4 14h7l-2 7 9-11h-7l2-7z"/></svg>
  </div>
  <h1>Welcome back</h1>
  <p class="sub">Enter your password to access the dashboard</p>

  <form id="loginForm" method="POST" action="/login">
    <div class="field">
      <input type="password" id="password" name="password" placeholder="Admin password" required autocomplete="current-password" autofocus>
      <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
      </svg>
    </div>
    <button type="submit" class="btn" id="submitBtn">Sign In</button>
    <p class="error" id="error"></p>
  </form>

  <div class="footer">Powered by <a href="https://github.com/cmliu/edgetunnel" target="_blank" rel="noopener">EdgeTunnel</a></div>
</div>

<script>
document.getElementById('loginForm').addEventListener('submit',async function(e){
  e.preventDefault();
  const btn=document.getElementById('submitBtn');
  const err=document.getElementById('error');
  const pwd=document.getElementById('password').value;

  btn.disabled=true;btn.textContent='Signing in...';err.style.display='none';

  try{
    const r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({password:pwd})});
    const d=await r.json().catch(()=>null);
    if(r.ok&&d?.success){window.location.href='/admin'}
    else{err.textContent='Invalid password. Try again.';err.style.display='block';btn.disabled=false;btn.textContent='Sign In'}
  }catch(ex){err.textContent='Network error.';err.style.display='block';btn.disabled=false;btn.textContent='Sign In'}
});
</script>
</body>
</html>`;
}
