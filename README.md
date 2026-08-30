# 🚀 edgetunnel 2.1 — Modular

> **Refactored 2026-08-30**: Monolithic `_worker.js` (6,199 lines) split into `src/` ES modules. See [`src/README.md`](src/README.md) and [`ARCHITECTURE.md`](ARCHITECTURE.md). Original preserved as `_worker.legacy.js`; Pages shim remains `_worker.js` → `src/worker.js`. `wrangler.toml` `main` now `src/worker.js`.

![Admin Panel](./img.png)

[![Stars](https://img.shields.io/github/stars/cmliu/edgetunnel?style=flat-square&logo=github)](https://github.com/cmliu/edgetunnel/stargazers)
[![Forks](https://img.shields.io/github/forks/cmliu/edgetunnel?style=flat-square&logo=github)](https://github.com/cmliu/edgetunnel/network/members)
[![License](https://img.shields.io/github/license/cmliu/edgetunnel?style=flat-square)](https://github.com/cmliu/edgetunnel/blob/main/LICENSE)
[![YouTube](https://img.shields.io/badge/YouTube-Channel-red?style=flat-square&logo=youtube)](https://www.youtube.com/watch?v=LeT4jQUh8ok)
[![zread](https://img.shields.io/badge/Ask_Zread-_.svg?style=flat-square&color=00b0aa&labelColor=000000&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHZpZXdCb3g9IjAgMCAxNiAxNiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTQuOTYxNTYgMS42MDAxSDIuMjQxNTZDMS44ODgxIDEuNjAwMSAxLjYwMTU2IDEuODg2NjQgMS42MDE1NiAyLjI0MDFWNC45NjAxQzEuNjAxNTYgNS4zMTM1NiAxLjg4ODEgNS42MDAxIDIuMjQxNTYgNS42MDAxSDQuOTYxNTZDNS4zMTUwMiA1LjYwMDEgNS42MDE1NiA1LjMxMzU2IDUuNjAxNTYgNC45NjAxVjIuMjQwMUM1LjYwMTU2IDEuODg2NjQgNS4zMTUwMiAxLjYwMDEgNC45NjE1NiAxLjYwMDFaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik00Ljk2MTU2IDEwLjM5OTlIMi4yNDE1NkMxLjg4ODEgMTAuMzk5OSAxLjYwMTU2IDEwLjY4NjQgMS42MDE1NiAxMS4wMzk5VjEzLjc1OTlDMS42MDE1NiAxNC4xMTM0IDEuODg4MSAxNC4zOTk5IDIuMjQxNTYgMTQuMzk5OUg0Ljk2MTU2QzUuMzE1MDIgMTQuMzk5OSA1LjYwMTU2IDE0LjExMzQgNS42MDE1NiAxMy43NTk5VjExLjAzOTlDNS42MDE1NiAxMC42ODY0IDUuMzE1MDIgMTAuMzk5OSA0Ljk2MTU2IDEwLjM5OTlaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik0xMy43NTg0IDEuNjAwMUgxMS4wMzg0QzEwLjY4NSAxLjYwMDEgMTAuMzk4NCAxLjg4NjY0IDEwLjM5ODQgMi4yNDAxVjQuOTYwMUMxMC4zOTg0IDUuMzEzNTYgMTAuNjg1IDUuNjAwMSAxMS4wMzg0IDUuNjAwMUgxMy43NTg0QzE0LjExMTkgNS42MDAxIDE0LjM5ODQgNS4zMTM1NiAxNC4zOTg0IDQuOTYwMVYyLjI0MDFDMTQuMzk4NCAxLjg4NjY0IDE0LjExMTkgMS42MDAxIDEzLjc1ODQgMS42MDAxWiIgZmlsbD0iI2ZmZiIvPgo8cGF0aCBkPSJNNCAxMkwxMiA0TDQgMTJaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik00IDEyTDEyIDQiIHN0cm9rZT0iI2ZmZiIgc3Ryb2tlLXdpZHRoPSIxLjUiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIvPgo8L3N2Zz4K&logoColor=ffffff)](https://zread.ai/cmliu/edgetunnel)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/cmliu/edgetunnel)

---

## 📖 Project Overview

**edgetunnel** is an edge computing tunnel decryption solution built on the CF Workers/Pages platform. It efficiently handles network traffic with a powerful admin panel and flexible node configuration.

- 🖥️ **Demo Site**: [https://EDT-Pages.github.io/admin](https://EDT-Pages.github.io/admin)

### ✨ Core Features

- 🛡️ **Protocol Support**: Supports VLESS, Trojan, Shadowsocks and other mainstream protocols with deep encryption integration.
- 📊 **Admin Panel**: Built-in visual backend with real-time configuration, log viewing, and traffic statistics.
- 🛠️ **Flexible Deployment**: Fully supports CF Workers and CF Pages (GitHub / Upload).
- 🔄 **Subscription System**: Built-in auto subscription generation and obfuscation conversion, compatible with major clients (Clash, Sing-box, Surge, etc.).
- ⚡ **Performance**: Supports custom ProxyIP, SOCKS5/HTTP chain proxy, and optimal API for network optimization.
- 🌐 **Multi-Platform**: Fully compatible with Windows, Android, iOS, MacOS, and various router firmware.

---

## 💡 Quick Deployment
>[!TIP]
> 📖 **Detailed Tutorial**: [edgetunnel Deployment Guide](https://cmliussss.com/p/edt2/)

>[!WARNING]
> ⚠️ **Error 1101 Issue**: [Video Explanation](https://www.youtube.com/watch?v=r4uVTEJptdE)

### ⚙️ Workers Deployment

<details>
<summary><code><strong>「 Workers Deployment Text Tutorial 」</strong></code></summary>

1. Deploy CF Worker:
   - Create a new Worker in the CF Worker console.
   - Paste the content of [worker.js](https://github.com/cmliu/edgetunnel/blob/main/_worker.js) into the Worker editor.
   - In the `Settings` tab on the left, select `Variables` > `Add Variable`.
     Variable name: **ADMIN**, value: your admin password, then click `Save`.

2. Bind KV Namespace:
   - In the `Bindings` tab, select `Add Binding +` > `KV Namespace` > `Add Binding`, then select an existing namespace or create a new one.
   - Variable name: **KV**, then click `Add Binding`.

3. Bind Custom Domain to Workers:
   - In the `Triggers` tab of the Workers console, click `Add Custom Domain` below.
   - Enter your subdomain that has been transferred to CF DNS, e.g.: `vless.google.com`, then click `Add Custom Domain` and wait for the certificate to take effect.

4. Access Admin Panel:
   - Visit `https://vless.google.com/admin` and enter the admin password to login.

</details>

### 🛠 Pages Upload Deployment **Best Practice!!!** [Image Tutorial](https://cmliussss.com/p/edt2/)

<details>
<summary><code><strong>「 Pages Upload File Deployment Text Tutorial 」</strong></code></summary>

1. Deploy CF Pages:
   - Download [main.zip](https://github.com/cmliu/edgetunnel/archive/refs/heads/main.zip) and give us a Star!!!
   - In the CF Pages console, select `Upload assets`, name your project and click `Create Project`, then upload [main.zip](https://github.com/cmliu/edgetunnel/archive/refs/heads/main.zip) and click `Deploy`.
   - After deployment, click `Continue Processing Site`, then select `Settings` > `Environment Variables` > **Production** > `Add Variable`.
     Variable name: **ADMIN**, value: your admin password, then click `Save`.
   - Return to the `Deployments` tab, click `Create New Deployment` in the bottom right, re-upload [main.zip](https://github.com/cmliu/edgetunnel/archive/refs/heads/main.zip) and click `Save and Deploy`.

2. Bind KV Namespace:
   - In the `Settings` tab, select `Bindings` > `+ Add` > `KV Namespace`, then select an existing namespace or create a new one.
   - Variable name: **KV**, then click `Save` and retry deployment.

3. Bind CNAME Custom Domain to Pages: [Video Tutorial](https://www.youtube.com/watch?v=LeT4jQUh8ok&t=851s)
   - In the Pages console's `Custom Domains` tab, click `Set up a custom domain`.
   - Enter your custom subdomain (do not use your root domain), e.g.:
     If your assigned domain is `fuck.cloudns.biz`, enter `lizi.fuck.cloudns.biz` as the custom domain.
   - Follow CF's instructions to add the CNAME record `edgetunnel.pages.dev` for subdomain `lizi` at your DNS provider, then click `Activate Domain`.

4. Access Admin Panel:
   - Visit `https://lizi.fuck.cloudns.biz/admin` and enter the admin password to login.

</details>

### 🛠 Pages + GitHub Deployment

<details>
<summary><code><strong>「 Pages + GitHub Deployment Text Tutorial 」</strong></code></summary>

1. Deploy CF Pages:
   - Fork this project on GitHub and give us a Star!!!
   - In the CF Pages console, select `Connect to Git`, select the `edgetunnel` project and click `Begin Setup`.
   - On the `Configure Build and Deployment` page below, select `Environment Variables (Advanced)` and `Add Variable`.
     Variable name: **ADMIN**, value: your admin password, then click `Save and Deploy`.

2. Bind KV Namespace:
   - In the `Settings` tab, select `Bindings` > `+ Add` > `KV Namespace`, then select an existing namespace or create a new one.
   - Variable name: **KV**, then click `Save` and retry deployment.

3. Bind CNAME Custom Domain to Pages: [Video Tutorial](https://www.youtube.com/watch?v=LeT4jQUh8ok&t=851s)
   - In the Pages console's `Custom Domains` tab, click `Set up a custom domain`.
   - Enter your custom subdomain (do not use your root domain), e.g.:
     If your assigned domain is `fuck.cloudns.biz`, enter `lizi.fuck.cloudns.biz` as the custom domain.
   - Follow CF's instructions to add the CNAME record `edgetunnel.pages.dev` for subdomain `lizi` at your DNS provider, then click `Activate Domain`.

4. Access Admin Panel:
   - Visit `https://lizi.fuck.cloudns.biz/admin` and enter the admin password to login.

</details>

---

## 🔧 Environment Variables

| Variable | Required | Example | Description |
| :--- | :---: | :--- | :--- |
| **ADMIN** | ✅ | `123456` | Admin panel login password |
| **KEY** | ❌ | `CMLiussss` | Quick subscription path key, visit `/CMLiussss` to get nodes quickly |
| **UUID** | ❌ | `90cd4a77-141a-43c9-991b-08263cfe9c10` | Force fixed UUID, only supports **UUIDv4** format |
| **PROXYIP** | ❌ | `proxyip.cmliussss.net:443` | Global custom proxy IP |
| **URL** | ❌ | `https://cloudflare-error-page-3th.pages.dev` | Default homepage disguise address (can be a URL or `1101`) |
| **GO2SOCKS5** | ❌ | `blog.cmliussss.com`,`*.ip111.cn`,`*google.com` | Force SOCKS5 list (`*` for global, domains comma-separated) |
| **DEBUG** | ❌ | `1` or `true` | **Developer mode**, default **off** (console.log), set to `1` or `true` to **enable** |
| **OFF_LOG** | ❌ | `1` or `true` | Default **on** for KV logging, set to `1` or `true` to **disable** |
| **BEST_SUB** | ❌ | `1` or `true` | Default **off** as **optimal subscription generator**, set to `1` or `true` to **enable** |
| **PRELOAD_RACE_DIAL** | ❌ | `1` or `true` | Default **off** for **preload race dial**, set to `1` or `true` to **enable** |
| **TCP_CONCURRENT_DIAL** | ❌ | `2` | **TCP concurrent dial count**, default `2`; no longer auto-reduces for China Mobile networks |
| **PROXY_CONCURRENT_DIAL** | ❌ | `1` | **Proxy concurrent dial count**, default `1`; higher = faster connection but more frequent IP switching |

---

## 🔧 Advanced Tips

To modify the **TOKEN in subscription URL** and **UUID for node verification**, modify the variables:
1. Change `ADMIN` or `KEY` variable values to randomly modify the **TOKEN in subscription URL** and **UUID for node verification**.
2. Set the `UUID` variable to force fix the **TOKEN in subscription URL** and **UUID for node verification** (must be **UUIDv4** format).

This tool supports dynamic switching of proxy methods via **PATH**:

- Specify `PROXYIP` example:
   ```url
   /proxyip=proxyip.cmliussss.net
   /?proxyip=proxyip.cmliussss.net
   ```

- Specify `SOCKS5` example:
   ```url
   /socks5=user:password@127.0.0.1:1080
   /?socks5=user:password@127.0.0.1:1080
   /socks://dXNlcjpwYXNzd29yZA==@127.0.0.1:1080 (activates global SOCKS5 by default)
   /socks5://user:password@127.0.0.1:1080 (activates global SOCKS5 by default)
   ```

- Specify `HTTP Proxy` example:
   ```url
   /http=user:password@127.0.0.1:1080
   /http://user:password@127.0.0.1:8080 (activates global SOCKS5 by default)
   ```

- Specify `Trojan fallback` example (for self-built scenarios, Trojan inbound only; fallback service must use same password, non-WebSocket, non-TLS; UDP is forwarded to fallback with excellent performance):
   ```url
   /trojan=1.1.1.1:1234
   ```

---

## 🛠 Development (Modular Refactor)

> **New in 2026-08-30**: The 6,199-line `_worker.js` has been refactored into `src/` modules. See [`ARCHITECTURE.md`](ARCHITECTURE.md).

```bash
npm install
npm run dev          # wrangler dev --local  (uses src/worker.js)
npm run check        # node --check on all src files
npm run lint         # eslint
npm run format       # prettier
npm run deploy       # wrangler deploy --dry-run to verify
```

**Structure**: `src/worker.js` → `router.js` → `handlers/*` → `core/*` → `utils/*` → `constants.js`/`state.js`. Original preserved as `_worker.legacy.js`; `_worker.js` is a 10-line shim for Pages. See `src/README.md` for full layout and import rules.

---

## 💻 Client Compatibility

| Platform | Recommended Clients |
| :--- | :--- |
| **Windows** | [v2rayN](https://github.com/2dust/v2rayN/releases), [Hiddify](https://github.com/hiddify/hiddify-app/releases), [FlClash](https://github.com/chen08209/FlClash/releases), [mihomo-party](https://github.com/mihomo-party-org/clash-party/releases), [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev/releases), [Clashmi](https://github.com/KaringX/clashmi/releases), [FlyClash](https://github.com/GtxFury/FlyClash/releases), [Karing](https://github.com/KaringX/karing/releases), [Bettbox](https://github.com/appshubcc/Bettbox/releases) |
| **Android** | [v2rayNG](https://github.com/2dust/v2rayNG/releases), [ClashMetaForAndroid](https://github.com/MetaCubeX/ClashMetaForAndroid/releases/), [FlClash](https://github.com/chen08209/FlClash/releases), [Clashmi](https://github.com/KaringX/clashmi/releases), [Hiddify](https://github.com/hiddify/hiddify-app/releases), [NekoBox](https://github.com/MatsuriDayo/NekoBoxForAndroid/releases), [FlyClash](https://github.com/GtxFury/FlyClash/releases), [Karing](https://github.com/KaringX/karing/releases), [Bettbox](https://github.com/appshubcc/Bettbox/releases) |
| **iOS** | Surge, Shadowrocket, Stash, [Hiddify](https://github.com/hiddify/hiddify-app/releases), Loon, Egern, [Clashmi](https://clashmi.app/download), [Karing](https://karing.app/), Quantumult X |
| **macOS** | [FlClash](https://github.com/chen08209/FlClash/releases), [mihomo-party](https://github.com/mihomo-party-org/clash-party/releases), [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev/releases), Surge, [Clashmi](https://clashmi.app/download), [Karing](https://karing.app/), [FlyClash](https://github.com/GtxFury/FlyClash/releases) |
| **HarmonyOS** | [ClashBox](https://github.com/xiaobaigroup/ClashBox/releases) |

---

## ⭐ Project Popularity

![Stargazers over time](https://github.com/cmliu/cmliu/blob/main/star/edgetunnel.svg)

---

## 🙏 Special Thanks
### 💖 Sponsor Support - Cloud servers maintaining [subscription conversion service](https://sub.cmliussss.net/)
- [Yuusei Network](https://yuusei.io/)
- [VMRack](https://www.vmrack.net?ref_code=5Zk7eNhbgL7)

### 🛠 Open Source References
- [zizifn/edgetunnel](https://github.com/zizifn/edgetunnel)
- [3Kmfi6HP/EDtunnel](https://github.com/6Kmfi6HP/EDtunnel)
- [SHIJS1999/cloudflare-worker-vless-ip](https://github.com/SHIJS1999/cloudflare-worker-vless-ip)
- [Stanley-baby](https://github.com/Stanley-baby)
- [ACL4SSR](https://github.com/ACL4SSR/ACL4SSR/tree/master/Clash/config)
- [Stock God](https://t.me/CF_NAT/38889)
- [Workers/Pages Metrics](https://t.me/zhetengsha/3382)
- [Freeloader](https://t.me/bestcfipas)
- [Mingyu](https://github.com/ymyuuu/workers-vless)
- [ToiCF/CF-Workers-HTTPS](https://github.com/ToiCF/CF-Workers-HTTPS)
- [ToiCF/CF-Workers-TURN](https://github.com/ToiCF/CF-Workers-TURN)
- [ToiCF/CF-Workers-SoftEther](https://github.com/ToiCF/CF-Workers-SoftEther)
- [eooce](https://github.com/eooce/Cloudflare-proxy)
- [Sukka](https://ip.skk.moe/)
- [zhangtaile](https://github.com/cmliu/edgetunnel/pull/999)
- [1345695](https://github.com/1345695/edcloudwasm)
- [ToiCF/GrainTCP](https://github.com/ToiCF/GrainTCP)
- [xream](https://github.com/cmliu/edgetunnel/pull/1359)

---

## ⚠️ Disclaimer

1. This project ("edgetunnel") is intended solely for **educational, scientific research, and personal security testing** purposes.
2. Users must strictly comply with local laws and regulations when downloading or using this project's code.
3. The author **cmliu** is not responsible for any actions or consequences resulting from misuse of this project's code.
4. This project is not responsible for any direct or indirect damages caused by the use of the code.
5. It is recommended to delete all deployments of this project within 24 hours after testing.

---

**If you find this project helpful, please give us a Star 🌟 — it's the greatest encouragement!**
