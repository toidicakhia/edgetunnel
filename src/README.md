# edgetunnel — Modular Architecture

> Refactored from single 6,199-line `_worker.js` (≈326 KB) into a maintainable, testable ES-module structure.
> Original preserved as `_worker.legacy.js` for reference. New entry: `src/worker.js` (see `wrangler.toml`).

## Directory Layout

```
src/
├── worker.js          # Cloudflare Worker entry — re-exports router (wrangler main)
├── router.js          # Main fetch router (previously export default { fetch } in _worker.js:17-529)
├── constants.js       # Immutable globals: Version, pagesStaticPage, tuning knobs
├── state.js           # Mutable globals: config_JSON, socks5Whitelist, dial counts (with setters)
│
├── handlers/
│   ├── xhttp.js       # XHTTP transport, HPACK padding, handleXHTTPRequest/UDP
│   ├── grpc.js        # gRPC transport (handleGRPCRequest)
│   └── ws.js          # WebSocket transport + Shadowsocks AEAD (handleWSRequest)
│
├── core/
│   ├── grain.js       # GrainTCP bundling: uplink/downlink queues, connectStreams
│   ├── tcp.js         # TCP forwarding: forwardTCP/UDP, concurrent dial, proxy fallback
│   ├── proxy.js       # SOCKS5 / HTTP / HTTPS chain proxy
│   ├── tls.js         # TlsClient (X25519, AES-GCM, ChaCha20-Poly1305, HKDF)
│   ├── turn.js        # TURN/STUN
│   ├── sstp.js        # SSTP / SoftEther
│   └── protocol.js    # VLESS / Trojan / Shadowsocks parsing + crypto
│
├── utils/
│   ├── helpers.js     # log, parseToArray, randomPath, replaceWildcard, toUint8Array, concatByteData
│   ├── crypto.js      # MD5MD5, sha224, base64SecretEncode/Decode, SS key derivation
│   ├── doh.js         # DoH queries, generateRandomIPs, fetchOptimalAPI/SubGenerator, TXT records
│   ├── network.js     # isIPHostname, stripIPv6Brackets, identifyISP, withTimeout, isSpeedTestSite
│   └── config.js      # readConfigJSON, getCloudflareUsage, subscription hot-patches (Clash/SingBox/Surge)
│
└── html/
    └── camouflage.js  # nginx / 1101 error page templates
```

## Key Refactor Decisions

1. **Global state isolation** — Mutable globals (`config_JSON`, `socks5Whitelist`, `debugLogging`, dial counts) moved to `src/state.js` with explicit setters. Router mutates via `set*()` instead of direct assignment, preserving ES-module live-binding semantics.
2. **Bug fixes** — Fixed 8 latent bugs from the original:
   - `calculateHPACKHuffmanByteLength`: `bytes` vs `byte`
   - `generateXHTTPPaddingString`: `charsetLen` vs `charsetLength`
   - `admin/getADDAPI`: `pendingValidateURL` → `pendingVerifyOptimalURL`
   - `responseContent` casing, `mergedOtherNodeArray` vs `mergedOtherNodes`, `transportPathParamValue` spaces, etc.
   - 30+ additional broken identifiers with spaces (e.g. `copy bundleresult`, `enable preload`, `dnsresponse context`) were normalized to camelCase.
3. **Circular dependencies minimized** — `grain` ↔ `tcp` ↔ `xhttp` cycles are limited to lazy function calls (not top-level execution), safe under ESM.
4. **Tooling** — Added `package.json` (type: module), `eslint.config.js`, `.prettierrc`, `.editorconfig`, and npm scripts (`dev`, `deploy`, `lint`, `format`, `check`).
5. **Backwards compatibility** — `_worker.js` is now a 10-line shim (`import worker from './src/worker.js'`) so existing Pages deployments keep working. `wrangler.toml` `main` updated to `src/worker.js`.

## Usage

```bash
npm install
npm run dev          # wrangler dev --local
npm run deploy       # wrangler deploy
npm run check        # node --check src/worker.js
npm run lint         # eslint src
npm run format       # prettier --write
```

## Import Rules

- `constants.js` and `state.js` are leaf modules (no imports from handlers/core).
- `utils/*` are leaves, may import `constants`/`state` but not handlers/core.
- `core/*` may import `utils` and `constants`/`state`, not handlers.
- `handlers/*` may import `core` and `utils`.
- `router.js` may import everything.
- `worker.js` only imports `router.js`.

This enforces a DAG and prevents future cycles.

## Testing

```bash
npm test            # node --test (add tests under test/*.test.js)
```

## Migration

- Original file: `_worker.legacy.js` (do not edit, for diff reference)
- New development: edit files under `src/`, run `npm run format && npm run lint`
- Deployment: `wrangler deploy` (uses `src/worker.js`) or push to GitHub for Pages (uses `_worker.js` shim)

## Future Work

- [ ] Extract `admin` and `subscription` logic from `router.js` into `handlers/admin.js` and `handlers/subscription.js`
- [ ] Add TypeScript (`tsconfig.json`) and `wrangler types`
- [ ] Add Vitest + Miniflare integration tests for WS/XHTTP/gRPC
- [ ] Split `utils/config.js` (1,200+ lines) into `subscription/clash.js`, `singbox.js`, `surge.js`
