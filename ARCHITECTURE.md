# Architecture — Before / After Refactor

## Before

```
_worker.js (6,199 lines, 326 KB)
├── global constants + mutable state (mixed)
├── export default { fetch } (500+ lines, all concerns in one function)
├── XHTTP helpers (450 lines)
├── gRPC helpers (310 lines)
├── WS + Shadowsocks (1,800 lines)
├── SOCKS5/HTTP/TLS/TURN/SSTP/DoH/config/subscription (3,000 lines)
└── HTML pages (120 lines)

Problems:
- Single file violates SRP, hard to navigate, no code ownership.
- Global mutable state scattered, implicit dependencies.
- No lint/format, no package.json, no tests, no CI.
- 8+ latent syntax bugs (spaces in identifiers, typos) masked by lack of `node --check`.
- Direct assignment to imported bindings would break under ESM.
- Circular import risks not visible.
```

## After

```
src/worker.js (10 lines) -> src/router.js (520 lines)
  ├── src/constants.js (23 lines, pure)
  ├── src/state.js (40 lines, explicit setters)
  ├── src/handlers/* (3 files, ~1,100 lines total)
  ├── src/core/* (7 files, ~1,800 lines total)
  ├── src/utils/* (5 files, ~1,200 lines total)
  └── src/html/* (1 file, 120 lines)

_worker.js (10 lines, shim) -> src/worker.js
_worker.legacy.js (original preserved)

Tooling:
- package.json (module, scripts)
- eslint.config.js, .prettierrc, .editorconfig
- wrangler.toml main = "src/worker.js"
```

## Dependency Graph (intended)

```
constants, state  (leaf)
      ↑
   utils/*        (leaf, may use constants/state)
      ↑
   core/*         (uses utils, constants/state)
      ↑
  handlers/*      (uses core, utils)
      ↑
   router.js      (uses all)
      ↑
   worker.js      (uses router)
```

Real graph after refactor still has 2 minor cycles (grain ↔ tcp, turn ↔ doh) but they are safe because they only call functions lazily, not at module evaluation time. Future work will break them by moving shared helpers (e.g. `getValidDataLength`, `isIPv4`) into `utils/network.js`.

## State Management

Before:
```js
let config_JSON, debugLogging = false;
...
debugLogging = env.DEBUG === '1' || debugLogging; // direct assignment, implicit global
```

After:
```js
// src/state.js
export let debugLogging = false;
export function setDebugLogging(v) { debugLogging = v; }

// src/router.js
import { debugLogging, setDebugLogging } from './state.js';
setDebugLogging(env.DEBUG === '1' || debugLogging); // explicit, live binding preserved
```

Reading `debugLogging` after `setDebugLogging` sees the new value via ESM live binding.

## Bug Fixes Applied

| File | Before | After |
|------|--------|-------|
| handlers/xhttp.js:40 | `const byte = ...; bytes.length` | `const bytes = ...` |
| handlers/xhttp.js:78 | `charsetLength` | `charsetLen` |
| router.js:132 | `new URL(pendingValidateURL)` | `pendingVerifyOptimalURL` |
| router.js:380 | `mergedOtherNodes` | `mergedOtherNodeArray` |
| router.js:443 | `transport path param value` | `transportPathParamValue` |
| router.js:528 | `responsecontent` | `responseContent` |
| grain.js | `copy bundleresult` | `copyBundleResult` |
| tcp.js | `enable preload` | `enablePreload` |
| ... | 30+ similar | camelCased |

All files now pass `node --check` and `eslint`.

## Deployment Paths

- **Workers (wrangler)**: `wrangler.toml` `main = "src/worker.js"` → `wrangler deploy`
- **Pages (git)**: `_worker.js` shim → `src/worker.js` → `router.js`
- **Legacy**: `_worker.legacy.js` remains for diff / rollback
