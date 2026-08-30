/**
 * src/worker.js
 * Main Cloudflare Worker entry point — refactored modular version.
 *
 * This file replaces the monolithic _worker.js. It re-exports the router's
 * fetch handler while keeping the same external interface so existing
 * deployments (wrangler.toml, Pages) continue to work.
 *
 * Architecture:
 *   worker.js  -> router.js (main fetch routing)
 *             -> handlers/* (ws, xhttp, grpc, admin, subscription)
 *             -> core/* (tcp, grain, proxy, tls, turn, sstp, protocol)
 *             -> utils/* (crypto, doh, network, config, helpers)
 *             -> html/* (camouflage pages)
 *             -> constants.js / state.js (shared globals)
 */

import router from './router.js';

export default router;

// Optional: re-export for programmatic usage / testing
export { router };
