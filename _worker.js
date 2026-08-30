/**
 * _worker.js — Legacy shim for Cloudflare Pages
 *
 * The original 6,199-line monolithic worker has been refactored into
 * a modular structure under src/. This file is kept for backwards
 * compatibility with Pages deployments that expect _worker.js at the
 * repository root.
 *
 * - New modular entry: src/worker.js
 * - Original preserved: _worker.legacy.js
 * - All new development should target src/
 */

import worker from './src/worker.js';

export default worker;
