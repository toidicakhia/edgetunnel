/**
 * src/transport/internet/websocket.js
 * WebSocket transport — mirror of Xray-core transport/internet/websocket.
 *
 * Server side (hub.go):
 *   - validates Host (when configured) and EXACT path → 404 otherwise
 *   - early data: Sec-WebSocket-Protocol header value decoded as
 *     base64.RawURLEncoding with replacer '+'→'-', '/'→'_', '='→''
 *     becomes the FIRST bytes of the stream (drained before any WS message);
 *     the same header value is echoed back in the 101 response.
 *   - one app write = one binary frame; frames read sequentially.
 */

import { Done } from '../../common/signal.js';
import { randomPath } from '../../utils/helpers.js'; // path normalization reuse

/** Xray's replacer for early-data base64 (RawURLEncoding stdout variant). */
export function decodeWSEarlyDataRawURL(str) {
	const normalized = String(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
	try {
		// Uint8Array.fromBase64 may be unavailable in some runtimes; fallback to btoa path
		if (typeof Uint8Array.fromBase64 === 'function') {
			return Uint8Array.fromBase64(normalized, { alphabet: 'base64url' });
		}
	} catch {
		/* fall through */
	}
	const bin = atob(normalized);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

/**
 * Validate host against configured host (Xray internet.IsValidHTTPHost semantics:
 * exact match, or suffix match with leading '.').
 */
export function isValidHTTPHost(actual, expected) {
	if (!expected) return true;
	if (!actual) return false;
	if (actual === expected) return true;
	return expected.startsWith('.') && actual.endsWith(expected);
}

/**
 * Create a full-window duplex connection over a WebSocket.
 * @param {WebSocket} ws Cloudflare WebSocketPair server side
 * @param {{ initial?: Uint8Array, maxMessageBytes?: number }} opts
 * @returns {{ readable: ReadableStream, writable: WritableStream, close: () => void }}
 */
export function webSocketDuplex(ws, { initial = null, maxMessageBytes = 64 * 1024 } = {}) {
	let initialDone = false;
	const closeDone = new Done();

	// buffer for initial early data
	const initialBuffer = initial ? [initial] : [];

	const readable = new ReadableStream({
		start(controller) {
			ws.addEventListener('message', (event) => {
				let data;
				if (typeof event.data === 'string') {
					data = new TextEncoder().encode(event.data);
				} else if (event.data instanceof ArrayBuffer) {
					data = new Uint8Array(event.data);
				} else if (ArrayBuffer.isView(event.data)) {
					data = new Uint8Array(
						event.data.buffer,
						event.data.byteOffset,
						event.data.byteLength
					);
				} else {
					return;
				}
				if (data.byteLength > maxMessageBytes) {
					controller.error(new Error('websocket: message too large'));
					return;
				}
				controller.enqueue(data);
			});
			ws.addEventListener('close', () => controller.close());
			ws.addEventListener('error', (e) =>
				controller.error(e?.error || new Error('websocket error'))
			);
		},
		pull() {
			if (!initialDone && initialBuffer.length) {
				initialDone = true;
				return;
			}
		},
		cancel() {
			closeDone.close();
		},
	});

	const writable = new WritableStream({
		async write(chunk) {
			if (ws.readyState !== WebSocket.OPEN && ws.readyState !== WebSocket.CONNECTING) {
				throw new Error('websocket: not open');
			}
			const data = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
			// one app write = one binary frame
			const sent = ws.send(data);
			if (sent && typeof sent.then === 'function') await sent;
		},
		close() {
			try {
				ws.close();
			} catch {
				/* ignore */
			}
			closeDone.close();
		},
		abort() {
			try {
				ws.close();
			} catch {
				/* ignore */
			}
			closeDone.close();
		},
	});

	return {
		readable,
		writable,
		close() {
			try {
				ws.close();
			} catch {
				/* ignore */
			}
			closeDone.close();
		},
		closed: closeDone.wait(),
	};
}

/**
 * Handle a WebSocket upgrade request (Xray websocket hub semantics).
 * @param {Request} request
 * @param {{ host?: string, path?: string, earlyDataValidation?: (bytes: Uint8Array) => boolean }} config
 * @returns {{ ok: boolean, response?: Response, conn?: ReturnType<typeof webSocketDuplex> }}
 */
export function handleWebSocketRequest(request, config = {}) {
	const url = new URL(request.url);
	const configuredPath = config.path || '/';
	if (config.host && !isValidHTTPHost(url.hostname, config.host)) {
		return { ok: false, response: new Response('Not Found', { status: 404 }) };
	}
	// Xray: EXACT path match (server side)
	if (url.pathname !== configuredPath) {
		return { ok: false, response: new Response('Not Found', { status: 404 }) };
	}

	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
	let initial = null;
	const responseHeaders = {};
	if (earlyDataHeader) {
		let decoded = null;
		try {
			decoded = decodeWSEarlyDataRawURL(earlyDataHeader);
		} catch {
			decoded = null;
		}
		if (decoded && decoded.byteLength > 0) {
			// validate by upper layer (protocol header check)
			if (config.earlyDataValidation && !config.earlyDataValidation(decoded)) {
				decoded = null;
			}
		}
		if (decoded && decoded.byteLength > 0) {
			initial = decoded;
			responseHeaders['Sec-WebSocket-Protocol'] = earlyDataHeader;
		}
	}

	const pair = new WebSocketPair();
	const [client, server] = Object.values(pair);
	server.accept();

	const conn = webSocketDuplex(server, { initial });
	return {
		ok: true,
		response: new Response(null, {
			status: 101,
			headers: responseHeaders,
			webSocket: client,
		}),
		conn,
	};
}

/** Randomly generate a WS-compatible path (reuse helpers.randomPath). */
export { randomPath as generateWsPath };
