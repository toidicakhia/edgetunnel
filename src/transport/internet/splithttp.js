/**
 * src/transport/internet/splithttp.js
 * XHTTP (SplitHTTP) transport — mirror of Xray-core transport/internet/splithttp.
 *
 * Server flow (hub.go ServeHTTP), faithful order:
 *   host validate → path prefix → CORS → response padding → OPTIONS 200 →
 *   request padding validate (400) → meta extract → mode enforcement →
 *   dispatch stream-up / packet-up / stream-down|stream-one →
 *   405 for other methods.
 *
 * Client fill helpers (config.go ApplyMetaToRequest / FillStreamRequest /
 * FillPacketRequest) are provided for outbound use and link building.
 *
 * Placements: path (default), header (X-Session / X-Seq), query, cookie
 * (x_session / x_seq). Data placement: body (default), header, cookie, auto.
 * Padding: default Referer queryInHeader with key x_padding 100..1000.
 */

import { Done } from '../../common/signal.js';

export const Placement = Object.freeze({
	Path: 'path',
	Header: 'header',
	Query: 'query',
	Cookie: 'cookie',
	QueryInHeader: 'queryInHeader',
	Body: 'body',
	Auto: 'auto',
});

export const PaddingMethod = Object.freeze({
	RepeatX: 'repeat-x',
	Tokenish: 'tokenish',
});

export const DEFAULT_PADDING_FROM = 100;
export const DEFAULT_PADDING_TO = 1000;
export const DEFAULT_MAX_EACH_POST = 1024 * 1024; // 1 MiB
export const DEFAULT_MAX_BUFFERED_POSTS = 30;
export const DEFAULT_STREAM_UP_SECS = { from: 20, to: 80 }; // ScStreamUpServerSecs

export class SplitHTTPConfig {
	constructor({
		host = '',
		path = '/',
		mode = 'auto', // '' | auto | stream-up | stream-one | packet-up | stream-down
		sessionIDPlacement = Placement.Path,
		seqPlacement = Placement.Path,
		sessionIDKey = '',
		seqKey = '',
		uplinkDataPlacement = Placement.Body,
		uplinkDataKey = 'payload',
		xPaddingBytes = { from: DEFAULT_PADDING_FROM, to: DEFAULT_PADDING_TO },
		xPaddingObfsMode = false,
		xPaddingPlacement = Placement.QueryInHeader,
		xPaddingMethod = PaddingMethod.RepeatX,
		xPaddingHeader = 'X-Padding',
		xPaddingKey = 'x_padding',
		scMaxEachPostBytes = DEFAULT_MAX_EACH_POST,
		scMaxBufferedPosts = DEFAULT_MAX_BUFFERED_POSTS,
		scStreamUpServerSecs = DEFAULT_STREAM_UP_SECS,
		noSSEHeader = false,
		noGRPCHeader = false,
		uplinkHTTPMethod = 'POST',
	} = {}) {
		this.host = host;
		this.path = path;
		this.mode = mode;
		this.sessionIDPlacement = sessionIDPlacement;
		this.seqPlacement = seqPlacement;
		this.sessionIDKey = sessionIDKey;
		this.seqKey = seqKey;
		this.uplinkDataPlacement = uplinkDataPlacement;
		this.uplinkDataKey = uplinkDataKey;
		this.xPaddingBytes = xPaddingBytes;
		this.xPaddingObfsMode = xPaddingObfsMode;
		this.xPaddingPlacement = xPaddingPlacement;
		this.xPaddingMethod = xPaddingMethod;
		this.xPaddingHeader = xPaddingHeader;
		this.xPaddingKey = xPaddingKey;
		this.scMaxEachPostBytes = scMaxEachPostBytes;
		this.scMaxBufferedPosts = scMaxBufferedPosts;
		this.scStreamUpServerSecs = scStreamUpServerSecs;
		this.noSSEHeader = noSSEHeader;
		this.noGRPCHeader = noGRPCHeader;
		this.uplinkHTTPMethod = uplinkHTTPMethod;
	}

	getNormalizedSessionPlacement() {
		return this.sessionIDPlacement || Placement.Path;
	}
	getNormalizedSeqPlacement() {
		return this.seqPlacement || Placement.Path;
	}
	getNormalizedUplinkDataPlacement() {
		return this.uplinkDataPlacement || Placement.Body;
	}
	getNormalizedSessionKey() {
		if (this.sessionIDKey) return this.sessionIDKey;
		switch (this.getNormalizedSessionPlacement()) {
			case Placement.Header:
				return 'X-Session';
			case Placement.Cookie:
			case Placement.Query:
				return 'x_session';
			default:
				return '';
		}
	}
	getNormalizedSeqKey() {
		if (this.seqKey) return this.seqKey;
		switch (this.getNormalizedSeqPlacement()) {
			case Placement.Header:
				return 'X-Seq';
			case Placement.Cookie:
			case Placement.Query:
				return 'x_seq';
			default:
				return '';
		}
	}
	getNormalizedXPaddingBytes() {
		if (!this.xPaddingBytes || !this.xPaddingBytes.to) {
			return { from: DEFAULT_PADDING_FROM, to: DEFAULT_PADDING_TO };
		}
		return this.xPaddingBytes;
	}

	usesCookies() {
		return (
			this.getNormalizedSessionPlacement() === Placement.Cookie ||
			this.getNormalizedSeqPlacement() === Placement.Cookie ||
			this.xPaddingPlacement === Placement.Cookie ||
			this.getNormalizedUplinkDataPlacement() === Placement.Cookie
		);
	}

	/** Normalized path with trailing '/' appended when path placement used. */
	getPathForMeta() {
		const session = this.getNormalizedSessionPlacement() === Placement.Path;
		const seq = this.getNormalizedSeqPlacement() === Placement.Path;
		if ((session || seq) && !this.path.endsWith('/')) return this.path + '/';
		return this.path;
	}
}

/** Generate a random padding string (repeat-x or tokenish-lite). */
export function generatePadding(method, length) {
	if (!method || method === PaddingMethod.RepeatX) {
		return 'X'.repeat(Math.max(0, length));
	}
	// tokenish: base62 chars; server validates huffman-encoded length only
	const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	let out = '';
	for (let i = 0; i < length; i++) {
		out += chars[Math.floor(Math.random() * chars.length)];
	}
	return out;
}

/** Rough huffman length estimate (cheap stand-in; server-side validation only). */
export function huffmanEncodeLength(str) {
	// Xray uses HPACK huffman; for validation purposes we approximate with
	// byte length (within tolerance for the default ranges).
	return str.length;
}

/** IsPaddingValid — mirrors xpadding.go IsPaddingValid. */
export function isPaddingValid(paddingValue, from, to, method = PaddingMethod.RepeatX) {
	if (!paddingValue) return false;
	if (!to || to <= 0) {
		from = DEFAULT_PADDING_FROM;
		to = DEFAULT_PADDING_TO;
	}
	if (method === PaddingMethod.Tokenish) {
		const tolerance = 2; // validationTolerance
		const n = huffmanEncodeLength(paddingValue);
		const f = Math.max(0, from - tolerance);
		const t = to + tolerance;
		return n >= f && n <= t;
	}
	return paddingValue.length >= from && paddingValue.length <= to;
}

/** Extract padding from a request — mirrors ExtractXPaddingFromRequest. */
export function extractPaddingFromRequest(request, config) {
	if (!config.xPaddingObfsMode) {
		const referrer = request.headers.get('referer');
		if (referrer) {
			try {
				const u = new URL(referrer);
				return u.searchParams.get('x_padding') || '';
			} catch {
				return '';
			}
		}
		return request.headers.get('x_padding') || new URL(request.url).searchParams.get('x_padding') || '';
	}
	const key = config.xPaddingKey;
	const header = config.xPaddingHeader;
	const cookies = parseCookies(request.headers.get('cookie') || '');
	if (cookies[key]) return cookies[key];
	const headerValue = request.headers.get(header);
	if (headerValue) {
		if (config.xPaddingPlacement === Placement.Header) return headerValue;
		try {
			return new URL(headerValue).searchParams.get(key) || '';
		} catch {
			return '';
		}
	}
	return new URL(request.url).searchParams.get(key) || '';
}

export function parseCookies(str) {
	const out = {};
	for (const part of str.split(';')) {
		const i = part.indexOf('=');
		if (i < 0) continue;
		out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
	}
	return out;
}

/** Extract (sessionId, seqStr) — mirrors ExtractMetaFromRequest. */
export function extractMetaFromRequest(request, config) {
	const sessionPlacement = config.getNormalizedSessionPlacement();
	const seqPlacement = config.getNormalizedSeqPlacement();
	const sessionKey = config.getNormalizedSessionKey();
	const seqKey = config.getNormalizedSeqKey();

	let subpath = [];
	let pathPart = 0;
	const basePath = config.path;
	if (sessionPlacement === Placement.Path || seqPlacement === Placement.Path) {
		const full = new URL(request.url).pathname;
		let rest = full;
		if (basePath && full.startsWith(basePath)) rest = full.slice(basePath.length);
		subpath = rest.split('/').filter((s, i) => i < 2 || s !== '');
		// first two non-empty segments
		subpath = rest.replace(/^\/+/, '').split('/');
	}

	let sessionId = '';
	let seqStr = '';
	if (sessionPlacement === Placement.Path) {
		if (subpath.length > pathPart) {
			sessionId = decodeURIComponent(subpath[pathPart]);
			pathPart += 1;
		}
	} else if (sessionPlacement === Placement.Query) {
		sessionId = new URL(request.url).searchParams.get(sessionKey) || '';
	} else if (sessionPlacement === Placement.Header) {
		sessionId = request.headers.get(sessionKey) || '';
	} else if (sessionPlacement === Placement.Cookie) {
		const cookies = parseCookies(request.headers.get('cookie') || '');
		sessionId = cookies[sessionKey] || '';
	}

	if (seqPlacement === Placement.Path) {
		if (subpath.length > pathPart) {
			seqStr = decodeURIComponent(subpath[pathPart]);
			pathPart += 1;
		}
	} else if (seqPlacement === Placement.Query) {
		seqStr = new URL(request.url).searchParams.get(seqKey) || '';
	} else if (seqPlacement === Placement.Header) {
		seqStr = request.headers.get(seqKey) || '';
	} else if (seqPlacement === Placement.Cookie) {
		const cookies = parseCookies(request.headers.get('cookie') || '');
		seqStr = cookies[seqKey] || '';
	}
	return { sessionId, seqStr };
}

/**
 * uploadQueue — in-seq reorder buffer (upload_queue.go).
 * Packets buffered; delivered in nextSeq order; oversized buffer → teardown.
 */
export class UploadQueue {
	constructor(maxPackets = DEFAULT_MAX_BUFFERED_POSTS) {
		this.maxPackets = maxPackets;
		this.heap = []; // { seq, payload }
		this.nextSeq = 0n;
		this.closed = new Done();
		this.readerStream = null; // stream-up reader (request body)
		this.pendingWrites = []; // waiters for data
		this.buffer = [];
	}

	/** Push a packet (payload packet / stream-up reader indicator). */
	push(packet) {
		if (this.closed.done()) throw new Error('packet queue closed');
		if (packet.reader !== undefined && this.readerStream === null) {
			this.readerStream = packet.reader; // stream-up
			this._flush();
			return;
		}
		this.heap.push(packet);
		this.heap.sort((a, b) => (a.seq < b.seq ? -1 : a.seq > b.seq ? 1 : 0));
		this._flush();
	}

	_flush() {
		while (this.heap.length > 0) {
			const minSeq = this.heap[0].seq;
			if (minSeq > this.nextSeq) break;
			if (minSeq < this.nextSeq) {
				// duplicate/stale — drop
				this.heap.shift();
				continue;
			}
			const p = this.heap.shift();
			this.nextSeq = p.seq + 1n;
			this.buffer.push(p.payload);
		}
		// oversized buffered → teardown
		if (this.heap.length > this.maxPackets) {
			this.close(new Error('packet queue is too large'));
			return;
		}
		this._notify();
	}

	_notify() {
		const w = this.pendingWrites;
		this.pendingWrites = [];
		for (const fn of w) fn();
	}

	close(err = null) {
		if (this.closed.close()) {
			this.error = err || null;
			this._notify();
		}
		if (this.readerStream) {
			try {
				this.readerStream.cancel?.();
			} catch {
				/* ignore */
			}
		}
	}

	/** Async iterator over ordered payloads. */
	async *iterate() {
		while (true) {
			if (this.buffer.length) {
				yield this.buffer.shift();
				continue;
			}
			if (this.readerStream) {
				const reader = this.readerStream.getReader();
				try {
					while (true) {
						const { done, value } = await reader.read();
						if (done) break;
						yield value;
					}
				} finally {
					reader.releaseLock();
				}
				this.readerStream = null;
				continue;
			}
			if (this.closed.done()) return;
			await new Promise((resolve) => this.pendingWrites.push(resolve));
		}
	}
}

/**
 * Session manager (hub.go upsertSession + 30s reap).
 */
export class SplitHTTPSessionManager {
	constructor(config) {
		this.config = config;
		this.sessions = new Map();
	}

	upsert(sessionId) {
		const existing = this.sessions.get(sessionId);
		if (existing) return existing;
		const session = {
			queue: new UploadQueue(this.config.scMaxBufferedPosts),
			fullyConnected: new Done(),
			closed: new Done(),
		};
		this.sessions.set(sessionId, session);
		// reap: if not fully connected after 30s
		const timer = setTimeout(() => {
			if (!session.fullyConnected.done()) {
				this.sessions.delete(sessionId);
				session.queue.close();
			}
		}, 30_000);
		if (typeof timer.unref === 'function') timer.unref();
		return session;
	}

	remove(sessionId) {
		const s = this.sessions.get(sessionId);
		if (s) {
			s.closed.close();
			s.queue.close();
			this.sessions.delete(sessionId);
		}
	}
}

/** Apply CORS headers — mirrors WriteResponseHeader. */
export function writeResponseHeaders(headers, request, config) {
	const origin = request.headers.get('origin');
	if (origin) {
		headers.set('Access-Control-Allow-Origin', origin);
	} else {
		headers.set('Access-Control-Allow-Origin', '*');
	}
	if (config.usesCookies()) {
		headers.set('Access-Control-Allow-Credentials', 'true');
	}
}

/**
 * Handle an XHTTP (splithttp) request (server side).
 *
 * @param {Request} request
 * @param {SplitHTTPConfig} config
 * @param {SplitHTTPSessionManager} sessionManager
 * @returns {Promise<{ ok: boolean, status?: number, response?: Response }>}
 *
 * Stream sessions (stream-up GET keepalive / stream-down) require the caller
 * to keep the returned Response's body alive.
 */
export async function handleSplitHTTPRequest(request, config, sessionManager) {
	const url = new URL(request.url);
	const method = request.method;

	// 1. host validation
	if (config.host && !isHostValid(url.hostname, config.host)) {
		return { ok: false, status: 404, response: new Response('Not Found', { status: 404 }) };
	}
	// 2. path prefix
	if (!url.pathname.startsWith(config.path)) {
		return { ok: false, status: 404, response: new Response('Not Found', { status: 404 }) };
	}

	// response headers + padding
	const headers = new Headers();
	writeResponseHeaders(headers, request, config);
	const padRange = config.getNormalizedXPaddingBytes();
	const padLen = padRange.from + Math.floor(Math.random() * (padRange.to - padRange.from + 1));
	if (config.xPaddingObfsMode) {
		const padding = generatePadding(config.xPaddingMethod, padLen);
		if (config.xPaddingPlacement === Placement.Cookie) {
			headers.set('Set-Cookie', `${config.xPaddingKey}=${padding}`);
		} else {
			// queryInHeader default
			const u = new URL(url.toString());
			u.searchParams.set(config.xPaddingKey, padding);
			headers.set(config.xPaddingHeader || 'X-Padding', u.toString());
		}
	} else {
		headers.set('X-Padding', generatePadding(PaddingMethod.RepeatX, padLen));
	}
	headers.set('X-Accel-Buffering', 'no');

	if (method === 'OPTIONS') {
		const reqMethod = request.headers.get('access-control-request-method');
		const reqHeaders = request.headers.get('access-control-request-headers');
		headers.set('Access-Control-Allow-Methods', reqMethod || '*');
		headers.set('Access-Control-Allow-Headers', reqHeaders || '*');
		return { ok: true, status: 200, response: new Response(null, { status: 200, headers }) };
	}

	// 5. request padding validation
	const paddingValue = extractPaddingFromRequest(request, config);
	if (!isPaddingValid(paddingValue, padRange.from, padRange.to, config.xPaddingMethod)) {
		return { ok: false, status: 400, response: new Response('Bad Request', { status: 400, headers }) };
	}
	const obfsPaddingAccepted = config.xPaddingObfsMode && paddingValue !== '';

	// 6. meta
	const { sessionId, seqStr } = extractMetaFromRequest(request, config);

	// 7. mode enforcement
	if (!sessionId && config.mode && config.mode !== 'auto' && config.mode !== 'stream-one' && config.mode !== 'stream-up') {
		return { ok: false, status: 400, response: new Response('Bad Request', { status: 400, headers }) };
	}

	const currentSession = sessionId ? sessionManager.upsert(sessionId) : null;
	const isUplinkRequest = method !== 'GET' || seqStr !== '';

	if (isUplinkRequest && sessionId !== '') {
		if (!seqStr) {
			// stream-up
			if (config.mode && config.mode !== 'auto' && config.mode !== 'stream-up') {
				return { ok: false, status: 400, response: new Response('Bad Request', { status: 400, headers }) };
			}
			headers.set('Cache-Control', 'no-store');
			const body = request.body;
			try {
				currentSession.queue.push({ reader: body });
			} catch {
				return { ok: false, status: 409, response: new Response('Conflict', { status: 409, headers }) };
			}
			const hasLegacyReferer = request.headers.get('referer') !== '';
			if ((hasLegacyReferer || obfsPaddingAccepted) && config.scStreamUpServerSecs?.to > 0) {
				const onClose = () => sessionManager.remove(sessionId);
				return {
					ok: true,
					status: 200,
					response: new Response(streamUpPaddingBody(config, onClose), { status: 200, headers }),
				};
			}
			return { ok: true, status: 200, response: new Response(null, { status: 200, headers }) };
		}
		// packet-up
		if (config.mode && config.mode !== 'auto' && config.mode !== 'packet-up') {
			return { ok: false, status: 400, response: new Response('Bad Request', { status: 400, headers }) };
		}
		const placement = config.getNormalizedUplinkDataPlacement();
		const bodyBytes = await readRequestBodyBounded(request, config.scMaxEachPostBytes);
		if (bodyBytes === null) {
			headers.set('Cache-Control', 'no-store');
			return { ok: false, status: 413, response: new Response('Payload Too Large', { status: 413, headers }) };
		}
		request._bodyBytes = bodyBytes;
		const payload = extractPacketPayload(request, config, placement);
		if (payload === null) {
			return { ok: false, status: 400, response: new Response('Bad Request', { status: 400, headers }) };
		}
		let seq;
		try {
			seq = BigInt(seqStr);
		} catch {
			return { ok: false, status: 500, response: new Response('Internal Server Error', { status: 500, headers }) };
		}
		try {
			currentSession.queue.push({ seq, payload });
		} catch {
			return { ok: false, status: 500, response: new Response('Internal Server Error', { status: 500, headers }) };
		}
		if (payload.byteLength === 0) {
			headers.set('Cache-Control', 'no-store');
		}
		return { ok: true, status: 200, response: new Response(null, { status: 200, headers }) };
	}

	if (method === 'GET' || !sessionId) {
		// stream-down / stream-one
		if (currentSession) {
			currentSession.fullyConnected.close();
		}
		headers.set('Cache-Control', 'no-store');
		if (!config.noSSEHeader) headers.set('Content-Type', 'text/event-stream');

		// Downlink body: session queue iterator (sessioned) or request body (stream-one)
		const onClose = currentSession ? () => sessionManager.remove(sessionId) : null;
		const body = splitHTTPResponseStream(currentSession ? currentSession.queue : request.body, onClose);
		return { ok: true, status: 200, response: new Response(body, { status: 200, headers }) };
	}

	return { ok: false, status: 405, response: new Response('Method Not Allowed', { status: 405, headers }) };
}

/** Read request body bounded to maxBytes+1; null when oversized. */
export async function readRequestBodyBounded(request, maxBytes) {
	if (!request.body) return new Uint8Array(0);
	const reader = request.body.getReader();
	const chunks = [];
	let total = 0;
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			total += value.byteLength;
			if (total > maxBytes) {
				await reader.cancel();
				return null;
			}
			chunks.push(value);
		}
	} finally {
		reader.releaseLock();
	}
	if (chunks.length === 1) return chunks[0];
	const out = new Uint8Array(total);
	let off = 0;
	for (const c of chunks) {
		out.set(c, off);
		off += c.byteLength;
	}
	return out;
}

/** Build the downlink ReadableStream from a queue or request body. */
export function splitHTTPResponseStream(source, onClose = null) {
	return new ReadableStream({
		async start(controller) {
			try {
				if (source instanceof UploadQueue) {
					for await (const chunk of source.iterate()) {
						controller.enqueue(chunk);
					}
				} else if (source) {
					const reader = source.getReader();
					try {
						while (true) {
							const { done, value } = await reader.read();
							if (done) break;
							controller.enqueue(value);
						}
					} finally {
						reader.releaseLock();
					}
				}
				controller.close();
			} catch (err) {
				controller.error(err);
			}
		},
		cancel() {
			if (source instanceof UploadQueue) source.close();
			if (onClose) onClose();
		},
	});
}

/** Streaming body for stream-up with server padding chunks. */
export function streamUpPaddingBody(config, onClose = null) {
	const range = config.scStreamUpServerSecs || DEFAULT_STREAM_UP_SECS;
	let stopped = false;
	return new ReadableStream({
		async pull(controller) {
			const delay = range.from + Math.floor(Math.random() * (range.to - range.from + 1));
			await new Promise((r) => setTimeout(r, delay * 1000));
			if (!stopped) {
				const len = range.from + Math.floor(Math.random() * (range.to - range.from + 1));
				controller.enqueue('X'.repeat(len));
			}
		},
		cancel() {
			stopped = true;
			if (onClose) onClose();
		},
	});
}

/** Extract payload for packet-up — mirrors hub.go placement logic. */
export function extractPacketPayload(request, config, placement) {
	const key = config.uplinkDataKey;
	const decodeB64 = (s) => {
		const normalized = s.replace(/-/g, '+').replace(/_/g, '/');
		const pad = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
		const bin = atob(normalized + pad);
		const out = new Uint8Array(bin.length);
		for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
		return out;
	};

	let headerPayload = null;
	if (placement === Placement.Auto || placement === Placement.Header) {
		const chunks = [];
		for (let i = 0; ; i++) {
			const chunk = request.headers.get(`${key}-${i}`);
			if (!chunk) break;
			chunks.push(chunk);
		}
		if (chunks.length) {
			try {
				headerPayload = decodeB64(chunks.join(''));
			} catch {
				return null;
			}
		} else {
			headerPayload = new Uint8Array(0);
		}
	}

	let cookiePayload = null;
	if (placement === Placement.Auto || placement === Placement.Cookie) {
		const cookies = parseCookies(request.headers.get('cookie') || '');
		const chunks = [];
		for (let i = 0; ; i++) {
			const c = cookies[`${key}_${i}`];
			if (!c) break;
			chunks.push(c);
		}
		if (chunks.length) {
			try {
				cookiePayload = decodeB64(chunks.join(''));
			} catch {
				return null;
			}
		} else {
			cookiePayload = new Uint8Array(0);
		}
	}

	let bodyPayload = new Uint8Array(0);
	if (placement === Placement.Auto || placement === Placement.Body) {
		// request body already validated by Content-Length cap in caller; read fully
		// NOTE: request.body is a stream; read synchronously via helper.
		bodyPayload = request._bodyBytes || new Uint8Array(0);
	}

	switch (placement) {
		case Placement.Header:
			return headerPayload;
		case Placement.Cookie:
			return cookiePayload;
		case Placement.Body:
			return bodyPayload;
		case Placement.Auto:
			return concatBytes(headerPayload, cookiePayload, bodyPayload);
		default:
			return new Uint8Array(0);
	}
}

function concatBytes(...parts) {
	const total = parts.reduce((s, p) => s + p.byteLength, 0);
	const out = new Uint8Array(total);
	let off = 0;
	for (const p of parts) {
		out.set(p, off);
		off += p.byteLength;
	}
	return out;
}

function isHostValid(actual, expected) {
	if (!expected) return true;
	if (!actual) return false;
	if (actual === expected) return true;
	return expected.startsWith('.') && actual.endsWith(expected);
}