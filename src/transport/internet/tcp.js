/**
 * src/transport/internet/tcp.js
 * TCP dial primitives — Workers `connect()` (cloudflare:sockets) adapter,
 * mirroring the dialing mechanics used by edgetunnel and Xray's freedom outbound.
 *
 * The connector wraps request.fetcher.connect (Workers TCP API); a raw
 * connector is provided for non-request contexts.
 */

/** Build a TCP connector from the incoming Request's fetcher (Workers). */
export function createRequestTCPConnector(request) {
	const requestObj = /** @type {any} */ (request);
	const fetcher = requestObj?.fetcher;
	if (!fetcher || typeof fetcher.connect !== 'function') return null;
	return (options, init) =>
		init === undefined ? fetcher.connect(options) : fetcher.connect(options, init);
}

/**
 * Dial a TCP destination with a timeout.
 * @param {Function} connector (options, init) => Socket
 * @param {{ hostname: string, port: number }} dest
 * @param {{ timeoutMs?: number, allowHalfOpen?: boolean }} opts
 * @returns {Promise<Socket>} socket with opened/readable/writable/close
 */
export async function dialTCP(connector, dest, { timeoutMs = 9999, allowHalfOpen = false } = {}) {
	if (!connector) throw new Error('tcp: no connector available');
	const socket = connector({ hostname: dest.hostname, port: dest.port }, { allowHalfOpen });
	let timer = null;
	try {
		await Promise.race([
			socket.opened,
			new Promise((_, reject) => {
				timer = setTimeout(() => reject(new Error(`tcp: connect timeout ${dest.hostname}:${dest.port}`)), timeoutMs);
			}),
		]);
	} catch (err) {
		clearTimeout(timer);
		try {
			socket.close();
		} catch {
			/* ignore */
		}
		throw err;
	}
	clearTimeout(timer);
	return socket;
}

/**
 * Race multiple dials (TCP_CONCURRENT_DIAL behavior): first-opened wins,
 * losers closed.
 * @param {Array<() => Promise<Socket>>} dialers
 * @returns {Promise<Socket>}
 */
export async function raceDial(dialers) {
	if (dialers.length === 1) return dialers[0]();
	let settled = false;
	const losers = [];
	return await new Promise((resolve, reject) => {
		for (const dial of dialers) {
			dial()
				.then((socket) => {
					if (settled) {
						losers.push(socket);
						return;
					}
					settled = true;
					resolve(socket);
					for (const l of losers) {
						try {
							l.close();
						} catch {
							/* ignore */
						}
					}
				})
				.catch((err) => {
					if (!settled) {
						settled = true;
						reject(err);
					}
				});
		}
	});
}

/** Parse 'host:port' / '[v6]:port' into { hostname, port }. */
export function parseHostPort(str, defaultPort = 443) {
	const s = String(str).trim();
	if (s.startsWith('[')) {
		const end = s.indexOf(']');
		return { hostname: s.slice(1, end), port: Number(s.slice(end + 2) || defaultPort) };
	}
	const i = s.lastIndexOf(':');
	if (i > 0 && !s.includes(':', i + 1)) {
		return { hostname: s.slice(0, i), port: Number(s.slice(i + 1) || defaultPort) };
	}
	return { hostname: s, port: defaultPort };
}

/**
 * Bidirectional byte relay between a socket and a transport Link.
 * Resolves when the socket closes; rejects on pump errors; closes the socket
 * when the link ends.
 */
export function attachSocket(socket, link) {
	return new Promise((resolve, reject) => {
		let settled = false;
		const settle = (fn, arg) => {
			if (settled) return;
			settled = true;
			fn(arg);
		};
		const up = pumpStream(link.readable, socket.writable, {
			onClose: () => {
				try {
					socket.close();
				} catch {
					/* ignore */
				}
			},
			onError: (err) => settle(reject, err),
		});
		pumpStream(socket.readable, link.writable, {
			onError: (err) => {
				up.close();
				settle(reject, err);
			},
		});
		socket.closed
			.catch(() => {})
			.then(() => {
				up.close();
				link.writable.close().catch(() => {});
				settle(resolve, undefined);
			});
	});
}

/** Drain a socket readable into a writer sink (fire-and-forget loop). */
export function pumpStream(readable, writable, { onClose = null, onError = null } = {}) {
	const reader = readable.getReader();
	const writer = writable.getWriter();
	(async () => {
		try {
			while (true) {
				const { done, value } = await reader.read();
				if (done) break;
				await writer.write(value);
			}
			await writer.close();
		} catch (err) {
			try {
				await writer.abort(err);
			} catch {
				/* ignore */
			}
			onError?.(err);
		} finally {
			reader.releaseLock();
			onClose?.();
		}
	})();
	return {
		async close() {
			try {
				await writer.abort(new Error('pump closed'));
			} catch {
				/* ignore */
			}
			try {
				reader.cancel();
			} catch {
				/* ignore */
			}
		},
	};
}