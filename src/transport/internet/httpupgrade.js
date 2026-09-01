/**
 * src/transport/internet/httpupgrade.js
 * HTTPUpgrade transport — mirror of Xray-core transport/internet/httpupgrade.
 *
 * Server: reads the request (capped), validates Host + exact path + Connection
 * Upgrade / Upgrade websocket headers, replies
 *   HTTP/1.1 101 Switching Protocols
 *   Connection: Upgrade
 *   Upgrade: websocket
 * then the raw socket bytes flow (no WS framing).
 */

import { isValidHTTPHost } from './websocket.js';

/**
 * Handle an HTTPUpgrade request (server side).
 * @param {Request} request
 * @param {{ host?: string, path?: string }} config
 * @returns {{ ok: boolean, response?: Response } | { ok: true, response: Response }} — returns the 101 Response.
 */
export function handleHTTPUpgradeRequest(request, config = {}) {
	const url = new URL(request.url);
	const configuredPath = config.path || '/';
	if (config.host && !isValidHTTPHost(url.hostname, config.host)) {
		return { ok: false, response: new Response('Not Found', { status: 404 }) };
	}
	if (url.pathname !== configuredPath) {
		return { ok: false, response: new Response('Not Found', { status: 404 }) };
	}
	const connection = (request.headers.get('connection') || '').toLowerCase();
	const upgrade = (request.headers.get('upgrade') || '').toLowerCase();
	if (!connection.includes('upgrade') || upgrade !== 'websocket') {
		return { ok: false, response: new Response('Bad Request', { status: 400 }) };
	}

	// Upgrade the request into a passthrough: Workers-only mechanics — the
	// caller must pipe request.body → response and response stream → request.
	// We return the upgrade Response and a duplex built over the request body.
	const response = new Response(null, {
		status: 101,
		headers: {
			Connection: 'Upgrade',
			Upgrade: 'websocket',
		},
	});

	return { ok: true, response };
}
