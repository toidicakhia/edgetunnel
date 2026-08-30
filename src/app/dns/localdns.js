/**
 * src/app/dns/localdns.js
 * Local DNS client — mirror of Xray-core app/dns (localdns).
 * Wraps utils/doh.js doHQuery for A/AAAA lookups.
 */

import { Client } from '../../features/dns.js';
import { doHQuery } from '../../utils/doh.js';
import { resolveAddressPort } from '../../utils/doh.js';

export class LocalDNSClient extends Client {
	constructor({ dohService = 'https://cloudflare-dns.com/dns-query' } = {}) {
		super();
		this.dohService = dohService;
	}

	type() {
		return Client;
	}

	async start() {}
	async close() {}

	async lookupIP(domain, { ipv4 = true, ipv6 = true } = {}) {
		const addresses = [];
		if (ipv4) {
			try {
				const out = await doHQuery(domain, 'A', this.dohService);
				for (const r of out) {
					if (r.data && !addresses.includes(r.data)) addresses.push(r.data);
				}
			} catch {
				/* fall through to AAAA */
			}
		}
		if (ipv6 && addresses.length === 0) {
			try {
				const out = await doHQuery(domain, 'AAAA', this.dohService);
				for (const r of out) {
					if (r.data && !addresses.includes(r.data)) addresses.push(r.data);
				}
			} catch {
				/* ignore */
			}
		}
		return { addresses, ttl: 600 };
	}
}

/** Resolve a host:port to candidate { hostname, port } list (reuse helpers). */
export async function resolveHostPort(hostname, port, request) {
	return resolveAddressPort(hostname, port, request);
}