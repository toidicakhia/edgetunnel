/**
 * src/features/dns.js
 * DNS client feature + local fallback — mirror of Xray-core features/dns.
 */

import { Feature } from './feature.js';

/**
 * dns.Client — resolves a hostname.
 * lookupIP(domain, { ipv4, ipv6 }) → Promise<{ addresses: string[], ttl: number }>
 */
export class Client extends Feature {
	type() {
		return Client;
	}

	async lookupIP(_domain, _option = {}) {
		throw new Error('dns client lookupIP not implemented');
	}
}

