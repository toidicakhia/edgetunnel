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

/** localdns — default fallback feature installed by core.New when none configured. */
export class LocalDNS extends Client {
	constructor(resolver = null) {
		super();
		this.resolver = resolver; // ({domain, ipv4, ipv6}) => Promise<string[]>
	}

	async start() {}

	async lookupIP(domain, { ipv4 = true, ipv6 = true } = {}) {
		if (!this.resolver) throw new Error('no dns resolver configured');
		const addresses = await this.resolver.lookup(domain);
		const filtered = addresses.filter((a) =>
			a.includes(':') ? ipv6 : ipv4
		);
		return { addresses: filtered, ttl: 600 };
	}
}