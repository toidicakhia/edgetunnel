/**
 * src/app/router/router.js
 * Rule-based router — mirror of Xray-core app/router.
 *
 * Rule sources:
 *   - whitelist entries: '*example.com' → domain-suffix, 'example.com' →
 *     domain-exact, '*' → catch-all (default outbound)
 *   - rule list from config: { type, value, tag, inboundTag? }
 */

/** Escape regex specials for literal matching. */
function escapeRegex(s) {
	return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Build a matcher from a whitelist-style pattern ('*' prefix wildcard). */
export function patternMatcher(pattern) {
	const p = String(pattern || '');
	if (p === '*') return () => true; // catch-all
	if (p.startsWith('*')) {
		const suffix = escapeRegex(p.slice(1));
		const re = new RegExp(`(?:^|\\.)${suffix}$`, 'i');
		return (hostname) => re.test(hostname);
	}
	const re = new RegExp(`^${escapeRegex(p)}$`, 'i');
	return (hostname) => re.test(hostname);
}

/** Parse CIDR '1.2.3.0/24' into a matcher (IPv4 + IPv6). */
export function cidrMatcher(cidr) {
	const [ip, bitsText] = String(cidr).split('/');
	const bits = bitsText === undefined ? (ip.includes(':') ? 128 : 32) : Number(bitsText);

	if (!ip.includes(':')) {
		const octets = ip.split('.').map(Number);
		let mask = 0;
		for (let i = 0; i < 4; i++) {
			const shift = 8 - Math.max(0, Math.min(8, bits - i * 8));
			mask = (mask << 8) | ((shift > 0 ? 0xff << shift : 0xff) & 0xff);
		}
		const base = octets.reduce((acc, o) => (acc << 8) | o, 0) >>> 0;
		return (hostname) => {
			const parts = hostname.split('.').map(Number);
			if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return false;
			const ipNum = parts.reduce((acc, o) => (acc << 8) | (o & 0xff), 0) >>> 0;
			return (ipNum & mask) === (base & mask);
		};
	}

	// IPv6 CIDR (prefix compare on the bigint address)
	const expand = (addr) => {
		const clean = addr.replace(/^\[|\]$/g, '');
		const groups = clean.split('::');
		let head = groups[0] ? groups[0].split(':') : [];
		const tail = groups.length > 1 && groups[1] ? groups[1].split(':') : [];
		const missing = 8 - head.length - tail.length;
		if (groups.length > 1) head = head.concat(Array(missing).fill('0'), tail);
		return head.map((g) => BigInt(parseInt(g || '0', 16) || 0));
	};
	const baseGroups = expand(ip);
	const prefix = BigInt(bits);
	return (hostname) => {
		if (!hostname.includes(':')) return false;
		const groups = expand(hostname);
		for (let i = 0; i < 8; i++) {
			if (prefix <= BigInt(i * 16)) return true; // outside this group's bits
			const groupBits = prefix - BigInt(i * 16) > 16n ? 16n : prefix - BigInt(i * 16);
			const mask = ((1n << groupBits) - 1n) << (16n - groupBits);
			if ((groups[i] & mask) !== (baseGroups[i] & mask)) return false;
		}
		return true;
	};
}
