/**
 * src/app/router/router.js
 * Rule-based router — mirror of Xray-core app/router.
 *
 * Rule sources:
 *   - whitelist entries: '*example.com' → domain-suffix, 'example.com' →
 *     domain-exact, '*' → catch-all (default outbound)
 *   - rule list from config: { type, value, tag, inboundTag? }
 */

import { Router, newRoute } from '../../features/routing.js';

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
			mask = (mask << 8) | (shift > 0 ? 0xff << shift : 0xff) & 0xff;
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

/**
 * RouterImpl — ordered rule list; first match wins; optional default tag.
 */
export class RouterImpl extends Router {
	/**
	 * @param {Array<{type: string, value: string, tag: string, ruleTag?: string}>} rules
	 * @param {{ defaultTag?: string }} opts
	 */
	constructor(rules = [], { defaultTag = '' } = {}) {
		super();
		this.rules = rules.map((r) => ({ ...r, matcher: compileRule(r) }));
		this.defaultTag = defaultTag;
	}

	async start() {}
	async close() {}

	pickRoute(ctx) {
		const target = ctx.target;
		if (!target) {
			const err = new Error('no target in session');
			err.code = 'ErrNoClue';
			throw err;
		}
		for (const rule of this.rules) {
			if (matchRule(rule, target, ctx)) {
				return newRoute(rule.tag, { ruleTag: rule.ruleTag || rule.type });
			}
		}
		if (this.defaultTag) return newRoute(this.defaultTag);
		const err = new Error('no matching route');
		err.code = 'ErrNoClue';
		throw err;
	}
}

function compileRule(rule) {
	switch (rule.type) {
		case 'domain-suffix':
		case 'domain-exact':
			return patternMatcher(rule.value);
		case 'ip':
			return cidrMatcher(rule.value);
		case 'port':
		case 'port-range': {
			const [a, b] = String(rule.value).split('-').map(Number);
			if (b !== undefined) return (dest) => dest.port >= a && dest.port <= b;
			return (dest) => dest.port === a;
		}
		case 'network': {
			const net = String(rule.value).toLowerCase();
			return (dest) => (net === 'tcp' ? dest.network === 0x01 : net === 'udp' ? dest.network === 0x02 : false);
		}
		default:
			return () => false;
	}
}

function matchRule(rule, dest, ctx) {
	if (rule.inboundTag && ctx.inbound?.tag !== rule.inboundTag) return false;
	return rule.matcher(dest.address, dest, ctx);
}

/** Build router rules from the socks5 whitelist (GO2SOCKS5 semantics). */
export function rulesFromWhitelist(whitelist, { tag = 'socks5' } = {}) {
	const rules = [];
	let catchAll = false;
	for (const entry of whitelist || []) {
		const p = String(entry || '').trim();
		if (!p) continue;
		if (p === '*') {
			catchAll = true;
			continue;
		}
		rules.push({
			type: p.startsWith('*') ? 'domain-suffix' : 'domain-exact',
			value: p.replace(/^\*/, ''),
			tag,
		});
	}
	return { rules, defaultTag: catchAll ? tag : '' };
}