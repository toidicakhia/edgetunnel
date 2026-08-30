/**
 * src/common/net.js
 * Network destination model + address (de)serialization —
 * mirror of Xray-core common/net + common/protocol/address.go.
 *
 * Address type bytes (common/protocol/payload.go AddressType):
 *   IPv4 = 1, Domain = 2, IPv6 = 3   (wire values used by Trojan/SOCKS)
 * VLESS/VMess/XUDP/mux use the same 0x01/0x02/0x03 family bytes (address.go).
 */

export const AddressType = Object.freeze({
	IPv4: 0x01,
	Domain: 0x02,
	IPv6: 0x03,
});

export const Network = Object.freeze({
	TCP: 0x01,
	UDP: 0x02,
	UNIX: 0x03,
});

export const NetworkName = Object.freeze({
	[Network.TCP]: 'tcp',
	[Network.UDP]: 'udp',
	[Network.UNIX]: 'unix',
});

/**
 * Destination — parsed target. Equivalent to net.Destination.
 * @param {string} address hostname or IP
 * @param {number} port port (0 allowed for domain rules)
 * @param {number} network Network.TCP | Network.UDP
 */
export class Destination {
	constructor(address, port, network = Network.TCP) {
		this.address = address;
		this.port = port;
		this.network = network;
	}

	isIPv4() {
		return /^\d{1,3}(\.\d{1,3}){3}$/.test(this.address);
	}

	isIPv6() {
		return this.address.includes(':');
	}

	isDomain() {
		return !this.isIPv4() && !this.isIPv6();
	}

	/** 'tcp:1.2.3.4:80' / 'udp:example.com:53' — Xray net.Destination.String */
	toString() {
		const host = this.isIPv6() ? `[${this.address}]` : this.address;
		return `${NetworkName[this.network] || 'tcp'}:${host}:${this.port}`;
	}

	clone() {
		return new Destination(this.address, this.port, this.network);
	}
}

/** Parse 'tcp:host:port' / 'udp:[v6]:53' strings. */
export function parseDestination(str) {
	const m = /^(tcp|udp):(.+):(\d+)$/.exec(String(str).trim());
	if (!m) throw new Error(`invalid destination: ${str}`);
	let host = m[2];
	if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
	return new Destination(host, Number(m[3]), m[1] === 'udp' ? Network.UDP : Network.TCP);
}

/**
 * Serialize [type][payload] (no port) — non-VLESS family (Trojan/SOCKS wire order).
 * @returns {Uint8Array}
 */
export function encodeAddress(dest) {
	if (dest.isIPv4()) {
		const out = new Uint8Array(5);
		out[0] = AddressType.IPv4;
		const parts = dest.address.split('.').map(Number);
		out[1] = parts[0];
		out[2] = parts[1];
		out[3] = parts[2];
		out[4] = parts[3];
		return out;
	}
	if (dest.isIPv6()) {
		const out = new Uint8Array(17);
		out[0] = AddressType.IPv6;
		const group = dest.address.replace(/^\[|\]$/g, '').split(':');
		let i = 1;
		for (const g of group) {
			if (g === '') continue; // '::' handled below
			const v = parseInt(g, 16) || 0;
			out[i++] = (v >> 8) & 0xff;
			out[i++] = v & 0xff;
		}
		return out;
	}
	const enc = new TextEncoder().encode(dest.address);
	const out = new Uint8Array(1 + enc.length);
	out[0] = AddressType.Domain;
	out.set(enc, 1);
	return out;
}

/**
 * Parse [type][payload] into a Destination (port set separately).
 * @returns {{address: string, consumed: number}}
 */
export function decodeAddress(bytes, offset = 0) {
	if (offset >= bytes.length) throw new Error('address: out of bounds');
	const type = bytes[offset];
	switch (type) {
		case AddressType.IPv4: {
			if (offset + 5 > bytes.length) throw new Error('address: short ipv4');
			return {
				address: `${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}.${bytes[offset + 4]}`,
				consumed: 5,
			};
		}
		case AddressType.Domain: {
			if (offset + 1 >= bytes.length) throw new Error('address: short domain len');
			const len = bytes[offset + 1];
			if (offset + 2 + len > bytes.length) throw new Error('address: short domain');
			return {
				address: new TextDecoder().decode(bytes.subarray(offset + 2, offset + 2 + len)),
				consumed: 2 + len,
			};
		}
		case AddressType.IPv6: {
			if (offset + 17 > bytes.length) throw new Error('address: short ipv6');
			const parts = [];
			for (let i = 0; i < 8; i++) {
				const hi = bytes[offset + 1 + i * 2];
				const lo = bytes[offset + 2 + i * 2];
				parts.push(((hi << 8) | lo).toString(16));
			}
			return { address: parts.join(':'), consumed: 17 };
		}
		default:
			throw new Error(`address: unknown type ${type}`);
	}
}

/**
 * PortThenAddress (VLESS/VMess/XUDP/mux family):
 * [2B BE port][type][payload]
 */
export function encodePortThenAddress(dest) {
	const addr = encodeAddress(dest);
	const out = new Uint8Array(2 + addr.length);
	out[0] = (dest.port >> 8) & 0xff;
	out[1] = dest.port & 0xff;
	out.set(addr, 2);
	return out;
}

/**
 * Parse PortThenAddress from bytes.
 * @returns {{destination: Destination, consumed: number}}
 */
export function decodePortThenAddress(bytes, offset = 0) {
	if (offset + 2 > bytes.length) throw new Error('ptaddr: short port');
	const port = (bytes[offset] << 8) | bytes[offset + 1];
	const { address, consumed } = decodeAddress(bytes, offset + 2);
	return { destination: new Destination(address, port), consumed: 2 + consumed };
}

/**
 * AddressThenPort (Trojan/SOCKS family): [type][payload][2B BE port]
 */
export function encodeAddressThenPort(dest) {
	const addr = encodeAddress(dest);
	const out = new Uint8Array(addr.length + 2);
	out.set(addr, 0);
	out[out.length - 2] = (dest.port >> 8) & 0xff;
	out[out.length - 1] = dest.port & 0xff;
	return out;
}

export function decodeAddressThenPort(bytes, offset = 0) {
	const { address, consumed } = decodeAddress(bytes, offset);
	if (offset + consumed + 2 > bytes.length) throw new Error('ataddr: short port');
	const port = (bytes[offset + consumed] << 8) | bytes[offset + consumed + 1];
	return { destination: new Destination(address, port), consumed: consumed + 2 };
}