/**
 * src/proxy/vless/encoding.js
 * VLESS protocol encoding/decoding — mirror of Xray-core proxy/vless/encoding.
 *
 * Request header layout (encoding.go):
 *   [0] version = 0x00
 *   [1..16] UUID (16B raw)
 *   [17] addons-len (1B, 0x00 when none)
 *   [18..18+n] addons protobuf (Addons{ string Flow = 1; bytes Seed = 2 })
 *   [next] command 0x01 TCP | 0x02 UDP | 0x03 Mux | 0x04 Rvs
 *   [next] PortThenAddress: 2B BE port + address (1B type + payload)
 *
 * Response header: [0] version 0x00 (addons-len 0) — plaintext.
 * UDP body: 2B BE length + payload per packet.
 *
 * uuid helpers moved here from src/core/protocol.js (getUUIDBytes etc.).
 */

import { toUint8Array } from '../../utils/helpers.js';

export const uuidBytesCache = new Map();

export const vlessTextDecoder = new TextDecoder();

export function readHexNibble(code) {
	if (code >= 48 && code <= 57) return code - 48;
	code |= 32;
	if (code >= 97 && code <= 102) return code - 87;
	return -1;
}

export function getUUIDBytes(uuid) {
	const key = String(uuid || '');
	const cached = uuidBytesCache.get(key);
	if (cached) return cached;

	const clean = key.replace(/-/g, '');
	if (clean.length !== 32) return null;

	const bytes = new Uint8Array(16);
	for (let i = 0; i < 16; i++) {
		const high = readHexNibble(clean.charCodeAt(i * 2));
		const low = readHexNibble(clean.charCodeAt(i * 2 + 1));
		if (high < 0 || low < 0) return null;
		bytes[i] = (high << 4) | low;
	}

	if (uuidBytesCache.size >= 32) uuidBytesCache.clear();
	uuidBytesCache.set(key, bytes);
	return bytes;
}

export function uuidBytesMatch(data, offset, uuid) {
	const expected = getUUIDBytes(uuid);
	if (!expected || data.byteLength < offset + 16) return false;
	for (let i = 0; i < 16; i++) {
		if (data[offset + i] !== expected[i]) return false;
	}
	return true;
}

/** uuidBytesToStr — 16 bytes → canonical UUID string (encode-side helper). */
export function uuidBytesToStr(bytes) {
	const hex = [];
	for (let i = 0; i < 16; i++) hex.push(bytes[i].toString(16).padStart(2, '0'));
	return `${hex.slice(0, 4).join('')}-${hex.slice(4, 6).join('')}-${hex.slice(6, 8).join('')}-${hex.slice(8, 10).join('')}-${hex.slice(10).join('')}`;
}

/**
 * Encode VLESS addons protobuf (addons.proto Addons).
 * @param {{ flow?: string, seed?: Uint8Array }} addons
 * @returns {Uint8Array} empty when no fields
 */
export function encodeAddons({ flow = '', seed = null } = {}) {
	const parts = [];
	if (flow) {
		const fieldBytes = new TextEncoder().encode(flow);
		parts.push(0x0a); // field 1, wiretype 2
		parts.push(writeVarint(fieldBytes.length));
		parts.push(fieldBytes);
	}
	if (seed && seed.byteLength) {
		parts.push(0x12); // field 2, wiretype 2
		parts.push(writeVarint(seed.byteLength));
		parts.push(seed);
	}
	const total = parts.reduce((s, p) => s + p.length, 0);
	const out = new Uint8Array(total);
	let off = 0;
	for (const p of parts) {
		out.set(p, off);
		off += p.length;
	}
	return out;
}

function writeVarint(value) {
	const out = [];
	let n = value >>> 0;
	while (n > 127) {
		out.push((n & 0x7f) | 0x80);
		n >>>= 7;
	}
	out.push(n);
	return out;
}

/**
 * Encode a VLESS request header (client side).
 * @param {object} opts
 * @param {string} opts.uuid client UUID
 * @param {number} opts.command RequestCommand (0x01 TCP / 0x02 UDP / 0x03 Mux / 0x04 Rvs)
 * @param {import('../../common/net.js').Destination} opts.dest target (TCP/UDP)
 * @param {{ flow?: string, seed?: Uint8Array }} [opts.addons]
 * @returns {{ header: Uint8Array, version: number }}
 */
export function encodeVLESSRequestHeader({ uuid, command, dest, addons = null }) {
	const uuidBytes = getUUIDBytes(uuid);
	if (!uuidBytes) throw new Error('vless: invalid uuid');
	const addonsBytes = addons ? encodeAddons(addons) : new Uint8Array(0);
	// PortThenAddress (2B port + type + payload)
	const portThenAddr = encodePortThenAddressBytes(dest);
	const header = new Uint8Array(1 + 16 + 1 + addonsBytes.length + 1 + portThenAddr.length);
	header[0] = 0; // version
	header.set(uuidBytes, 1);
	header[17] = addonsBytes.length;
	header.set(addonsBytes, 18);
	header[18 + addonsBytes.length] = command;
	header.set(portThenAddr, 19 + addonsBytes.length);
	return { header, version: 0 };
}

/** PortThenAddress byte builder (family: 2B BE port first). */
export function encodePortThenAddressBytes(dest) {
	const addr = encodeVLESSAddressBytes(dest.address);
	const out = new Uint8Array(2 + addr.length);
	out[0] = (dest.port >> 8) & 0xff;
	out[1] = dest.port & 0xff;
	out.set(addr, 2);
	return out;
}

/** [type][payload] address builder (VLESS family: IPv4=1 Domain=2 IPv6=3). */
export function encodeVLESSAddressBytes(address) {
	if (/^\d{1,3}(\.\d{1,3}){3}$/.test(address)) {
		const out = new Uint8Array(5);
		out[0] = 1;
		const parts = address.split('.').map(Number);
		out[1] = parts[0];
		out[2] = parts[1];
		out[3] = parts[2];
		out[4] = parts[3];
		return out;
	}
	if (address.includes(':')) {
		const clean = address.replace(/^\[|\]$/g, '');
		const out = new Uint8Array(17);
		out[0] = 3;
		const groups = clean.split(':');
		let i = 1;
		for (const g of groups) {
			if (g === '') continue;
			const v = parseInt(g, 16) || 0;
			out[i++] = (v >> 8) & 0xff;
			out[i++] = v & 0xff;
		}
		return out;
	}
	const enc = new TextEncoder().encode(address);
	const out = new Uint8Array(1 + 1 + enc.length);
	out[0] = 2;
	out[1] = enc.length;
	out.set(enc, 2);
	return out;
}

/** Decode single raw address type from a PortThenAddress (with port). */
export function decodePortThenAddressBytes(data, cmdOffset) {
	const port = (data[cmdOffset] << 8) | data[cmdOffset + 1];
	const addressType = data[cmdOffset + 2];
	let addrValIdx = cmdOffset + 3;
	let addrLen = 0;
	let hostname = '';
	switch (addressType) {
		case 1:
			addrLen = 4;
			hostname = `${data[addrValIdx]}.${data[addrValIdx + 1]}.${data[addrValIdx + 2]}.${data[addrValIdx + 3]}`;
			break;
		case 2: {
			addrLen = data[addrValIdx];
			addrValIdx += 1;
			hostname = vlessTextDecoder.decode(data.subarray(addrValIdx, addrValIdx + addrLen));
			break;
		}
		case 3: {
			addrLen = 16;
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = addrValIdx + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			break;
		}
		default:
			throw new Error(`invalid address type: ${addressType}`);
	}
	return { port, addressType, hostname, rawIndex: addrValIdx + addrLen };
}

/**
 * parseVLESSRequest — decode a VLESS request header (byte-compatible with
 * src/core/protocol.js parseVLESSRequest; returns same shape).
 */
export function parseVLESSRequest(chunk, token) {
	const data = toUint8Array(chunk);
	const length = data.byteLength;
	if (length < 24) return { hasError: true, message: 'Invalid data' };
	const version = data[0];
	if (!uuidBytesMatch(data, 1, token)) return { hasError: true, message: 'Invalid uuid' };

	const optLen = data[17];
	const cmdIndex = 18 + optLen;
	if (length < cmdIndex + 4) return { hasError: true, message: 'Invalid data' };

	const cmd = data[cmdIndex];
	let isUDP = false;
	if (cmd === 1) {
	} else if (cmd === 2) {
		isUDP = true;
	} else {
		return { hasError: true, message: 'Invalid command' };
	}

	const portIdx = cmdIndex + 1;
	const port = (data[portIdx] << 8) | data[portIdx + 1];
	let addrValIdx = portIdx + 3,
		addrLen = 0,
		hostname = '';
	const addressType = data[portIdx + 2];
	switch (addressType) {
		case 1:
			addrLen = 4;
			if (length < addrValIdx + addrLen)
				return { hasError: true, message: 'Invalid IPv4 address length' };
			hostname = `${data[addrValIdx]}.${data[addrValIdx + 1]}.${data[addrValIdx + 2]}.${data[addrValIdx + 3]}`;
			break;
		case 2:
			if (length < addrValIdx + 1)
				return { hasError: true, message: 'Invalid domain length' };
			addrLen = data[addrValIdx];
			addrValIdx += 1;
			if (length < addrValIdx + addrLen)
				return { hasError: true, message: 'Invalid domain data' };
			hostname = vlessTextDecoder.decode(data.subarray(addrValIdx, addrValIdx + addrLen));
			break;
		case 3: {
			addrLen = 16;
			if (length < addrValIdx + addrLen)
				return { hasError: true, message: 'Invalid IPv6 address length' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = addrValIdx + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			break;
		}
		default:
			return { hasError: true, message: `Invalid address type: ${addressType}` };
	}
	if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
	const rawIndex = addrValIdx + addrLen;
	return {
		hasError: false,
		addressType,
		port,
		hostname,
		isUDP,
		rawClientData: data.subarray(rawIndex),
		version,
	};
}

/** Response header: [version][addons-len] — Xray EncodeResponseHeader; empty addons => 0x00. */
export function encodeVLESSResponseHeader(version = 0) {
	return new Uint8Array([version, 0]);
}

/** Encode one VLESS UDP packet: [2B BE length][payload]. */
export function encodeVLESSUDPPacket(payload) {
	const data = toUint8Array(payload);
	const out = new Uint8Array(2 + data.byteLength);
	out[0] = (data.byteLength >> 8) & 0xff;
	out[1] = data.byteLength & 0xff;
	out.set(data, 2);
	return out;
}

/** Decode VLESS UDP frames from a byte buffer; returns { packets, rest }. */
export function decodeVLESSUDPPackets(chunk, buffer = new Uint8Array(0)) {
	const input = buffer.byteLength ? concatBytes(buffer, toUint8Array(chunk)) : toUint8Array(chunk);
	const packets = [];
	let cursor = 0;
	while (cursor + 2 <= input.byteLength) {
		const len = (input[cursor] << 8) | input[cursor + 1];
		const start = cursor + 2;
		const end = start + len;
		if (end > input.byteLength) break;
		packets.push(input.subarray(start, end));
		cursor = end;
	}
	return { packets, rest: input.subarray(cursor) };
}

function concatBytes(a, b) {
	const out = new Uint8Array(a.byteLength + b.byteLength);
	out.set(a, 0);
	out.set(b, a.byteLength);
	return out;
}