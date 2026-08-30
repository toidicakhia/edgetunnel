/**
 * src/proxy/trojan/encoding.js
 * Trojan protocol encoding/decoding — mirror of Xray-core proxy/trojan.
 *
 * Request (protocol.go):
 *   [0..55] 56B lowercase hex of SHA-224(password)
 *   [56..57] \r\n
 *   [58] command 0x01 TCP | 0x03 UDP
 *   [next] address: 1B type (0x01 IPv4 | 0x03 domain 1B len+bytes | 0x04 IPv6) + addr + 2B BE port
 *   [next] \r\n
 * UDP packet: [address+port][2B BE len]\r\n[payload]  (repeated per packet)
 *
 * Ported from src/core/protocol.js (parseTrojanRequest and friends).
 */

import { toUint8Array } from '../../utils/helpers.js';
import { sha224 } from '../../utils/crypto.js';

export const trojanTextDecoder = new TextDecoder();

/** Parse a 'host:port' / '[v6]:port' trojan proxy address. */
export function parseTrojanProxyAddress(address) {
	const raw = String(address || '').trim();
	if (!raw || raw.includes('/') || raw.includes('@') || raw.includes('://'))
		throw new Error('trojan proxy only supports host:port');
	let hostname = '',
		portText = '';
	if (raw.startsWith('[')) {
		const match = raw.match(/^(\[[^\]]+\]):(\d+)$/);
		if (!match) throw new Error('Invalid IPv6 trojanProxyAddress');
		hostname = match[1];
		portText = match[2];
	} else {
		const parts = raw.split(':');
		if (parts.length !== 2) throw new Error('trojan proxy only supports host:port');
		hostname = parts[0];
		portText = parts[1];
	}
	const port = Number(portText);
	if (!hostname || !Number.isInteger(port) || port < 1 || port > 65535)
		throw new Error('Invalidtrojan proxyPort');
	return { hostname, port };
}

/** SHA-224 hex credentials (hexSha224(password) + double-hash + raw hex). */
export function getTrojanPasswordHashes(passwordPlainText) {
	const text = String(passwordPlainText || '');
	const hash1 = sha224(text).toLowerCase();
	const hash2 = sha224(hash1).toLowerCase();
	const hashes = [hash1, hash2];
	if (/^[0-9a-fA-F]{56}$/.test(text)) {
		hashes.push(text.toLowerCase());
	}
	return hashes;
}

export function matchTrojanPassword(data, expectedHashes) {
	if (!data || data.byteLength < 56) return false;
	const headerStr = trojanTextDecoder.decode(data.subarray(0, 56)).toLowerCase();
	return expectedHashes.some((h) => h === headerStr);
}

/** Encode a trojan request header [sha224][\r\n][cmd][addr+port][\r\n]. */
export function encodeTrojanRequestHeader({ password, command, dest }) {
	const passwordBytes = trojanTextDecoder.encode(sha224(String(password || '')).toLowerCase());
	// address family: 0x01 IPv4 | 0x03 domain | 0x04 IPv6 (trojan ATyp)
	const addr = encodeTrojanAddress(dest.address);
	const header = new Uint8Array(56 + 2 + 1 + addr.length + 2 + 2);
	header.set(passwordBytes, 0);
	header[56] = 0x0d;
	header[57] = 0x0a;
	header[58] = command;
	header.set(addr, 59);
	const portOffset = 59 + addr.length;
	header[portOffset] = (dest.port >> 8) & 0xff;
	header[portOffset + 1] = dest.port & 0xff;
	header[portOffset + 2] = 0x0d;
	header[portOffset + 3] = 0x0a;
	return header;
}

function encodeTrojanAddress(address) {
	if (/^\d{1,3}(\.\d{1,3}){3}$/.test(address)) {
		const out = new Uint8Array(5);
		out[0] = 0x01;
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
		out[0] = 0x04;
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
	out[0] = 0x03;
	out[1] = enc.length;
	out.set(enc, 2);
	return out;
}

/** Parse a trojan request (byte-compatible with src/core/protocol.js). */
export function parseTrojanRequest(buffer, passwordPlainText) {
	const data = toUint8Array(buffer);
	if (data.byteLength < 58) return { hasError: true, message: 'invalid data' };
	const crLfIndex = 56;
	if (data[crLfIndex] !== 0x0d || data[crLfIndex + 1] !== 0x0a)
		return { hasError: true, message: 'invalid header format' };

	const expectedHashes = getTrojanPasswordHashes(passwordPlainText);
	if (!matchTrojanPassword(data, expectedHashes)) {
		return { hasError: true, message: 'invalid password' };
	}

	const socks5Index = crLfIndex + 2;
	if (data.byteLength < socks5Index + 6)
		return { hasError: true, message: 'invalid S5 request data' };

	const cmd = data[socks5Index];
	if (cmd !== 1 && cmd !== 3)
		return { hasError: true, message: 'unsupported command, only TCP/UDP is allowed' };
	const isUDP = cmd === 3;

	const atype = data[socks5Index + 1];
	let addressLength = 0;
	let addressIndex = socks5Index + 2;
	let address = '';
	switch (atype) {
		case 1: // IPv4
			addressLength = 4;
			if (data.byteLength < addressIndex + addressLength + 4)
				return { hasError: true, message: 'invalid S5 request data' };
			address = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
			break;
		case 3: // Domain
			if (data.byteLength < addressIndex + 1)
				return { hasError: true, message: 'invalid S5 request data' };
			addressLength = data[addressIndex];
			addressIndex += 1;
			if (data.byteLength < addressIndex + addressLength + 4)
				return { hasError: true, message: 'invalid S5 request data' };
			address = trojanTextDecoder.decode(
				data.subarray(addressIndex, addressIndex + addressLength)
			);
			break;
		case 4: {
			// IPv6
			addressLength = 16;
			if (data.byteLength < addressIndex + addressLength + 4)
				return { hasError: true, message: 'invalid S5 request data' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const partIndex = addressIndex + i * 2;
				ipv6.push(((data[partIndex] << 8) | data[partIndex + 1]).toString(16));
			}
			address = ipv6.join(':');
			break;
		}
		default:
			return { hasError: true, message: `invalid addressType is ${atype}` };
	}

	if (!address) {
		return { hasError: true, message: `address is empty, addressType is ${atype}` };
	}

	const portIndex = addressIndex + addressLength;
	if (data.byteLength < portIndex + 4)
		return { hasError: true, message: 'invalid S5 request data' };
	const portRemote = (data[portIndex] << 8) | data[portIndex + 1];

	return {
		hasError: false,
		addressType: atype,
		port: portRemote,
		hostname: address,
		isUDP,
		rawClientData: data.subarray(portIndex + 4),
	};
}

/**
 * Parse a Trojan UDP payload stream: sequence of
 * [addr+port][2B BE length]\r\n[payload].
 * @returns {{ packets: Array<{ dest: {hostname,port}, payload: Uint8Array }>, rest: Uint8Array }}
 */
export function parseTrojanUDPPackets(chunk, buffer = new Uint8Array(0)) {
	const data = buffer.byteLength ? concatBytes(buffer, toUint8Array(chunk)) : toUint8Array(chunk);
	const packets = [];
	let cursor = 0;
	while (cursor < data.byteLength) {
		const packetStart = cursor;
		const atype = data[cursor];
		const addrCursor = cursor + 1;
		let addrLen = 0;
		if (atype === 1) addrLen = 4;
		else if (atype === 4) addrLen = 16;
		else if (atype === 3) {
			if (data.byteLength < addrCursor + 1) break;
			addrLen = 1 + data[addrCursor];
		} else throw new Error(`invalid trojan udp addressType: ${atype}`);

		const portCursor = addrCursor + addrLen;
		if (data.byteLength < portCursor + 6) break;

		const port = (data[portCursor] << 8) | data[portCursor + 1];
		const payloadLength = (data[portCursor + 2] << 8) | data[portCursor + 3];
		if (data[portCursor + 4] !== 0x0d || data[portCursor + 5] !== 0x0a)
			throw new Error('invalid trojan udp delimiter');

		const payloadStart = portCursor + 6;
		const payloadEnd = payloadStart + payloadLength;
		if (data.byteLength < payloadEnd) break;

		packets.push({
			dest: { port, hostname: atype === 3 ? null : null },
			payload: data.slice(payloadStart, payloadEnd),
			addressPortHeader: data.slice(packetStart, portCursor + 2),
		});
		cursor = payloadEnd;
	}
	return { packets, rest: data.subarray(cursor) };
}

/** Encode one Trojan UDP packet: [addr+port][2B len]\r\n[payload]. */
export function encodeTrojanUDPPacket(dest, payload) {
	const addr = encodeTrojanAddress(dest.hostname);
	const data = toUint8Array(payload);
	const out = new Uint8Array(addr.length + 2 + 2 + 2 + data.byteLength);
	out.set(addr, 0);
	const portOffset = addr.length;
	out[portOffset] = (dest.port >> 8) & 0xff;
	out[portOffset + 1] = dest.port & 0xff;
	out[portOffset + 2] = (data.byteLength >> 8) & 0xff;
	out[portOffset + 3] = data.byteLength & 0xff;
	out[portOffset + 4] = 0x0d;
	out[portOffset + 5] = 0x0a;
	out.set(data, portOffset + 6);
	return out;
}

function concatBytes(a, b) {
	const out = new Uint8Array(a.byteLength + b.byteLength);
	out.set(a, 0);
	out.set(b, a.byteLength);
	return out;
}
