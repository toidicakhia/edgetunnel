/**
 * src/core/protocol.js
 * Auto-generated from _worker.js refactor
 * Original: edgetunnel 2.1 (2026-08-11)
 */
import { closeSocketQuietly, forwardUDP } from './tcp.js';
import { concatByteData, getValidDataLength, toUint8Array } from '../utils/helpers.js';
import { connectStreams } from './grain.js';
import { createRequestTCPConnector } from './proxy.js';
import { pureMD5Bytes, sha224 } from '../utils/crypto.js';
import { stripIPv6Brackets } from '../utils/network.js';


export const trojanTextDecoder = new TextDecoder();

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

export async function connectTrojanProxy(firstPacketdata, tcpConnector, trojanProxyTarget) {
	if (!trojanProxyTarget) throw new Error('trojan fallback is not configured');
	const socket = tcpConnector({
		hostname: stripIPv6Brackets(trojanProxyTarget.hostname),
		port: trojanProxyTarget.port,
	});
	let writer = null;
	try {
		if (socket.opened) await socket.opened;
		if (getValidDataLength(firstPacketdata) > 0) {
			writer = socket.writable.getWriter();
			await writer.write(toUint8Array(firstPacketdata));
		}
		return socket;
	} catch (error) {
		try {
			socket?.close?.();
		} catch {}
		throw error;
	} finally {
		try {
			writer?.releaseLock();
		} catch {}
	}
}

export function extractTrojanProxyHandshakeData(firstPacketdata, rawData) {
	const firstPacket = toUint8Array(firstPacketdata);
	const payload = toUint8Array(rawData);
	if (!payload.byteLength) return firstPacket;
	const handshakelength = firstPacket.byteLength - payload.byteLength;
	if (handshakelength <= 0) return firstPacket;
	for (let i = 0; i < payload.byteLength; i++) {
		if (firstPacket[handshakelength + i] !== payload[i]) return firstPacket;
	}
	return firstPacket.subarray(0, handshakelength);
}

export async function forwardTrojanUDPProxyData(chunk, webSocket, context, request) {
	const data = toUint8Array(chunk);
	if (!context.proxySocket) {
		const tcpConnector = createRequestTCPConnector(request);
		const socket = await connectTrojanProxy(data, tcpConnector, context.proxyAddress);
		context.proxySocket = socket;
		socket.closed.catch(() => {}).finally(() => closeSocketQuietly(webSocket));
		connectStreams(socket, webSocket, null, null);
		return;
	}
	if (!data.byteLength) return;
	const writer = context.proxySocket.writable.getWriter();
	try {
		await writer.write(data);
	} finally {
		try {
			writer.releaseLock();
		} catch {}
	}
}

const _trojanHashCache = new Map();

export function getTrojanPasswordHashes(passwordPlainText) {
	const text = String(passwordPlainText || '');
	let cached = _trojanHashCache.get(text);
	if (cached) return cached;
	const hash1 = sha224(text).toLowerCase();
	const hash2 = sha224(hash1).toLowerCase();
	const hashes = [hash1, hash2];
	if (/^[0-9a-fA-F]{56}$/.test(text)) {
		hashes.push(text.toLowerCase());
	}
	if (_trojanHashCache.size > 128) _trojanHashCache.clear();
	_trojanHashCache.set(text, hashes);
	return hashes;
}

export function matchTrojanPassword(data, expectedHashes) {
	if (!data || data.byteLength < 56) return false;
	const headerStr = trojanTextDecoder.decode(data.subarray(0, 56)).toLowerCase();
	return expectedHashes.some((h) => h === headerStr);
}

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

export const SS_SUPPORTED_CIPHERS = {
	'aes-128-gcm': {
		method: 'aes-128-gcm',
		keyLen: 16,
		saltLen: 16,
		maxChunk: 0x3fff,
		aesLength: 128,
	},
	'aes-256-gcm': {
		method: 'aes-256-gcm',
		keyLen: 32,
		saltLen: 32,
		maxChunk: 0x3fff,
		aesLength: 256,
	},
};

export const SS_AEAD_TAG_LENGTH = 16,
	SS_NONCE_LENGTH = 12;

export const SS_SUBKEY_INFO = new TextEncoder().encode('ss-subkey');

export const ssTextEncoder = new TextEncoder(),
	ssTextDecoder = new TextDecoder(),
	ssMasterKeyCache = new Map();

export async function forwardTrojanUDPData(chunk, webSocket, context, request) {
	const currentChunk = toUint8Array(chunk);
	if (context?.proxyAddress)
		return forwardTrojanUDPProxyData(currentChunk, webSocket, context, request);
	const bufferChunk = context?.buffer instanceof Uint8Array ? context.buffer : new Uint8Array(0);
	const input = bufferChunk.byteLength ? concatByteData(bufferChunk, currentChunk) : currentChunk;
	let cursor = 0;

	while (cursor < input.byteLength) {
		const packetStart = cursor;
		const atype = input[cursor];
		const addrCursor = cursor + 1;
		let addrLen = 0;
		if (atype === 1) addrLen = 4;
		else if (atype === 4) addrLen = 16;
		else if (atype === 3) {
			if (input.byteLength < addrCursor + 1) break;
			addrLen = 1 + input[addrCursor];
		} else throw new Error(`invalid trojan udp addressType: ${atype}`);

		const portCursor = addrCursor + addrLen;
		if (input.byteLength < portCursor + 6) break;

		const port = (input[portCursor] << 8) | input[portCursor + 1];
		const payloadLength = (input[portCursor + 2] << 8) | input[portCursor + 3];
		if (input[portCursor + 4] !== 0x0d || input[portCursor + 5] !== 0x0a)
			throw new Error('invalid trojan udp delimiter');

		const payloadStart = portCursor + 6;
		const payloadEnd = payloadStart + payloadLength;
		if (input.byteLength < payloadEnd) break;

		const addressPortHeader = input.slice(packetStart, portCursor + 2);
		const payload = input.slice(payloadStart, payloadEnd);
		cursor = payloadEnd;

		if (port !== 53) throw new Error('UDP is not supported');
		if (!payload.byteLength) continue;

		let tcpDNSquery = payload;
		if (payload.byteLength < 2 || ((payload[0] << 8) | payload[1]) !== payload.byteLength - 2) {
			tcpDNSquery = new Uint8Array(payload.byteLength + 2);
			tcpDNSquery[0] = (payload.byteLength >>> 8) & 0xff;
			tcpDNSquery[1] = payload.byteLength & 0xff;
			tcpDNSquery.set(payload, 2);
		}

		const dnsResponseContext = { buffer: new Uint8Array(0) };
		await forwardUDP(tcpDNSquery, webSocket, null, request, (dnsRespChunk) => {
			const currentResponseChunk = toUint8Array(dnsRespChunk);
			const responseInput = dnsResponseContext.buffer.byteLength
				? concatByteData(dnsResponseContext.buffer, currentResponseChunk)
				: currentResponseChunk;
			const responseFrameList = [];
			let responseCursor = 0;
			while (responseCursor + 2 <= responseInput.byteLength) {
				const dnsLen =
					(responseInput[responseCursor] << 8) | responseInput[responseCursor + 1];
				const dnsStart = responseCursor + 2;
				const dnsEnd = dnsStart + dnsLen;
				if (dnsEnd > responseInput.byteLength) break;
				const dnsPayload = responseInput.slice(dnsStart, dnsEnd);
				const frame = new Uint8Array(
					addressPortHeader.byteLength + 4 + dnsPayload.byteLength
				);
				frame.set(addressPortHeader, 0);
				frame[addressPortHeader.byteLength] = (dnsPayload.byteLength >>> 8) & 0xff;
				frame[addressPortHeader.byteLength + 1] = dnsPayload.byteLength & 0xff;
				frame[addressPortHeader.byteLength + 2] = 0x0d;
				frame[addressPortHeader.byteLength + 3] = 0x0a;
				frame.set(dnsPayload, addressPortHeader.byteLength + 4);
				responseFrameList.push(frame);
				responseCursor = dnsEnd;
			}
			dnsResponseContext.buffer = responseInput.slice(responseCursor);
			return responseFrameList.length ? responseFrameList : new Uint8Array(0);
		});
	}

	if (context) context.buffer = input.slice(cursor);
}

export function SSIncrementNonceCounter(counter) {
	for (let i = 0; i < counter.length; i++) {
		counter[i] = (counter[i] + 1) & 0xff;
		if (counter[i] !== 0) return;
	}
}

export async function SSDeriveMasterKey(passwordText, keyLen) {
	const cacheKey = `${keyLen}:${passwordText}`;
	if (ssMasterKeyCache.has(cacheKey)) return ssMasterKeyCache.get(cacheKey);
	const deriveTask = (async () => {
		const pwBytes = ssTextEncoder.encode(passwordText || '');
		let prev = new Uint8Array(0),
			result = new Uint8Array(0);
		while (result.byteLength < keyLen) {
			const input = new Uint8Array(prev.byteLength + pwBytes.byteLength);
			input.set(prev, 0);
			input.set(pwBytes, prev.byteLength);
			prev = pureMD5Bytes(input);
			result = concatByteData(result, prev);
		}
		return result.slice(0, keyLen);
	})();
	ssMasterKeyCache.set(cacheKey, deriveTask);
	try {
		return await deriveTask;
	} catch (error) {
		ssMasterKeyCache.delete(cacheKey);
		throw error;
	}
}

export async function SSDeriveSessionKey(config, masterKey, salt, usages) {
	const hmacOpts = { name: 'HMAC', hash: 'SHA-1' };
	const saltHmacKey = await crypto.subtle.importKey('raw', salt, hmacOpts, false, ['sign']);
	const prk = new Uint8Array(await crypto.subtle.sign('HMAC', saltHmacKey, masterKey));
	const prkHmacKey = await crypto.subtle.importKey('raw', prk, hmacOpts, false, ['sign']);
	const subKey = new Uint8Array(config.keyLen);
	let prev = new Uint8Array(0),
		written = 0,
		counter = 1;
	while (written < config.keyLen) {
		const input = concatByteData(prev, SS_SUBKEY_INFO, new Uint8Array([counter]));
		prev = new Uint8Array(await crypto.subtle.sign('HMAC', prkHmacKey, input));
		const copyLen = Math.min(prev.byteLength, config.keyLen - written);
		subKey.set(prev.subarray(0, copyLen), written);
		written += copyLen;
		counter += 1;
	}
	return crypto.subtle.importKey(
		'raw',
		subKey,
		{ name: 'AES-GCM', length: config.aesLength },
		false,
		usages
	);
}

export async function SSAEADEncrypt(cryptoKey, nonceCounter, plaintext) {
	const iv = nonceCounter.slice();
	const ct = await crypto.subtle.encrypt(
		{ name: 'AES-GCM', iv, tagLength: 128 },
		cryptoKey,
		plaintext
	);
	SSIncrementNonceCounter(nonceCounter);
	return new Uint8Array(ct);
}

export async function SSAEADDecrypt(cryptoKey, nonceCounter, ciphertext) {
	const iv = nonceCounter.slice();
	const pt = await crypto.subtle.decrypt(
		{ name: 'AES-GCM', iv, tagLength: 128 },
		cryptoKey,
		ciphertext
	);
	SSIncrementNonceCounter(nonceCounter);
	return new Uint8Array(pt);
}
