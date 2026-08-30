import test from 'node:test';
import assert from 'node:assert/strict';
import {
	getUUIDBytes,
	uuidBytesMatch,
	parseVLESSRequest,
	parseTrojanRequest,
	SSDeriveMasterKey,
	SSDeriveSessionKey,
	SSAEADEncrypt,
	SSAEADDecrypt,
	SS_SUPPORTED_CIPHERS,
} from '../src/core/protocol.js';
import { sha224 } from '../src/utils/crypto.js';
import { readXHTTPFirstPacket } from '../src/handlers/xhttp.js';

test('getUUIDBytes converts UUID string to 16 bytes and matches', () => {
	const uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4';
	const bytes = getUUIDBytes(uuid);
	assert.equal(bytes.length, 16);
	assert.equal(bytes[0], 0xd3);
	assert.equal(bytes[1], 0x42);
	assert.equal(bytes[15], 0xa4);

	const packet = new Uint8Array(20);
	packet.set(bytes, 1);
	assert.equal(uuidBytesMatch(packet, 1, uuid), true);
	assert.equal(uuidBytesMatch(packet, 0, uuid), false);
});

test('parseVLESSRequest parses IPv4 target correctly', () => {
	const uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4';
	const uuidBytes = getUUIDBytes(uuid);

	// VLESS header: version(1) + uuid(16) + optLen(1)=0 + cmd(1)=1(TCP) + port(2)=80 + addrType(1)=1(IPv4) + ip(4)=1.1.1.1 + payload
	const packet = new Uint8Array(1 + 16 + 1 + 1 + 2 + 1 + 4 + 4);
	packet[0] = 0; // version 0
	packet.set(uuidBytes, 1);
	packet[17] = 0; // optLen
	packet[18] = 1; // cmd TCP
	packet[19] = 0x00; // port 80 (high byte)
	packet[20] = 0x50; // port 80 (low byte)
	packet[21] = 1; // IPv4
	packet[22] = 1; packet[23] = 1; packet[24] = 1; packet[25] = 1; // 1.1.1.1
	packet.set([0x47, 0x45, 0x54, 0x20], 26); // "GET "

	const result = parseVLESSRequest(packet, uuid);
	assert.equal(result.hasError, false);
	assert.equal(result.version, 0);
	assert.equal(result.isUDP, false);
	assert.equal(result.port, 80);
	assert.equal(result.hostname, '1.1.1.1');
	assert.deepEqual(Array.from(result.rawClientData), [0x47, 0x45, 0x54, 0x20]);
});

test('parseVLESSRequest parses Domain target correctly', () => {
	const uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4';
	const uuidBytes = getUUIDBytes(uuid);
	const domain = 'example.com';
	const domainBytes = new TextEncoder().encode(domain);

	// VLESS header: version(1) + uuid(16) + optLen(1)=0 + cmd(1)=1 + port(2)=443 + addrType(1)=2(Domain) + domainLen(1) + domain
	const packet = new Uint8Array(1 + 16 + 1 + 1 + 2 + 1 + 1 + domainBytes.length);
	packet[0] = 0;
	packet.set(uuidBytes, 1);
	packet[17] = 0;
	packet[18] = 1;
	packet[19] = 0x01; // port 443
	packet[20] = 0xbb;
	packet[21] = 2; // Domain
	packet[22] = domainBytes.length;
	packet.set(domainBytes, 23);

	const result = parseVLESSRequest(packet, uuid);
	assert.equal(result.hasError, false);
	assert.equal(result.port, 443);
	assert.equal(result.hostname, 'example.com');
});

test('parseTrojanRequest validates password and extracts destination', () => {
	const password = 'my-trojan-password';
	const hash = sha224(password);
	const domain = 'cloudflare.com';
	const domainBytes = new TextEncoder().encode(domain);

	// Trojan header: 56 hex chars + \r\n (2) + cmd(1)=1 + atype(1)=3(Domain) + domainLen(1) + domain + port(2)=443 + \r\n(2)
	const headerLength = 56 + 2 + 1 + 1 + 1 + domainBytes.length + 2 + 2;
	const packet = new Uint8Array(headerLength);
	for (let i = 0; i < 56; i++) packet[i] = hash.charCodeAt(i);
	packet[56] = 0x0d;
	packet[57] = 0x0a;
	packet[58] = 1; // TCP
	packet[59] = 3; // Domain
	packet[60] = domainBytes.length;
	packet.set(domainBytes, 61);
	const portIdx = 61 + domainBytes.length;
	packet[portIdx] = 0x01;
	packet[portIdx + 1] = 0xbb; // 443
	packet[portIdx + 2] = 0x0d;
	packet[portIdx + 3] = 0x0a;

	const result = parseTrojanRequest(packet, password);
	assert.equal(result.hasError, false);
	assert.equal(result.isUDP, false);
	assert.equal(result.port, 443);
	assert.equal(result.hostname, 'cloudflare.com');
});

test('Shadowsocks AEAD encryption/decryption roundtrip', async () => {
	const password = 'secret-ss-password';
	const cipherConfig = SS_SUPPORTED_CIPHERS['aes-128-gcm'];
	
	const masterKey = await SSDeriveMasterKey(password, cipherConfig.keyLen);
	assert.equal(masterKey.length, 16);

	const salt = crypto.getRandomValues(new Uint8Array(cipherConfig.saltLen));
	const sessionKey = await SSDeriveSessionKey(cipherConfig, masterKey, salt, ['encrypt', 'decrypt']);

	const plaintext = new TextEncoder().encode('Hello, Shadowsocks AEAD!');
	const encNonce = new Uint8Array(12);
	const ciphertext = await SSAEADEncrypt(sessionKey, encNonce, plaintext);

	const decNonce = new Uint8Array(12);
	const decrypted = await SSAEADDecrypt(sessionKey, decNonce, ciphertext);

	assert.equal(new TextDecoder().decode(decrypted), 'Hello, Shadowsocks AEAD!');
});

test('readXHTTPFirstPacket rejects invalid non-proxy payload immediately without hanging', async () => {
	const invalidPayload = new TextEncoder().encode('POST / HTTP/1.1\r\nHost: example.com\r\n\r\n{"test":123}');
	let readCount = 0;
	const mockReader = {
		read: async () => {
			readCount++;
			if (readCount === 1) return { value: invalidPayload, done: false };
			return { value: undefined, done: true };
		},
	};
	const uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4';
	const res = await readXHTTPFirstPacket(mockReader, uuid);
	assert.equal(res, null);
	assert.equal(readCount, 1); // Exited on the first chunk without hanging in loop!
});
