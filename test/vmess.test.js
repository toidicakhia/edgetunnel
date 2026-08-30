import test from 'node:test';
import assert from 'node:assert/strict';
import {
	vmessKDF,
	vmessKDF16,
	getCmdKey,
	createAuthID,
	decodeAuthID,
	sealVMessAEADHeader,
	openVMessAEADHeader,
	parseVMessInnerHeader,
	parseVMessRequest,
	generateVMessLink,
	vmessDecryptChunk,
	vmessEncryptChunk,
	vmessCreateResponseHeader,
	getChunkNonce,
	Shake128,
	ShakeSizeParser,
	crc32,
	fnv1a,
	KDFSaltConstAEADRespHeaderLenKey,
	KDFSaltConstAEADRespHeaderLenIV,
	KDFSaltConstAEADRespHeaderPayloadKey,
	KDFSaltConstAEADRespHeaderPayloadIV,
} from '../src/core/vmess.js';

test('CRC32 computes IEEE checksum correctly', () => {
	const data = new TextEncoder().encode('123456789');
	assert.equal(crc32(data), 0xcbf43926);
});

test('vmessKDF matches official Xray-core / V2Ray-core test vector', () => {
	const key = new TextEncoder().encode('Demo Key for KDF Value Test');
	const kdfOut = vmessKDF(
		key,
		'Demo Path for KDF Value Test',
		'Demo Path for KDF Value Test2',
		'Demo Path for KDF Value Test3'
	);
	const hex = Buffer.from(kdfOut).toString('hex');
	assert.equal(hex, '53e9d7e1bd7bd25022b71ead07d8a596efc8a845c7888652fd684b4903dc8892');

	const kdf16 = vmessKDF16(
		key,
		'Demo Path for KDF Value Test',
		'Demo Path for KDF Value Test2',
		'Demo Path for KDF Value Test3'
	);
	assert.equal(Buffer.from(kdf16).toString('hex'), '53e9d7e1bd7bd25022b71ead07d8a596');
});

test('getCmdKey produces valid 16-byte MD5 key from UUID', () => {
	const uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4';
	const cmdKey = getCmdKey(uuid);
	assert.equal(cmdKey.length, 16);
});

test('createAuthID and decodeAuthID roundtrip successfully', () => {
	const cmdKey = new Uint8Array(16);
	for (let i = 0; i < 16; i++) cmdKey[i] = i * 7;
	const timestamp = Math.floor(Date.now() / 1000);

	const authID = createAuthID(cmdKey, timestamp);
	assert.equal(authID.length, 16);

	const decoded = decodeAuthID(authID, cmdKey);
	assert.notEqual(decoded, null);
	assert.equal(decoded.timestamp, timestamp);
});

test('sealVMessAEADHeader and openVMessAEADHeader roundtrip', async () => {
	const uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4';
	const cmdKey = getCmdKey(uuid);
	const testHeader = new TextEncoder().encode('Test VMess Inner Payload');

	const sealed = await sealVMessAEADHeader(cmdKey, testHeader);
	const authID = sealed.slice(0, 16);
	const rest = sealed.slice(16);

	const opened = await openVMessAEADHeader(cmdKey, authID, rest);
	assert.notEqual(opened, null);
	assert.deepEqual(Array.from(opened.header), Array.from(testHeader));
});

test('Shake128 and ShakeSizeParser mask/unmask chunk lengths correctly', () => {
	const nonce = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
	const encoder = new ShakeSizeParser(nonce);
	const decoder = new ShakeSizeParser(nonce);

	const originalLength = 1420;
	const encoded = encoder.encode(originalLength);
	const decoded = decoder.decode(encoded);
	assert.equal(decoded, originalLength);

	// Padding length generator test
	const padLen = encoder.nextPaddingLen();
	assert.equal(typeof padLen, 'number');
	assert.equal(padLen >= 0 && padLen < 64, true);
});

test('Chunk nonce increments correctly with count', () => {
	const bodyIV = new Uint8Array([0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x12, 0x34, 0x56, 0x78]);
	const nonce0 = getChunkNonce(bodyIV, 0);
	assert.equal(nonce0[0], 0);
	assert.equal(nonce0[1], 0);
	assert.equal(nonce0.length, 12);

	const nonce1 = getChunkNonce(bodyIV, 1);
	assert.equal(nonce1[0], 0);
	assert.equal(nonce1[1], 1);

	const nonce258 = getChunkNonce(bodyIV, 0x0102);
	assert.equal(nonce258[0], 1);
	assert.equal(nonce258[1], 2);
});

test('vmessCreateResponseHeader creates valid decryptable response header', async () => {
	const bodyKey = new Uint8Array(16).fill(0x11);
	const bodyIV = new Uint8Array(16).fill(0x22);
	const respHeaderByte = 0x55;

	const resp = await vmessCreateResponseHeader(respHeaderByte, bodyKey, bodyIV);
	assert.equal(resp.length, 18 + 18); // 18 bytes enc len + 18 bytes enc payload (2 + 16)

	// Decrypt with client keys
	const bodyKeyHash = new Uint8Array(await crypto.subtle.digest('SHA-256', bodyKey));
	const bodyIVHash = new Uint8Array(await crypto.subtle.digest('SHA-256', bodyIV));
	const respKey = bodyKeyHash.slice(0, 16);
	const respIV = bodyIVHash.slice(0, 16);

	const lenKey = vmessKDF16(respKey, KDFSaltConstAEADRespHeaderLenKey);
	const lenNonce = vmessKDF(respIV, KDFSaltConstAEADRespHeaderLenIV).slice(0, 12);
	const payloadKey = vmessKDF16(respKey, KDFSaltConstAEADRespHeaderPayloadKey);
	const payloadNonce = vmessKDF(respIV, KDFSaltConstAEADRespHeaderPayloadIV).slice(0, 12);

	const lenK = await crypto.subtle.importKey('raw', lenKey, { name: 'AES-GCM' }, false, ['decrypt']);
	const lenPt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: lenNonce }, lenK, resp.slice(0, 18)));
	const payloadLen = (lenPt[0] << 8) | lenPt[1];
	assert.equal(payloadLen, 2);

	const payloadK = await crypto.subtle.importKey('raw', payloadKey, { name: 'AES-GCM' }, false, ['decrypt']);
	const payloadPt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: payloadNonce }, payloadK, resp.slice(18)));
	assert.equal(payloadPt[0], 0); // Option 0
	assert.equal(payloadPt[1], 0); // Command 0
});

test('vmessEncryptChunk and vmessDecryptChunk roundtrip across multiple counts', async () => {
	const bodyKey = crypto.getRandomValues(new Uint8Array(16));
	const bodyIV = crypto.getRandomValues(new Uint8Array(16));
	const plaintext1 = new TextEncoder().encode('GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\n\r\n');
	const plaintext2 = new TextEncoder().encode('HTTP/1.1 204 No Content\r\nDate: Sun, 30 Aug 2026\r\n\r\n');

	// Chunk 0 (uplink)
	const enc0 = await vmessEncryptChunk(plaintext1, bodyKey, bodyIV, 0, 'aes-128-gcm');
	const dec0 = await vmessDecryptChunk(enc0, bodyKey, bodyIV, 0, 'aes-128-gcm');
	assert.deepEqual(Array.from(dec0), Array.from(plaintext1));

	// Chunk 1 (uplink)
	const enc1 = await vmessEncryptChunk(plaintext2, bodyKey, bodyIV, 1, 'aes-128-gcm');
	const dec1 = await vmessDecryptChunk(enc1, bodyKey, bodyIV, 1, 'aes-128-gcm');
	assert.deepEqual(Array.from(dec1), Array.from(plaintext2));
});

test('generateVMessLink builds valid vmess:// format', () => {
	const link = generateVMessLink({
		host: '1.1.1.1',
		port: 443,
		uuid: 'd342d11e-d424-4583-b36e-524ab1f0afa4',
		net: 'ws',
		path: '/vmess-ws',
		ps: 'EdgeTunnel-VMess',
	});
	assert.equal(link.startsWith('vmess://'), true);

	const jsonStr = atob(link.replace('vmess://', ''));
	const parsed = JSON.parse(jsonStr);
	assert.equal(parsed.v, '2');
	assert.equal(parsed.add, '1.1.1.1');
	assert.equal(parsed.port, '443');
	assert.equal(parsed.id, 'd342d11e-d424-4583-b36e-524ab1f0afa4');
	assert.equal(parsed.net, 'ws');
	assert.equal(parsed.path, '/vmess-ws');
	assert.equal(parsed.ps, 'EdgeTunnel-VMess');
});
