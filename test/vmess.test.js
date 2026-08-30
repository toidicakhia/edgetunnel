import test from 'node:test';
import assert from 'node:assert/strict';
import {
	vmessKDF,
	vmessKDF16,
	getCmdKey,
	createAuthID,
	decodeAuthID,
	generateVMessLink,
	parseVMessInnerHeader,
	vmessDecryptChunk,
	vmessCreateResponseHeader,
	crc32,
} from '../src/core/vmess.js';

test('CRC32 computes IEEE checksum correctly', () => {
	const data = new TextEncoder().encode('123456789');
	assert.equal(crc32(data), 0xcbf43926);
});

test('vmessKDF derives deterministic keys', async () => {
	const key = new TextEncoder().encode('test-key-material');
	const kdfOut1 = await vmessKDF(key, 'path1', 'path2');
	const kdfOut2 = await vmessKDF(key, 'path1', 'path2');
	assert.deepEqual(kdfOut1, kdfOut2);
	assert.equal(kdfOut1.length, 32);

	const kdf16 = await vmessKDF16(key, 'path1', 'path2');
	assert.equal(kdf16.length, 16);
	assert.deepEqual(kdf16, kdfOut1.slice(0, 16));
});

test('getCmdKey produces valid 16-byte MD5 key from UUID', async () => {
	const uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4';
	const cmdKey = await getCmdKey(uuid);
	assert.equal(cmdKey.length, 16);
});

test('createAuthID and decodeAuthID roundtrip successfully', async () => {
	const cmdKey = new Uint8Array(16);
	for (let i = 0; i < 16; i++) cmdKey[i] = i * 7;
	const timestamp = Math.floor(Date.now() / 1000);

	const authID = await createAuthID(cmdKey, timestamp);
	assert.equal(authID.length, 16);

	const decoded = await decodeAuthID(authID, cmdKey);
	assert.notEqual(decoded, null);
	assert.equal(decoded.timestamp, timestamp);
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
