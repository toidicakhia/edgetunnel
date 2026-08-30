import test from 'node:test';
import assert from 'node:assert/strict';
import { pureMD5, MD5MD5, sha224, base64SecretEncode, base64SecretDecode } from '../src/utils/crypto.js';

test('pureMD5 generates correct 32-character hex hash', () => {
	const hash = pureMD5('hello world');
	assert.equal(hash, '5eb63bbbe01eeed093cb22bb8f5acdc3');
});

test('MD5MD5 produces double MD5 slice hash', async () => {
	const hash = await MD5MD5('test-secret');
	assert.equal(typeof hash, 'string');
	assert.equal(hash.length, 32);
});

test('sha224 produces 56-character hex hash', () => {
	const hash = sha224('password123');
	assert.equal(typeof hash, 'string');
	assert.equal(hash.length, 56);
	assert.equal(hash, '3d45597256050bb1e93bd9c10aee4c8716f8774f5a48c995bf0cf860');
});

test('base64SecretEncode and base64SecretDecode roundtrip correctly', () => {
	const secret = 'my-secret-key-12345';
	const plaintext = JSON.stringify({ type: 'socks5', hostname: '1.2.3.4', port: 1080 });
	
	const encoded = base64SecretEncode(plaintext, secret);
	assert.equal(typeof encoded, 'string');
	assert.notEqual(encoded, plaintext);

	const decoded = base64SecretDecode(encoded, secret);
	assert.equal(decoded, plaintext);
	assert.deepEqual(JSON.parse(decoded), { type: 'socks5', hostname: '1.2.3.4', port: 1080 });
});
