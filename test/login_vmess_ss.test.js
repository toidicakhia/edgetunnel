import test from 'node:test';
import assert from 'node:assert/strict';
import {
	getCmdKey,
	createAuthID,
	vmessKDF,
	vmessKDF16,
	fnv1a,
	parseVMessRequest,
	KDFSaltConstVMessHeaderPayloadLengthAEADKey,
	KDFSaltConstVMessHeaderPayloadLengthAEADIV,
	KDFSaltConstVMessHeaderPayloadAEADKey,
	KDFSaltConstVMessHeaderPayloadAEADIV,
} from '../src/core/vmess.js';
import {
	SS_SUPPORTED_CIPHERS,
	SS_NONCE_LENGTH,
	SSDeriveMasterKey,
	SSDeriveSessionKey,
	SSAEADEncrypt,
	SSAEADDecrypt,
} from '../src/core/protocol.js';

// Helper to encrypt with AES-GCM
async function aesGcmEncrypt(keyBytes, nonce12, plaintext, ad) {
	const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
	const ct = await crypto.subtle.encrypt(
		{ name: 'AES-GCM', iv: nonce12, additionalData: ad || new Uint8Array(0), tagLength: 128 },
		key,
		plaintext
	);
	return new Uint8Array(ct);
}

test('VMess AEAD: Full Handshake & Authentication (Login) Verification', async () => {
	const uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4';
	const cmdKey = await getCmdKey(uuid);
	const nowSec = Math.floor(Date.now() / 1000);

	// 1. Client creates 16-byte AuthID
	const authID = await createAuthID(cmdKey, nowSec);
	assert.equal(authID.length, 16);

	// 2. Client prepares inner header (version 1, bodyIV 16B, bodyKey 16B, respHeader 1B, opt 1B, sec 1B, reserved 1B, cmd 1B, port 2B, atype 1B, ip 4B, fnv 4B)
	const bodyIV = crypto.getRandomValues(new Uint8Array(16));
	const bodyKey = crypto.getRandomValues(new Uint8Array(16));
	const port = 8080;
	const ip = [192, 168, 1, 100];

	// Construct plaintext inner header
	const innerLen = 1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + 4 + 4; // 49 bytes
	const innerHeader = new Uint8Array(innerLen);
	let offset = 0;
	innerHeader[offset++] = 1; // version 1
	innerHeader.set(bodyIV, offset); offset += 16;
	innerHeader.set(bodyKey, offset); offset += 16;
	innerHeader[offset++] = 0x55; // response header
	innerHeader[offset++] = 0x01; // option ChunkStream
	innerHeader[offset++] = (0 << 4) | 3; // paddingLen 0, security 3 (AES-128-GCM)
	innerHeader[offset++] = 0; // reserved
	innerHeader[offset++] = 1; // cmd TCP (1)
	innerHeader[offset++] = (port >>> 8) & 0xff;
	innerHeader[offset++] = port & 0xff;
	innerHeader[offset++] = 1; // atype IPv4 (1)
	innerHeader.set(ip, offset); offset += 4;

	// Calculate and append FNV1a checksum
	const hash = fnv1a(innerHeader.slice(0, offset));
	innerHeader[offset++] = (hash >>> 24) & 0xff;
	innerHeader[offset++] = (hash >>> 16) & 0xff;
	innerHeader[offset++] = (hash >>> 8) & 0xff;
	innerHeader[offset++] = hash & 0xff;

	// 3. Encrypt outer length (2 bytes + 16 bytes tag) and inner header
	const nonce = crypto.getRandomValues(new Uint8Array(8));
	const lenKey = await vmessKDF16(cmdKey, KDFSaltConstVMessHeaderPayloadLengthAEADKey, authID, nonce);
	const lenNonce = (await vmessKDF(cmdKey, KDFSaltConstVMessHeaderPayloadLengthAEADIV, authID, nonce)).slice(0, 12);
	const lenPlain = new Uint8Array([(innerHeader.length >>> 8) & 0xff, innerHeader.length & 0xff]);
	const encryptedLen = await aesGcmEncrypt(lenKey, lenNonce, lenPlain, authID);

	const headerKey = await vmessKDF16(cmdKey, KDFSaltConstVMessHeaderPayloadAEADKey, authID, nonce);
	const headerNonce = (await vmessKDF(cmdKey, KDFSaltConstVMessHeaderPayloadAEADIV, authID, nonce)).slice(0, 12);
	const encryptedHeader = await aesGcmEncrypt(headerKey, headerNonce, innerHeader, authID);

	// 4. Assemble full VMess AEAD request packet: AuthID (16) + EncryptedLen (18) + Nonce (8) + EncryptedHeader (innerLen + 16)
	const fullPacket = new Uint8Array(authID.length + encryptedLen.length + nonce.length + encryptedHeader.length);
	let pOffset = 0;
	fullPacket.set(authID, pOffset); pOffset += authID.length;
	fullPacket.set(encryptedLen, pOffset); pOffset += encryptedLen.length;
	fullPacket.set(nonce, pOffset); pOffset += nonce.length;
	fullPacket.set(encryptedHeader, pOffset);

	// 5. Server parses and authenticates (logins) request using UUID
	const serverParse = await parseVMessRequest(fullPacket, uuid);
	assert.equal(serverParse.hasError, false, `VMess parse failed: ${serverParse.message}`);
	assert.equal(serverParse.hostname, '192.168.1.100');
	assert.equal(serverParse.port, 8080);
	assert.equal(serverParse.isUDP, false);
	assert.equal(serverParse.security, 'aes-128-gcm');
	assert.equal(serverParse.responseHeader, 0x55);
	assert.deepEqual(Array.from(serverParse.bodyKey), Array.from(bodyKey));
	assert.deepEqual(Array.from(serverParse.bodyIV), Array.from(bodyIV));

	// 6. Test wrong UUID fails authentication
	const wrongUUID = '00000000-0000-0000-0000-000000000000';
	const serverParseWrong = await parseVMessRequest(fullPacket, wrongUUID);
	assert.equal(serverParseWrong.hasError, true);
});

test('Shadowsocks AEAD: Full Handshake & Authentication (Login) Verification', async () => {
	const password = 'd342d11e-d424-4583-b36e-524ab1f0afa4'; // Using UUID as password
	const cipherConfig = SS_SUPPORTED_CIPHERS['aes-128-gcm'];

	// 1. Client derives Master Key
	const clientMasterKey = await SSDeriveMasterKey(password, cipherConfig.keyLen);
	assert.equal(clientMasterKey.length, 16);

	// 2. Client generates Salt & derives Session Key
	const salt = crypto.getRandomValues(new Uint8Array(cipherConfig.saltLen));
	const clientSessionKey = await SSDeriveSessionKey(cipherConfig, clientMasterKey, salt, ['encrypt']);

	// 3. Client constructs SOCKS5 target header (atype 1 = IPv4: 1.1.1.1, port: 443) + HTTP GET payload
	const targetPayload = new Uint8Array([
		1, 1, 1, 1, 1, // atype 1 (IPv4), 1.1.1.1
		0x01, 0xbb,    // port 443 (BE)
		0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, // "GET / "
	]);

	// 4. Client encrypts length chunk (2 bytes + 16 bytes tag) & payload chunk (targetPayload.length + 16 bytes tag)
	const clientNonce = new Uint8Array(SS_NONCE_LENGTH);
	const lengthPlain = new Uint8Array([(targetPayload.length >>> 8) & 0xff, targetPayload.length & 0xff]);
	const encryptedLength = await SSAEADEncrypt(clientSessionKey, clientNonce, lengthPlain);
	const encryptedPayload = await SSAEADEncrypt(clientSessionKey, clientNonce, targetPayload);

	// Assemble client packet: salt + encryptedLength + encryptedPayload
	const packet = new Uint8Array(salt.length + encryptedLength.length + encryptedPayload.length);
	packet.set(salt, 0);
	packet.set(encryptedLength, salt.length);
	packet.set(encryptedPayload, salt.length + encryptedLength.length);

	// 5. Server side handshake & authentication
	// Server extracts salt and derives server session key from password
	const receivedSalt = packet.subarray(0, cipherConfig.saltLen);
	const serverMasterKey = await SSDeriveMasterKey(password, cipherConfig.keyLen);
	const serverSessionKey = await SSDeriveSessionKey(cipherConfig, serverMasterKey, receivedSalt, ['decrypt']);

	// Server decrypts 2-byte length
	const serverNonce = new Uint8Array(SS_NONCE_LENGTH);
	const receivedEncLength = packet.subarray(cipherConfig.saltLen, cipherConfig.saltLen + 2 + 16);
	const decryptedLengthBytes = await SSAEADDecrypt(serverSessionKey, serverNonce, receivedEncLength);
	const expectedLength = (decryptedLengthBytes[0] << 8) | decryptedLengthBytes[1];
	assert.equal(expectedLength, targetPayload.length);

	// Server decrypts payload
	const receivedEncPayload = packet.subarray(cipherConfig.saltLen + 2 + 16);
	const decryptedPayload = await SSAEADDecrypt(serverSessionKey, serverNonce, receivedEncPayload);
	assert.deepEqual(Array.from(decryptedPayload), Array.from(targetPayload));

	// Server parses destination from decrypted payload
	const atype = decryptedPayload[0];
	assert.equal(atype, 1);
	const host = `${decryptedPayload[1]}.${decryptedPayload[2]}.${decryptedPayload[3]}.${decryptedPayload[4]}`;
	const port = (decryptedPayload[5] << 8) | decryptedPayload[6];
	const initialData = decryptedPayload.subarray(7);

	assert.equal(host, '1.1.1.1');
	assert.equal(port, 443);
	assert.equal(new TextDecoder().decode(initialData), 'GET / ');

	// 6. Test wrong password fails authentication
	const wrongPassword = 'incorrect-password-123';
	const wrongMasterKey = await SSDeriveMasterKey(wrongPassword, cipherConfig.keyLen);
	const wrongSessionKey = await SSDeriveSessionKey(cipherConfig, wrongMasterKey, receivedSalt, ['decrypt']);
	const wrongNonce = new Uint8Array(SS_NONCE_LENGTH);

	await assert.rejects(async () => {
		await SSAEADDecrypt(wrongSessionKey, wrongNonce, receivedEncLength);
	}, /operation failed|tag mismatch|decryption failed/i);
});
