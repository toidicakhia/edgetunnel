// SS AEAD encrypt/decrypt roundtrip test
// Verifies the crypto functions used by the Shadowsocks handler work correctly
import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
	SSDeriveMasterKey,
	SSDeriveSessionKey,
	SSAEADEncrypt,
	SSAEADDecrypt,
	SS_SUPPORTED_CIPHERS,
	SS_AEAD_TAG_LENGTH,
} from '../src/core/protocol.js';

const TEST_PASSWORD = 'test-uuid-1234-5678';

describe('SS AEAD Crypto', () => {
	for (const [method, config] of Object.entries(SS_SUPPORTED_CIPHERS)) {
		it(`derives keys and roundtrips for ${method}`, async () => {
			const masterKey = await SSDeriveMasterKey(TEST_PASSWORD, config.keyLen);
			assert.ok(masterKey instanceof Uint8Array);
			assert.strictEqual(masterKey.byteLength, config.keyLen);

			// Client side: derive decrypt key with random salt
			const clientSalt = crypto.getRandomValues(new Uint8Array(config.saltLen));
			const clientKey = await SSDeriveSessionKey(config, masterKey, clientSalt, ['decrypt']);
			assert.ok(clientKey);

			// Server side: derive encrypt key with another random salt
			const serverSalt = crypto.getRandomValues(new Uint8Array(config.saltLen));
			const serverKey = await SSDeriveSessionKey(config, masterKey, serverSalt, ['encrypt']);
			assert.ok(serverKey);

			// Simulate SS AEAD framing: length (2 bytes) + payload
			const plaintext = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"

			// Server encrypts response
			const lengthPlain = new Uint8Array(2);
			lengthPlain[0] = (plaintext.byteLength >>> 8) & 0xff;
			lengthPlain[1] = plaintext.byteLength & 0xff;

			// Use fixed nonces for test
			const clientNonce0 = new Uint8Array(12); // length nonce = 0
			const clientNonce1 = new Uint8Array(12); // payload nonce = 1 after increment

			// Actually SSAEADEncrypt increments the nonce, so we need to use the correct sequence
			const encNonce = new Uint8Array(12); // start at 0
			const lengthCipher = await SSAEADEncrypt(serverKey, encNonce, lengthPlain);
			assert.strictEqual(lengthCipher.byteLength, 2 + SS_AEAD_TAG_LENGTH);

			const payloadCipher = await SSAEADEncrypt(serverKey, encNonce, plaintext);
			assert.strictEqual(payloadCipher.byteLength, plaintext.byteLength + SS_AEAD_TAG_LENGTH);

			// Server sends: serverSalt + lengthCipher + payloadCipher
			// Client receives and decrypts

			// Client derives decrypt key with server's salt
			const clientDecryptKey = await SSDeriveSessionKey(config, masterKey, serverSalt, ['decrypt']);

			// Client decrypts: nonce starts at 0 for length
			const decNonce = new Uint8Array(12);
			const decLengthPlain = await SSAEADDecrypt(clientDecryptKey, decNonce, lengthCipher);
			assert.strictEqual(decLengthPlain.byteLength, 2);
			const decPayloadLen = (decLengthPlain[0] << 8) | decLengthPlain[1];
			assert.strictEqual(decPayloadLen, plaintext.byteLength);

			// Client decrypts payload with nonce=1
			const decPayloadPlain = await SSAEADDecrypt(clientDecryptKey, decNonce, payloadCipher);
			assert.deepStrictEqual(new Uint8Array(decPayloadPlain), plaintext);
		});
	}
});