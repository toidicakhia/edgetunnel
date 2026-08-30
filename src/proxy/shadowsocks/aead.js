/**
 * src/proxy/shadowsocks/aead.js
 * Shadowsocks AEAD-2020 engine — moved from src/core/protocol.js
 * (rewrite by Xray-core layout). Matches proxy/shadowsocks AEAD_2020.
 *
 * TCP: [IV][2B masked size + tag][payload + tag]…, session key =
 * HKDF-SHA1(masterKey, salt=IV, info='ss-subkey').
 * UDP: [IV][addr + port][single AEAD seal of payload].
 */

import { concatByteData } from '../../utils/helpers.js';
import { pureMD5Bytes } from '../../utils/crypto.js';

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

/** Increment a 12-byte AEAD nonce counter in place (Xray SSIncrementNonceCounter). */
export function SSIncrementNonceCounter(counter) {
	for (let i = 0; i < counter.length; i++) {
		counter[i] = (counter[i] + 1) & 0xff;
		if (counter[i] !== 0) return;
	}
}

/** EVP_BytesToKey MD5 master key derivation (Xray SSDeriveMasterKey). */
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

/** HKDF-SHA1 session key derivation, info 'ss-subkey' (Xray SSDeriveSessionKey). */
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

/** AEAD seal; nonce counter increments after use. */
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

/** AEAD open; nonce counter increments after use. */
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
