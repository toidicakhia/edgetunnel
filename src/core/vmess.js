/**
 * src/core/vmess.js
 * VMess AEAD (alterId=0) implementation for Cloudflare Workers.
 * Follows Xray-core / v2ray-core spec: https://xtls.github.io/en/development/protocols/vmess.html
 * Covers AuthID, KDF, AEAD header (outer) and inner command header, plus body chunk handling.
 */

import { concatByteData, toUint8Array } from '../utils/helpers.js';
import { getUUIDBytes } from './protocol.js';
import { pureMD5Bytes } from '../utils/crypto.js';

// -----------------------------------------------------------------------------
// Constants (matching Xray-core proxy/vmess/aead/consts.go)
// -----------------------------------------------------------------------------
export const KDFSaltConstAuthIDEncryptionKey = 'AES Auth ID Encryption';
export const KDFSaltConstAEADRespHeaderLenKey = 'AEAD Resp Header Len Key';
export const KDFSaltConstAEADRespHeaderLenIV = 'AEAD Resp Header Len IV';
export const KDFSaltConstAEADRespHeaderPayloadKey = 'AEAD Resp Header Key';
export const KDFSaltConstAEADRespHeaderPayloadIV = 'AEAD Resp Header IV';
export const KDFSaltConstVMessAEADKDF = 'VMess AEAD KDF';
export const KDFSaltConstVMessHeaderPayloadAEADKey = 'VMess Header AEAD Key';
export const KDFSaltConstVMessHeaderPayloadAEADIV = 'VMess Header AEAD Nonce';
export const KDFSaltConstVMessHeaderPayloadLengthAEADKey = 'VMess Header AEAD Key_Length';
export const KDFSaltConstVMessHeaderPayloadLengthAEADIV = 'VMess Header AEAD Nonce_Length';

const CMD_KEY_SALT = 'c48619fe-8f02-49e0-b9e9-edf763e17e21';

// -----------------------------------------------------------------------------
// Pure JS SHA-256 with incremental hashing support
// -----------------------------------------------------------------------------
export class PureSha256 {
	constructor() {
		this.K = new Uint32Array([
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
		]);
		this.h = new Uint32Array([
			0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
			0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
		]);
		this.buf = new Uint8Array(64);
		this.bufLen = 0;
		this.totalLen = 0;
		this.W = new Uint32Array(64);
	}

	_processBlock(b) {
		const W = this.W;
		for (let i = 0; i < 16; i++) {
			W[i] = (b[i * 4] << 24) | (b[i * 4 + 1] << 16) | (b[i * 4 + 2] << 8) | b[i * 4 + 3];
		}
		for (let i = 16; i < 64; i++) {
			const v0 = W[i - 15];
			const s0 = ((v0 >>> 7) | (v0 << 25)) ^ ((v0 >>> 18) | (v0 << 14)) ^ (v0 >>> 3);
			const v1 = W[i - 2];
			const s1 = ((v1 >>> 17) | (v1 << 15)) ^ ((v1 >>> 19) | (v1 << 13)) ^ (v1 >>> 10);
			W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
		}
		let [a, b0, c, d, e, f, g, h0] = this.h;
		const K = this.K;
		for (let i = 0; i < 64; i++) {
			const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
			const ch = (e & f) ^ (~e & g);
			const t1 = (h0 + S1 + ch + K[i] + W[i]) >>> 0;
			const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
			const maj = (a & b0) ^ (a & c) ^ (b0 & c);
			const t2 = (S0 + maj) >>> 0;
			h0 = g;
			g = f;
			f = e;
			e = (d + t1) >>> 0;
			d = c;
			c = b0;
			b0 = a;
			a = (t1 + t2) >>> 0;
		}
		this.h[0] = (this.h[0] + a) >>> 0;
		this.h[1] = (this.h[1] + b0) >>> 0;
		this.h[2] = (this.h[2] + c) >>> 0;
		this.h[3] = (this.h[3] + d) >>> 0;
		this.h[4] = (this.h[4] + e) >>> 0;
		this.h[5] = (this.h[5] + f) >>> 0;
		this.h[6] = (this.h[6] + g) >>> 0;
		this.h[7] = (this.h[7] + h0) >>> 0;
	}

	update(data) {
		const bytes = data instanceof Uint8Array ? data : (typeof data === 'string' ? new TextEncoder().encode(data) : new Uint8Array(data));
		this.totalLen += bytes.length;
		let offset = 0;
		while (offset < bytes.length) {
			if (this.bufLen === 0 && bytes.length - offset >= 64) {
				this._processBlock(bytes.subarray(offset, offset + 64));
				offset += 64;
			} else {
				const toCopy = Math.min(64 - this.bufLen, bytes.length - offset);
				this.buf.set(bytes.subarray(offset, offset + toCopy), this.bufLen);
				this.bufLen += toCopy;
				offset += toCopy;
				if (this.bufLen === 64) {
					this._processBlock(this.buf);
					this.bufLen = 0;
				}
			}
		}
		return this;
	}

	digest() {
		const totalBits = this.totalLen * 8;
		this.buf[this.bufLen++] = 0x80;
		if (this.bufLen > 56) {
			this.buf.fill(0, this.bufLen);
			this._processBlock(this.buf);
			this.bufLen = 0;
		}
		this.buf.fill(0, this.bufLen, 56);
		const hi = Math.floor(totalBits / 0x100000000);
		const lo = totalBits >>> 0;
		const view = new DataView(this.buf.buffer, this.buf.byteOffset, this.buf.byteLength);
		view.setUint32(56, hi, false);
		view.setUint32(60, lo, false);
		this._processBlock(this.buf);

		const out = new Uint8Array(32);
		const outView = new DataView(out.buffer);
		for (let i = 0; i < 8; i++) {
			outView.setUint32(i * 4, this.h[i], false);
		}
		return out;
	}
}

// -----------------------------------------------------------------------------
// Recursive HMAC for VMess KDF (matching Xray-core proxy/vmess/aead/kdf.go)
// -----------------------------------------------------------------------------
class HMac {
	constructor(hasherCreator, key) {
		this.hasherCreator = hasherCreator;
		let k = key instanceof Uint8Array ? key : new TextEncoder().encode(String(key));
		const blockSize = 64;
		if (k.length > blockSize) {
			const h = hasherCreator();
			h.update(k);
			k = h.digest();
		}
		this.ipad = new Uint8Array(blockSize);
		this.opad = new Uint8Array(blockSize);
		for (let i = 0; i < blockSize; i++) {
			this.ipad[i] = 0x36;
			this.opad[i] = 0x5c;
		}
		for (let i = 0; i < k.length; i++) {
			this.ipad[i] ^= k[i];
			this.opad[i] ^= k[i];
		}
		this.inner = hasherCreator();
		this.inner.update(this.ipad);
	}
	update(data) {
		this.inner.update(data);
		return this;
	}
	digest() {
		const innerHash = this.inner.digest();
		const outer = this.hasherCreator();
		outer.update(this.opad);
		outer.update(innerHash);
		return outer.digest();
	}
}

const _vmessKDFSaltBytes = new TextEncoder().encode(KDFSaltConstVMessAEADKDF);
const _cmdKeySaltBytes = new TextEncoder().encode(CMD_KEY_SALT);

/**
 * KDF as per Xray-core proxy/vmess/aead/kdf.go
 * Recursively creates nested HMAC structures.
 */
export function vmessKDF(keyBytes, ...paths) {
	let creator = function () {
		return new HMac(() => new PureSha256(), _vmessKDFSaltBytes);
	};
	for (const p of paths) {
		const pBytes = p instanceof Uint8Array ? p : new TextEncoder().encode(String(p));
		const parent = creator;
		creator = function () {
			return new HMac(parent, pBytes);
		};
	}
	const hmac = creator();
	const kBytes = keyBytes instanceof Uint8Array ? keyBytes : new TextEncoder().encode(String(keyBytes));
	hmac.update(kBytes);
	return hmac.digest();
}

export function vmessKDF16(keyBytes, ...paths) {
	return vmessKDF(keyBytes, ...paths).slice(0, 16);
}

export function getCmdKey(uuidStr) {
	// CmdKey = MD5(UUID bytes + 'c48619fe-8f02-49e0-b9e9-edf763e17e21')
	const uuidBytes = getUUIDBytes(uuidStr);
	if (!uuidBytes) throw new Error('Invalid UUID for CmdKey');
	const combined = new Uint8Array(uuidBytes.length + _cmdKeySaltBytes.length);
	combined.set(uuidBytes, 0);
	combined.set(_cmdKeySaltBytes, uuidBytes.length);
	return pureMD5Bytes(combined);
}

// -----------------------------------------------------------------------------
// CRC32 & FNV1a Checksums
// -----------------------------------------------------------------------------
const crc32Table = (() => {
	const table = new Uint32Array(256);
	for (let i = 0; i < 256; i++) {
		let c = i;
		for (let j = 0; j < 8; j++) {
			c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
		}
		table[i] = c;
	}
	return table;
})();

export function crc32(data) {
	let crc = 0xffffffff;
	for (let i = 0; i < data.length; i++) {
		crc = crc32Table[(crc ^ data[i]) & 0xff] ^ (crc >>> 8);
	}
	return (crc ^ 0xffffffff) >>> 0;
}

export function fnv1a(data) {
	let hash = 0x811c9dc5;
	for (let i = 0; i < data.length; i++) {
		hash ^= data[i];
		hash = Math.imul(hash, 0x01000193) >>> 0;
	}
	return hash >>> 0;
}

// -----------------------------------------------------------------------------
// AES Helpers (WebCrypto AES-GCM + Pure JS AES-128 ECB)
// -----------------------------------------------------------------------------
const _aesKeyCache = new Map();

async function _importAesKey(keyBytes, usage) {
	const cacheKey = `${keyBytes.length}:${Array.from(keyBytes).join(',')}:${usage}`;
	let entry = _aesKeyCache.get(cacheKey);
	if (entry) return entry;
	entry = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, [usage]);
	if (_aesKeyCache.size > 256) _aesKeyCache.clear();
	_aesKeyCache.set(cacheKey, entry);
	return entry;
}

async function aesGcmEncrypt(keyBytes, nonce12, plaintext, ad) {
	const key = await _importAesKey(keyBytes, 'encrypt');
	const algo = {
		name: 'AES-GCM',
		iv: nonce12,
		additionalData: ad || new Uint8Array(0),
		tagLength: 128,
	};
	const ct = await crypto.subtle.encrypt(algo, key, plaintext);
	return new Uint8Array(ct);
}

async function aesGcmDecrypt(keyBytes, nonce12, ciphertext, ad) {
	const key = await _importAesKey(keyBytes, 'decrypt');
	const algo = {
		name: 'AES-GCM',
		iv: nonce12,
		additionalData: ad || new Uint8Array(0),
		tagLength: 128,
	};
	const pt = await crypto.subtle.decrypt(algo, key, ciphertext);
	return new Uint8Array(pt);
}

let aesSBox, aesInvSBox, aesRcon;
function initAESSBox() {
	if (aesSBox) return;
	aesSBox = new Uint8Array([
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
		0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
		0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
		0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
		0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
		0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
		0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
		0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
		0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
		0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
		0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
		0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
		0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
		0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
		0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
		0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
		0x16,
	]);
	aesInvSBox = new Uint8Array(256);
	for (let i = 0; i < 256; i++) aesInvSBox[aesSBox[i]] = i;
	aesRcon = new Uint8Array([0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]);
}

function aesKeyExpansion(key) {
	initAESSBox();
	const Nk = 4,
		Nr = 10,
		Nb = 4;
	const w = new Uint32Array(Nb * (Nr + 1));
	for (let i = 0; i < Nk; i++)
		w[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
	for (let i = Nk; i < Nb * (Nr + 1); i++) {
		let temp = w[i - 1];
		if (i % Nk === 0) {
			temp =
				(aesSBox[(temp >>> 16) & 0xff] << 24) |
				(aesSBox[(temp >>> 8) & 0xff] << 16) |
				(aesSBox[temp & 0xff] << 8) |
				aesSBox[(temp >>> 24) & 0xff];
			temp ^= aesRcon[i / Nk] << 24;
		}
		w[i] = w[i - Nk] ^ temp;
	}
	return w;
}

function aesAddRoundKey(state, w, round) {
	for (let c = 0; c < 4; c++) {
		const word = w[round * 4 + c];
		state[c * 4] ^= (word >>> 24) & 0xff;
		state[c * 4 + 1] ^= (word >>> 16) & 0xff;
		state[c * 4 + 2] ^= (word >>> 8) & 0xff;
		state[c * 4 + 3] ^= word & 0xff;
	}
}

function aesSubBytes(state) {
	for (let i = 0; i < 16; i++) state[i] = aesSBox[state[i]];
}
function aesInvSubBytes(state) {
	for (let i = 0; i < 16; i++) state[i] = aesInvSBox[state[i]];
}
function aesShiftRows(state) {
	const t = new Uint8Array(16);
	t[0] = state[0];
	t[1] = state[5];
	t[2] = state[10];
	t[3] = state[15];
	t[4] = state[4];
	t[5] = state[9];
	t[6] = state[14];
	t[7] = state[3];
	t[8] = state[8];
	t[9] = state[13];
	t[10] = state[2];
	t[11] = state[7];
	t[12] = state[12];
	t[13] = state[1];
	t[14] = state[6];
	t[15] = state[11];
	state.set(t);
}
function aesInvShiftRows(state) {
	const t = new Uint8Array(16);
	t[0] = state[0];
	t[1] = state[13];
	t[2] = state[10];
	t[3] = state[7];
	t[4] = state[4];
	t[5] = state[1];
	t[6] = state[14];
	t[7] = state[11];
	t[8] = state[8];
	t[9] = state[5];
	t[10] = state[2];
	t[11] = state[15];
	t[12] = state[12];
	t[13] = state[9];
	t[14] = state[6];
	t[15] = state[3];
	state.set(t);
}
function xtime(a) {
	return (a << 1) ^ ((a >>> 7) & 1 ? 0x1b : 0);
}
function aesMixColumns(state) {
	for (let c = 0; c < 4; c++) {
		const i = c * 4;
		const a0 = state[i],
			a1 = state[i + 1],
			a2 = state[i + 2],
			a3 = state[i + 3];
		const t = a0 ^ a1 ^ a2 ^ a3;
		const u = a0;
		state[i] ^= t ^ xtime(a0 ^ a1);
		state[i + 1] ^= t ^ xtime(a1 ^ a2);
		state[i + 2] ^= t ^ xtime(a2 ^ a3);
		state[i + 3] ^= t ^ xtime(a3 ^ u);
	}
}
function aesInvMixColumns(state) {
	for (let c = 0; c < 4; c++) {
		const i = c * 4;
		const a0 = state[i],
			a1 = state[i + 1],
			a2 = state[i + 2],
			a3 = state[i + 3];
		const b0 = 0x0e,
			b1 = 0x09,
			b2 = 0x0d,
			b3 = 0x0b;
		const mul = (a, b) => {
			let p = 0;
			for (let j = 0; j < 8; j++) {
				if (b & 1) p ^= a;
				const hi = a & 0x80;
				a = (a << 1) & 0xff;
				if (hi) a ^= 0x1b;
				b >>>= 1;
			}
			return p;
		};
		const s0 = mul(a0, b0) ^ mul(a1, b3) ^ mul(a2, b2) ^ mul(a3, b1);
		const s1 = mul(a0, b1) ^ mul(a1, b0) ^ mul(a2, b3) ^ mul(a3, b2);
		const s2 = mul(a0, b2) ^ mul(a1, b1) ^ mul(a2, b0) ^ mul(a3, b3);
		const s3 = mul(a0, b3) ^ mul(a1, b2) ^ mul(a2, b1) ^ mul(a3, b0);
		state[i] = s0;
		state[i + 1] = s1;
		state[i + 2] = s2;
		state[i + 3] = s3;
	}
}

function aesEncryptBlock(key, plaintext) {
	initAESSBox();
	const w = aesKeyExpansion(key);
	const state = new Uint8Array(plaintext);
	aesAddRoundKey(state, w, 0);
	for (let round = 1; round < 10; round++) {
		aesSubBytes(state);
		aesShiftRows(state);
		aesMixColumns(state);
		aesAddRoundKey(state, w, round);
	}
	aesSubBytes(state);
	aesShiftRows(state);
	aesAddRoundKey(state, w, 10);
	return state;
}

function aesDecryptBlock(key, ciphertext) {
	initAESSBox();
	const w = aesKeyExpansion(key);
	const state = new Uint8Array(ciphertext);
	aesAddRoundKey(state, w, 10);
	for (let round = 9; round >= 1; round--) {
		aesInvShiftRows(state);
		aesInvSubBytes(state);
		aesAddRoundKey(state, w, round);
		aesInvMixColumns(state);
	}
	aesInvShiftRows(state);
	aesInvSubBytes(state);
	aesAddRoundKey(state, w, 0);
	return state;
}

function aesEcbEncryptPureJS(key16, plaintext16) {
	return aesEncryptBlock(key16, plaintext16);
}
function aesEcbDecryptPureJS(key16, ciphertext16) {
	return aesDecryptBlock(key16, ciphertext16);
}

// -----------------------------------------------------------------------------
// SHAKE-128 / Keccak Sponge Implementation for Chunk Masking & Padding
// -----------------------------------------------------------------------------
const KECCAK_RC = [
	0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
	0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
	0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
	0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
	0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
	0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

const KECCAK_RHO = [
	0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

const KECCAK_PI = [
	0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4,
];

function rotl64(x, n) {
	const bn = BigInt(n);
	return ((x << bn) | (x >> (64n - bn))) & 0xffffffffffffffffn;
}

export class Shake128 {
	constructor() {
		this.state = new BigUint64Array(25);
		this.rate = 168; // 1344 bits / 8
		this.buf = new Uint8Array(this.rate);
		this.bufLen = 0;
		this.squeezed = false;
		this.squeezeOffset = 0;
	}

	_keccakF() {
		const s = this.state;
		const view = new DataView(this.buf.buffer, this.buf.byteOffset, this.buf.byteLength);
		for (let i = 0; i < this.rate / 8; i++) {
			s[i] ^= view.getBigUint64(i * 8, true);
		}
		this.buf.fill(0);
		this.bufLen = 0;

		const C = new BigUint64Array(5);
		const D = new BigUint64Array(5);
		const B = new BigUint64Array(25);

		for (let round = 0; round < 24; round++) {
			for (let x = 0; x < 5; x++) {
				C[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
			}
			for (let x = 0; x < 5; x++) {
				D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
			}
			for (let i = 0; i < 25; i++) {
				s[i] ^= D[i % 5];
			}
			for (let i = 0; i < 25; i++) {
				B[KECCAK_PI[i]] = rotl64(s[i], KECCAK_RHO[i]);
			}
			for (let y = 0; y < 5; y++) {
				const y5 = y * 5;
				for (let x = 0; x < 5; x++) {
					s[y5 + x] = B[y5 + x] ^ ((~B[y5 + ((x + 1) % 5)]) & B[y5 + ((x + 2) % 5)]);
				}
			}
			s[0] ^= KECCAK_RC[round];
		}
	}

	update(data) {
		const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
		for (let i = 0; i < bytes.length; i++) {
			this.buf[this.bufLen++] = bytes[i];
			if (this.bufLen === this.rate) {
				this._keccakF();
			}
		}
		return this;
	}

	_finalize() {
		if (this.squeezed) return;
		this.buf[this.bufLen] ^= 0x1f; // SHAKE-128 domain suffix
		this.buf[this.rate - 1] ^= 0x80;
		this._keccakF();
		this.squeezed = true;
		this._fillSqueezeBuf();
	}

	_fillSqueezeBuf() {
		const view = new DataView(this.buf.buffer, this.buf.byteOffset, this.buf.byteLength);
		for (let i = 0; i < this.rate / 8; i++) {
			view.setBigUint64(i * 8, this.state[i], true);
		}
		this.squeezeOffset = 0;
	}

	read(outLen) {
		this._finalize();
		const out = new Uint8Array(outLen);
		let outOffset = 0;
		while (outOffset < outLen) {
			if (this.squeezeOffset >= this.rate) {
				const C = new BigUint64Array(5);
				const D = new BigUint64Array(5);
				const B = new BigUint64Array(25);
				const s = this.state;
				for (let round = 0; round < 24; round++) {
					for (let x = 0; x < 5; x++) C[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
					for (let x = 0; x < 5; x++) D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
					for (let i = 0; i < 25; i++) s[i] ^= D[i % 5];
					for (let i = 0; i < 25; i++) B[KECCAK_PI[i]] = rotl64(s[i], KECCAK_RHO[i]);
					for (let y = 0; y < 5; y++) {
						const y5 = y * 5;
						for (let x = 0; x < 5; x++) s[y5 + x] = B[y5 + x] ^ ((~B[y5 + ((x + 1) % 5)]) & B[y5 + ((x + 2) % 5)]);
					}
					s[0] ^= KECCAK_RC[round];
				}
				this._fillSqueezeBuf();
			}
			const toCopy = Math.min(outLen - outOffset, this.rate - this.squeezeOffset);
			out.set(this.buf.subarray(this.squeezeOffset, this.squeezeOffset + toCopy), outOffset);
			this.squeezeOffset += toCopy;
			outOffset += toCopy;
		}
		return out;
	}
}

export class ShakeSizeParser {
	constructor(nonce) {
		this.shake = new Shake128();
		this.shake.update(nonce);
	}
	next() {
		const b = this.shake.read(2);
		return (b[0] << 8) | b[1];
	}
	decode(b) {
		const mask = this.next();
		const size = (b[0] << 8) | b[1];
		return mask ^ size;
	}
	encode(size) {
		const mask = this.next();
		const masked = mask ^ size;
		return new Uint8Array([(masked >>> 8) & 0xff, masked & 0xff]);
	}
	nextPaddingLen() {
		return this.next() % 64;
	}
}

// -----------------------------------------------------------------------------
// VMess AEAD AuthID & Headers
// -----------------------------------------------------------------------------

export function createAuthID(cmdKey, timeSec) {
	const buf = new ArrayBuffer(16);
	const view = new DataView(buf);
	view.setBigInt64(0, BigInt(timeSec), false); // BE
	const rand = crypto.getRandomValues(new Uint8Array(4));
	new Uint8Array(buf).set(rand, 8);
	const first12 = new Uint8Array(buf, 0, 12);
	const crc = crc32(first12);
	view.setUint32(12, crc, false);
	const key = vmessKDF16(cmdKey, KDFSaltConstAuthIDEncryptionKey);
	const encrypted = aesEcbEncryptPureJS(key, new Uint8Array(buf));
	return encrypted;
}

export function decodeAuthID(authID16, cmdKey) {
	const key = vmessKDF16(cmdKey, KDFSaltConstAuthIDEncryptionKey);
	const decrypted = aesEcbDecryptPureJS(key, authID16);
	const view = new DataView(decrypted.buffer, decrypted.byteOffset, decrypted.byteLength);
	const timeSec = Number(view.getBigInt64(0, false));
	const rand = decrypted.slice(8, 12);
	const crc = view.getUint32(12, false);
	const first12 = decrypted.slice(0, 12);
	const calcCrc = crc32(first12);
	if (calcCrc !== crc) return null;
	return { timeSec, timestamp: timeSec, rand, crc, raw: decrypted };
}

// Open VMess AEAD header (outer)
// Returns inner header bytes and consumed length, or null if not VMess
export async function openVMessAEADHeader(cmdKey, authID, readerOrBytes) {
	let data;
	if (readerOrBytes instanceof Uint8Array) {
		data = readerOrBytes;
	} else if (readerOrBytes && typeof readerOrBytes.read === 'function') {
		let buf = new Uint8Array(0);
		while (buf.length < 8192) {
			const { done, value } = await readerOrBytes.read();
			if (done) break;
			if (value) buf = concatByteData(buf, toUint8Array(value));
			if (buf.length >= 18 + 8) {
				try {
					const lenKey = vmessKDF16(
						cmdKey,
						KDFSaltConstVMessHeaderPayloadLengthAEADKey,
						authID,
						buf.slice(18, 26)
					);
					const lenNonce = vmessKDF(
						cmdKey,
						KDFSaltConstVMessHeaderPayloadLengthAEADIV,
						authID,
						buf.slice(18, 26)
					).slice(0, 12);
					const lenCt = buf.slice(0, 18);
					const lenPt = await aesGcmDecrypt(lenKey, lenNonce, lenCt, authID);
					const len = (lenPt[0] << 8) | lenPt[1];
					if (buf.length >= 18 + 8 + len + 16) break;
				} catch {
					/* not enough */
				}
			}
		}
		data = buf;
	} else {
		data = toUint8Array(readerOrBytes);
	}

	if (data.length < 18 + 8) return null;
	const encryptedLen = data.slice(0, 18);
	const nonce = data.slice(18, 26);
	const rest = data.slice(26);

	const lenKey = vmessKDF16(
		cmdKey,
		KDFSaltConstVMessHeaderPayloadLengthAEADKey,
		authID,
		nonce
	);
	const lenNonce = vmessKDF(
		cmdKey,
		KDFSaltConstVMessHeaderPayloadLengthAEADIV,
		authID,
		nonce
	).slice(0, 12);

	let lenPt;
	try {
		lenPt = await aesGcmDecrypt(lenKey, lenNonce, encryptedLen, authID);
	} catch {
		return null;
	}
	const headerLen = (lenPt[0] << 8) | lenPt[1];
	if (headerLen <= 0 || headerLen > 4096) return null;
	if (rest.length < headerLen + 16) return null;

	const encryptedHeader = rest.slice(0, headerLen + 16);
	const headerKey = vmessKDF16(
		cmdKey,
		KDFSaltConstVMessHeaderPayloadAEADKey,
		authID,
		nonce
	);
	const headerNonce = vmessKDF(
		cmdKey,
		KDFSaltConstVMessHeaderPayloadAEADIV,
		authID,
		nonce
	).slice(0, 12);

	let headerPt;
	try {
		headerPt = await aesGcmDecrypt(headerKey, headerNonce, encryptedHeader, authID);
	} catch {
		return null;
	}
	const consumed = 18 + 8 + headerLen + 16;
	const remaining = rest.slice(headerLen + 16);
	return { header: headerPt, remaining, consumed, nonce, authID };
}

/**
 * Seal VMess AEAD Header (matching Xray-core proxy/vmess/aead/encrypt.go SealVMessAEADHeader)
 */
export async function sealVMessAEADHeader(cmdKey, headerBytes, authID, nonce) {
	const finalAuthID = authID || createAuthID(cmdKey, Math.floor(Date.now() / 1000));
	const finalNonce = nonce || crypto.getRandomValues(new Uint8Array(8));
	const lenPlain = new Uint8Array([(headerBytes.length >>> 8) & 0xff, headerBytes.length & 0xff]);

	const lenKey = vmessKDF16(cmdKey, KDFSaltConstVMessHeaderPayloadLengthAEADKey, finalAuthID, finalNonce);
	const lenNonce = vmessKDF(cmdKey, KDFSaltConstVMessHeaderPayloadLengthAEADIV, finalAuthID, finalNonce).slice(0, 12);
	const encryptedLen = await aesGcmEncrypt(lenKey, lenNonce, lenPlain, finalAuthID);

	const headerKey = vmessKDF16(cmdKey, KDFSaltConstVMessHeaderPayloadAEADKey, finalAuthID, finalNonce);
	const headerNonce = vmessKDF(cmdKey, KDFSaltConstVMessHeaderPayloadAEADIV, finalAuthID, finalNonce).slice(0, 12);
	const encryptedHeader = await aesGcmEncrypt(headerKey, headerNonce, headerBytes, finalAuthID);

	const out = new Uint8Array(finalAuthID.length + encryptedLen.length + finalNonce.length + encryptedHeader.length);
	let offset = 0;
	out.set(finalAuthID, offset); offset += finalAuthID.length;
	out.set(encryptedLen, offset); offset += encryptedLen.length;
	out.set(finalNonce, offset); offset += finalNonce.length;
	out.set(encryptedHeader, offset);
	return out;
}

// Parse inner header (decrypted payload)
export function parseVMessInnerHeader(headerBytes) {
	if (headerBytes.length < 38) return null;
	let offset = 0;
	const version = headerBytes[offset];
	offset += 1;
	if (version !== 1) return null;
	const bodyIV = headerBytes.slice(offset, offset + 16);
	offset += 16;
	const bodyKey = headerBytes.slice(offset, offset + 16);
	offset += 16;
	const responseHeader = headerBytes[offset];
	offset += 1;
	const option = headerBytes[offset];
	offset += 1;
	const secByte = headerBytes[offset];
	offset += 1;
	const paddingLen = (secByte >> 4) & 0x0f;
	const security = secByte & 0x0f;
	const reserved = headerBytes[offset];
	offset += 1;
	if (reserved !== 0) {
		/* ignore */
	}
	const command = headerBytes[offset];
	offset += 1;
	if (command !== 1 && command !== 2 && command !== 3) return null; // 1 TCP, 2 UDP, 3 Mux
	// Address
	if (headerBytes.length < offset + 2 + 1) return null;
	const port = (headerBytes[offset] << 8) | headerBytes[offset + 1];
	offset += 2;
	const atype = headerBytes[offset];
	offset += 1;
	let address = '';
	let addressLength = 0;
	if (atype === 1) {
		// IPv4
		addressLength = 4;
		if (headerBytes.length < offset + addressLength) return null;
		address = `${headerBytes[offset]}.${headerBytes[offset + 1]}.${headerBytes[offset + 2]}.${headerBytes[offset + 3]}`;
		offset += 4;
	} else if (atype === 2) {
		// Domain
		if (headerBytes.length < offset + 1) return null;
		addressLength = headerBytes[offset];
		offset += 1;
		if (headerBytes.length < offset + addressLength) return null;
		address = new TextDecoder().decode(headerBytes.slice(offset, offset + addressLength));
		offset += addressLength;
	} else if (atype === 3) {
		// IPv6
		addressLength = 16;
		if (headerBytes.length < offset + 16) return null;
		const ipv6 = [];
		for (let i = 0; i < 8; i++) {
			ipv6.push(
				((headerBytes[offset + i * 2] << 8) | headerBytes[offset + i * 2 + 1]).toString(16)
			);
		}
		address = ipv6.join(':');
		offset += 16;
	} else {
		return null;
	}
	if (paddingLen > 0) {
		if (headerBytes.length < offset + paddingLen) return null;
		offset += paddingLen;
	}
	if (headerBytes.length < offset + 4) return null;
	const fnv = headerBytes.slice(offset, offset + 4);
	offset += 4;
	// Verify FNV1a — Xray-core rejects mismatches (encoding/server.go)
	const hash = fnv1a(headerBytes.slice(0, offset - 4));
	const expected = (fnv[0] << 24) | (fnv[1] << 16) | (fnv[2] << 8) | fnv[3];
	if (hash >>> 0 !== expected >>> 0) return null;
	// Map security (Xray/V2Ray SecurityType: 0=Unknown/Auto, 1=Legacy, 2=Auto, 3=AES128-GCM, 4=ChaCha20-Poly1305, 5=None)
	let secType;
	switch (security) {
		case 0:
		case 1:
		case 2:
			secType = 'auto';
			break;
		case 3:
			secType = 'aes-128-gcm';
			break;
		case 4:
			secType = 'chacha20-poly1305';
			break;
		case 5:
			secType = 'none';
			break;
		default:
			secType = 'unknown';
			break;
	}
	const isUDP = command === 2;
	const isMux = command === 3;
	return {
		version,
		bodyIV,
		bodyKey,
		responseHeader,
		option,
		security: secType,
		securityCode: security,
		paddingLen,
		command,
		port,
		addressType: atype,
		address,
		isUDP,
		isMux,
		rawHeader: headerBytes,
	};
}

// High-level VMess request parser (tries AEAD, time window)
export async function parseVMessRequest(chunk, uuidStr) {
	const data = toUint8Array(chunk);
	if (data.length < 16) return { hasError: true, message: 'VMess data too short' };
	const authID = data.slice(0, 16);
	const rest = data.slice(16);
	let cmdKey;
	try {
		cmdKey = getCmdKey(uuidStr);
	} catch (e) {
		return { hasError: true, message: e.message };
	}
	if (!cmdKey) return { hasError: true, message: 'Invalid UUID' };

	const nowSec = Math.floor(Date.now() / 1000);
	const decoded = decodeAuthID(authID, cmdKey);
	if (!decoded) {
		return { hasError: true, message: 'VMess AuthID invalid' };
	}
	const timeDiff = Math.abs(decoded.timeSec - nowSec);
	if (timeDiff > 300) {
		return { hasError: true, message: 'VMess AuthID timestamp expired' };
	}

	let outer;
	try {
		outer = await openVMessAEADHeader(cmdKey, authID, rest);
	} catch (e) {
		return { hasError: true, message: 'VMess AEAD open failed: ' + e.message };
	}
	if (!outer) return { hasError: true, message: 'VMess AEAD open failed' };

	const inner = parseVMessInnerHeader(outer.header);
	if (!inner) return { hasError: true, message: 'VMess inner header invalid' };
	if (inner.isMux) return { hasError: true, message: 'Mux not supported' };

	if (inner.security === 'unknown') return { hasError: true, message: 'Unknown VMess security' };
	let security = inner.security;
	if (security === 'auto') security = 'aes-128-gcm';

	return {
		hasError: false,
		address: inner.address,
		port: inner.port,
		hostname: inner.address,
		isUDP: inner.isUDP,
		isMux: inner.isMux,
		security,
		option: inner.option,
		bodyKey: inner.bodyKey,
		bodyIV: inner.bodyIV,
		responseHeader: inner.responseHeader,
		rawClientData: outer.remaining,
		consumed: 16 + outer.consumed,
		innerHeader: inner,
		cmdKey,
		authID,
		nonce: outer.nonce,
	};
}

// -----------------------------------------------------------------------------
// Body Handling for VMess
// -----------------------------------------------------------------------------

export function generateChacha20Poly1305Key(key16) {
	const md5_1 = pureMD5Bytes(key16);
	const md5_2 = pureMD5Bytes(md5_1);
	const full = new Uint8Array(32);
	full.set(md5_1, 0);
	full.set(md5_2, 16);
	return full;
}

export function getChunkNonce(nonce16, count) {
	const out = new Uint8Array(nonce16.slice(0, 12));
	out[0] = (count >>> 8) & 0xff;
	out[1] = count & 0xff;
	return out;
}

// Decrypt a single VMess body chunk
export async function vmessDecryptChunk(chunk, bodyKey, bodyIV, count, security) {
	if (security === 'none') {
		return chunk;
	}
	const nonce = getChunkNonce(bodyIV, count);
	if (security === 'aes-128-gcm' || security === 'auto') {
		return aesGcmDecrypt(bodyKey, nonce, chunk, new Uint8Array(0));
	}
	if (security === 'chacha20-poly1305') {
		const chachaKey = generateChacha20Poly1305Key(bodyKey);
		const { chacha20Poly1305Decrypt } = await import('./tls.js');
		return chacha20Poly1305Decrypt(chachaKey, nonce, chunk, new Uint8Array(0));
	}
	throw new Error('Unsupported VMess security: ' + security);
}

export async function vmessEncryptChunk(plaintext, bodyKey, bodyIV, count, security) {
	if (security === 'none') return plaintext;
	const nonce = getChunkNonce(bodyIV, count);
	if (security === 'aes-128-gcm' || security === 'auto') {
		return aesGcmEncrypt(bodyKey, nonce, plaintext, new Uint8Array(0));
	}
	if (security === 'chacha20-poly1305') {
		const chachaKey = generateChacha20Poly1305Key(bodyKey);
		const { chacha20Poly1305Encrypt } = await import('./tls.js');
		return chacha20Poly1305Encrypt(chachaKey, nonce, plaintext, new Uint8Array(0));
	}
	throw new Error('Unsupported VMess security: ' + security);
}

// Helper to read VMess body stream (chunked)
export async function* vmessBodyReader(buffer, bodyKey, bodyIV, security, option) {
	let offset = 0;
	let count = 0;
	const hasMask = (option & 0x04) !== 0;
	const hasPadding = (option & 0x08) !== 0;
	const shakeParser = (hasMask || hasPadding) ? new ShakeSizeParser(bodyIV) : null;

	while (offset + 2 <= buffer.length) {
		// Xray calls NextPaddingLen() BEFORE Decode() — both consume SHAKE128
		let padLen = 0;
		if (hasPadding && shakeParser) {
			padLen = shakeParser.nextPaddingLen();
		}
		let len;
		if (shakeParser) {
			len = shakeParser.decode(buffer.subarray(offset, offset + 2));
		} else {
			len = (buffer[offset] << 8) | buffer[offset + 1];
		}
		offset += 2;

		if (len === 0) break; // end of stream
		if (offset + len > buffer.length) break; // need more data
		const chunk = buffer.slice(offset, offset + len);
		offset += len;
		let decrypted;
		try {
			decrypted = await vmessDecryptChunk(chunk, bodyKey, bodyIV, count, security);
		} catch (e) {
			throw new Error('VMess body decrypt failed at count ' + count + ': ' + e.message);
		}
		count++;

		if (padLen && decrypted.length >= padLen) {
			decrypted = decrypted.subarray(0, decrypted.length - padLen);
		}

		yield decrypted;
	}
}

// For encoding response (server to client) - generates VMess AEAD response header
// responseHeaderByte: byte đã thỏa thuận trong inner header (Xray-core server.go: EncodeResponseHeader)
export async function vmessCreateResponseHeader(responseHeaderByte, bodyKey, bodyIV) {
	const bodyKeyHash = new PureSha256().update(bodyKey).digest();
	const bodyIVHash = new PureSha256().update(bodyIV).digest();
	const respKey = bodyKeyHash.slice(0, 16);
	const respIV = bodyIVHash.slice(0, 16);
	const lenKey = vmessKDF16(respKey, KDFSaltConstAEADRespHeaderLenKey);
	const lenNonce = vmessKDF(respIV, KDFSaltConstAEADRespHeaderLenIV).slice(0, 12);
	const payloadKey = vmessKDF16(respKey, KDFSaltConstAEADRespHeaderPayloadKey);
	const payloadNonce = vmessKDF(respIV, KDFSaltConstAEADRespHeaderPayloadIV).slice(0, 12);

	// Xray-core server.go EncodeResponseHeader writes [responseHeader, Option]
	// then MarshalCommand(nil) fails and appends [0x00, 0x00]; the client reads 4 bytes.
	const plainHeader = new Uint8Array([responseHeaderByte, 0x00, 0x00, 0x00]);
	const lenPlain = new Uint8Array([(plainHeader.length >>> 8) & 0xff, plainHeader.length & 0xff]);
	const lenCt = await aesGcmEncrypt(lenKey, lenNonce, lenPlain, new Uint8Array(0));
	const payloadCt = await aesGcmEncrypt(payloadKey, payloadNonce, plainHeader, new Uint8Array(0));
	const out = new Uint8Array(lenCt.length + payloadCt.length);
	out.set(lenCt, 0);
	out.set(payloadCt, lenCt.length);
	return out;
}

// VMess link generation for subscription (vmess://)
export function generateVMessLink({
	host,
	port,
	uuid,
	security = 'auto',
	net = 'ws',
	path = '/',
	hostHeader = '',
	tls = 'tls',
	sni = '',
	fp = 'chrome',
	ps = '',
}) {
	const vmessJson = {
		v: '2',
		ps: ps || `${host}:${port}`,
		add: host,
		port: String(port),
		id: uuid,
		aid: '0',
		scy: security,
		net: net,
		type: 'none',
		host: hostHeader || host,
		path: path,
		tls: tls,
		sni: sni || host,
		alpn: '',
		fp: fp,
	};
	const b64 = btoa(JSON.stringify(vmessJson));
	return `vmess://${b64}`;
}
