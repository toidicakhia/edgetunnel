/**
 * src/utils/crypto.js
 * Auto-generated from _worker.js refactor
 * Original: edgetunnel 2.1 (2026-08-11)
 */

export function base64SecretEncode(plaintext, secret) {
	const encoder = new TextEncoder();
	const data = encoder.encode(plaintext);
	const key = encoder.encode(secret);
	const mixed = new Uint8Array(data.length);

	for (let i = 0; i < data.length; i++) {
		mixed[i] = data[i] ^ key[i % key.length];
	}

	// convert Uint8Array to btoa processed string
	let binary = '';
	for (let i = 0; i < mixed.length; i++) {
		binary += String.fromCharCode(mixed[i]);
	}
	return btoa(binary);
}

/**
 * keyedBase64Decode
 * @param {string} encoded - key-processedBase64Str
 * @param {string} secret - secretKeystr（mustMatchEncoding）
 * @returns {string} decodedOriginalPlaintextstr
 */

export function base64SecretDecode(encoded, secret) {
	const binary = atob(encoded);
	const mixed = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		mixed[i] = binary.charCodeAt(i);
	}

	const encoder = new TextEncoder();
	const key = encoder.encode(secret);
	const data = new Uint8Array(mixed.length);

	for (let i = 0; i < mixed.length; i++) {
		data[i] = mixed[i] ^ key[i % key.length];
	}

	const decoder = new TextDecoder();
	return decoder.decode(data);
}

function pureMD5(string) {
	function rotateLeft(lValue, iShiftBits) {
		return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
	}
	function addUnsigned(lX, lY) {
		const lX8 = lX & 0x80000000;
		const lY8 = lY & 0x80000000;
		const lX4 = lX & 0x40000000;
		const lY4 = lY & 0x40000000;
		const lResult = (lX & 0x3fffffff) + (lY & 0x3fffffff);
		if (lX4 & lY4) return lResult ^ 0x80000000 ^ lX8 ^ lY8;
		if (lX4 | lY4) {
			if (lResult & 0x40000000) return lResult ^ 0xc0000000 ^ lX8 ^ lY8;
			return lResult ^ 0x40000000 ^ lX8 ^ lY8;
		}
		return lResult ^ lX8 ^ lY8;
	}
	function F(x, y, z) {
		return (x & y) | (~x & z);
	}
	function G(x, y, z) {
		return (x & z) | (y & ~z);
	}
	function H(x, y, z) {
		return x ^ y ^ z;
	}
	function I(x, y, z) {
		return y ^ (x | ~z);
	}
	function FF(a, b, c, d, x, s, ac) {
		a = addUnsigned(a, addUnsigned(addUnsigned(F(b, c, d), x), ac));
		return addUnsigned(rotateLeft(a, s), b);
	}
	function GG(a, b, c, d, x, s, ac) {
		a = addUnsigned(a, addUnsigned(addUnsigned(G(b, c, d), x), ac));
		return addUnsigned(rotateLeft(a, s), b);
	}
	function HH(a, b, c, d, x, s, ac) {
		a = addUnsigned(a, addUnsigned(addUnsigned(H(b, c, d), x), ac));
		return addUnsigned(rotateLeft(a, s), b);
	}
	function II(a, b, c, d, x, s, ac) {
		a = addUnsigned(a, addUnsigned(addUnsigned(I(b, c, d), x), ac));
		return addUnsigned(rotateLeft(a, s), b);
	}
	function convertToWordArray(string) {
		let lWordCount;
		const lMessageLength = string.length;
		const lNumberOfWords_temp1 = lMessageLength + 8;
		const lNumberOfWords_temp2 = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64;
		const lNumberOfWords = (lNumberOfWords_temp2 + 1) * 16;
		const lWordArray = Array(lNumberOfWords - 1);
		let lBytePosition = 0;
		let lByteCount = 0;
		while (lByteCount < lMessageLength) {
			lWordCount = (lByteCount - (lByteCount % 4)) / 4;
			lBytePosition = (lByteCount % 4) * 8;
			lWordArray[lWordCount] =
				lWordArray[lWordCount] | (string.charCodeAt(lByteCount) << lBytePosition);
			lByteCount++;
		}
		lWordCount = (lByteCount - (lByteCount % 4)) / 4;
		lBytePosition = (lByteCount % 4) * 8;
		lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80 << lBytePosition);
		lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
		lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;
		return lWordArray;
	}
	function wordToHex(lValue) {
		let WordToHexValue = '',
			WordToHexValue_temp = '',
			lByte,
			lCount;
		for (lCount = 0; lCount <= 3; lCount++) {
			lByte = (lValue >>> (lCount * 8)) & 255;
			WordToHexValue_temp = '0' + lByte.toString(16);
			WordToHexValue =
				WordToHexValue + WordToHexValue_temp.substr(WordToHexValue_temp.length - 2, 2);
		}
		return WordToHexValue;
	}

	const x = convertToWordArray(unescape(encodeURIComponent(string)));
	let a = 0x67452301,
		b = 0xefcdab89,
		c = 0x98badcfe,
		d = 0x10325476;
	const S11 = 7,
		S12 = 12,
		S13 = 17,
		S14 = 22;
	const S21 = 5,
		S22 = 9,
		S23 = 14,
		S24 = 20;
	const S31 = 4,
		S32 = 11,
		S33 = 16,
		S34 = 23;
	const S41 = 6,
		S42 = 10,
		S43 = 15,
		S44 = 21;

	for (let k = 0; k < x.length; k += 16) {
		const AA = a,
			BB = b,
			CC = c,
			DD = d;
		a = FF(a, b, c, d, x[k + 0] || 0, S11, 0xd76aa478);
		d = FF(d, a, b, c, x[k + 1] || 0, S12, 0xe8c7b756);
		c = FF(c, d, a, b, x[k + 2] || 0, S13, 0x242070db);
		b = FF(b, c, d, a, x[k + 3] || 0, S14, 0xc1bdceee);
		a = FF(a, b, c, d, x[k + 4] || 0, S11, 0xf57c0faf);
		d = FF(d, a, b, c, x[k + 5] || 0, S12, 0x4787c62a);
		c = FF(c, d, a, b, x[k + 6] || 0, S13, 0xa8304613);
		b = FF(b, c, d, a, x[k + 7] || 0, S14, 0xfd469501);
		a = FF(a, b, c, d, x[k + 8] || 0, S11, 0x698098d8);
		d = FF(d, a, b, c, x[k + 9] || 0, S12, 0x8b44f7af);
		c = FF(c, d, a, b, x[k + 10] || 0, S13, 0xffff5bb1);
		b = FF(b, c, d, a, x[k + 11] || 0, S14, 0x895cd7be);
		a = FF(a, b, c, d, x[k + 12] || 0, S11, 0x6b901122);
		d = FF(d, a, b, c, x[k + 13] || 0, S12, 0xfd987193);
		c = FF(c, d, a, b, x[k + 14] || 0, S13, 0xa679438e);
		b = FF(b, c, d, a, x[k + 15] || 0, S14, 0x49b40821);

		a = GG(a, b, c, d, x[k + 1] || 0, S21, 0xf61e2562);
		d = GG(d, a, b, c, x[k + 6] || 0, S22, 0xc040b340);
		c = GG(c, d, a, b, x[k + 11] || 0, S23, 0x265e5a51);
		b = GG(b, c, d, a, x[k + 0] || 0, S24, 0xe9b6c7aa);
		a = GG(a, b, c, d, x[k + 5] || 0, S21, 0xd62f105d);
		d = GG(d, a, b, c, x[k + 10] || 0, S22, 0x2441453);
		c = GG(c, d, a, b, x[k + 15] || 0, S23, 0xd8a1e681);
		b = GG(b, c, d, a, x[k + 4] || 0, S24, 0xe7d3fbc8);
		a = GG(a, b, c, d, x[k + 9] || 0, S21, 0x21e1cde6);
		d = GG(d, a, b, c, x[k + 14] || 0, S22, 0xc33707d6);
		c = GG(c, d, a, b, x[k + 3] || 0, S23, 0xf4d50d87);
		b = GG(b, c, d, a, x[k + 8] || 0, S24, 0x455a14ed);
		a = GG(a, b, c, d, x[k + 13] || 0, S21, 0xa9e3e905);
		d = GG(d, a, b, c, x[k + 2] || 0, S22, 0xfcefa3f8);
		c = GG(c, d, a, b, x[k + 7] || 0, S23, 0x676f02d9);
		b = GG(b, c, d, a, x[k + 12] || 0, S24, 0x8d2a4c8a);

		a = HH(a, b, c, d, x[k + 5] || 0, S31, 0xfffa3942);
		d = HH(d, a, b, c, x[k + 8] || 0, S32, 0x8771f681);
		c = HH(c, d, a, b, x[k + 11] || 0, S33, 0x6d9d6122);
		b = HH(b, c, d, a, x[k + 14] || 0, S34, 0xfde5380c);
		a = HH(a, b, c, d, x[k + 1] || 0, S31, 0xa4beea44);
		d = HH(d, a, b, c, x[k + 4] || 0, S32, 0x4bdecfa9);
		c = HH(c, d, a, b, x[k + 7] || 0, S33, 0xf6bb4b60);
		b = HH(b, c, d, a, x[k + 10] || 0, S34, 0xbebfbc70);
		a = HH(a, b, c, d, x[k + 13] || 0, S31, 0x289b7ec6);
		d = HH(d, a, b, c, x[k + 0] || 0, S32, 0xeaa127fa);
		c = HH(c, d, a, b, x[k + 3] || 0, S33, 0xd4ef3085);
		b = HH(b, c, d, a, x[k + 6] || 0, S34, 0x4881d05);
		a = HH(a, b, c, d, x[k + 9] || 0, S31, 0xd9d4d039);
		d = HH(d, a, b, c, x[k + 12] || 0, S32, 0xe6db99e5);
		c = HH(c, d, a, b, x[k + 15] || 0, S33, 0x1fa27cf8);
		b = HH(b, c, d, a, x[k + 2] || 0, S34, 0xc4ac5665);

		a = II(a, b, c, d, x[k + 0] || 0, S41, 0xf4292244);
		d = II(d, a, b, c, x[k + 7] || 0, S42, 0x432aff97);
		c = II(c, d, a, b, x[k + 14] || 0, S43, 0xab9423a7);
		b = II(b, c, d, a, x[k + 5] || 0, S44, 0xfc93a039);
		a = II(a, b, c, d, x[k + 12] || 0, S41, 0x655b59c3);
		d = II(d, a, b, c, x[k + 3] || 0, S42, 0x8f0ccc92);
		c = II(c, d, a, b, x[k + 10] || 0, S43, 0xffeff47d);
		b = II(b, c, d, a, x[k + 1] || 0, S44, 0x85845dd1);
		a = II(a, b, c, d, x[k + 8] || 0, S41, 0x6fa87e4f);
		d = II(d, a, b, c, x[k + 15] || 0, S42, 0xfe2ce6e0);
		c = II(c, d, a, b, x[k + 6] || 0, S43, 0xa3014314);
		b = II(b, c, d, a, x[k + 13] || 0, S44, 0x4e0811a1);
		a = II(a, b, c, d, x[k + 4] || 0, S41, 0xf7537e82);
		d = II(d, a, b, c, x[k + 11] || 0, S42, 0xbd3af235);
		c = II(c, d, a, b, x[k + 2] || 0, S43, 0x2ad7d2bb);
		b = II(b, c, d, a, x[k + 9] || 0, S44, 0xeb86d391);

		a = addUnsigned(a, AA);
		b = addUnsigned(b, BB);
		c = addUnsigned(c, CC);
		d = addUnsigned(d, DD);
	}
	return (wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d)).toLowerCase();
}

export async function MD5MD5(text) {
	const encoder = new TextEncoder();
	try {
		const firstHash = await crypto.subtle.digest('MD5', encoder.encode(text));
		const firstHashArray = Array.from(new Uint8Array(firstHash));
		const firstHex = firstHashArray
			.map((bytes) => bytes.toString(16).padStart(2, '0'))
			.join('');

		const secondHash = await crypto.subtle.digest('MD5', encoder.encode(firstHex.slice(7, 27)));
		const secondHashArray = Array.from(new Uint8Array(secondHash));
		const secondHex = secondHashArray
			.map((bytes) => bytes.toString(16).padStart(2, '0'))
			.join('');

		return secondHex.toLowerCase();
	} catch (_) {
		const firstHex = pureMD5(text);
		const secondHex = pureMD5(firstHex.slice(7, 27));
		return secondHex.toLowerCase();
	}
}

export function sha224(s) {
	const K = [
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
		0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
		0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
		0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
		0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
		0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
		0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
		0xc67178f2,
	];
	const r = (n, b) => ((n >>> b) | (n << (32 - b))) >>> 0;
	s = unescape(encodeURIComponent(s));
	const l = s.length * 8;
	s += String.fromCharCode(0x80);
	while ((s.length * 8) % 512 !== 448) s += String.fromCharCode(0);
	const h = [
		0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7,
		0xbefa4fa4,
	];
	const hi = Math.floor(l / 0x100000000),
		lo = l & 0xffffffff;
	s += String.fromCharCode(
		(hi >>> 24) & 0xff,
		(hi >>> 16) & 0xff,
		(hi >>> 8) & 0xff,
		hi & 0xff,
		(lo >>> 24) & 0xff,
		(lo >>> 16) & 0xff,
		(lo >>> 8) & 0xff,
		lo & 0xff
	);
	const w = [];
	for (let i = 0; i < s.length; i += 4)
		w.push(
			(s.charCodeAt(i) << 24) |
				(s.charCodeAt(i + 1) << 16) |
				(s.charCodeAt(i + 2) << 8) |
				s.charCodeAt(i + 3)
		);
	for (let i = 0; i < w.length; i += 16) {
		const x = new Array(64).fill(0);
		for (let j = 0; j < 16; j++) x[j] = w[i + j];
		for (let j = 16; j < 64; j++) {
			const s0 = r(x[j - 15], 7) ^ r(x[j - 15], 18) ^ (x[j - 15] >>> 3);
			const s1 = r(x[j - 2], 17) ^ r(x[j - 2], 19) ^ (x[j - 2] >>> 10);
			x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0;
		}
		let [a, b, c, d, e, f, g, h0] = h;
		for (let j = 0; j < 64; j++) {
			const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25),
				ch = (e & f) ^ (~e & g),
				t1 = (h0 + S1 + ch + K[j] + x[j]) >>> 0;
			const S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22),
				maj = (a & b) ^ (a & c) ^ (b & c),
				t2 = (S0 + maj) >>> 0;
			h0 = g;
			g = f;
			f = e;
			e = (d + t1) >>> 0;
			d = c;
			c = b;
			b = a;
			a = (t1 + t2) >>> 0;
		}
		for (let j = 0; j < 8; j++)
			h[j] =
				(h[j] +
					(j === 0
						? a
						: j === 1
							? b
							: j === 2
								? c
								: j === 3
									? d
									: j === 4
										? e
										: j === 5
											? f
											: j === 6
												? g
												: h0)) >>>
				0;
	}
	let hex = '';
	for (let i = 0; i < 7; i++) {
		for (let j = 24; j >= 0; j -= 8) hex += ((h[i] >>> j) & 0xff).toString(16).padStart(2, '0');
	}
	return hex;
}
