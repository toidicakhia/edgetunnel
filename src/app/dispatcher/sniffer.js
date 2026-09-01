/**
 * src/app/dispatcher/sniffer.js
 * Traffic sniffing — mirror of Xray-core app/dispatcher/sniffer.go.
 *
 * Detects HTTP (Host header) and TLS (SNI from ClientHello) from leading bytes;
 * returns protocol name + optional target override.
 */

/** Parse a TLS ClientHello and return the SNI (host) if present. */
export function sniffTLSClientHello(bytes) {
	// TLS record: [0]=0x16 [1..2]=ver [3..4]=len
	if (bytes.byteLength < 5 || bytes[0] !== 0x16) return null;
	const recordLen = (bytes[3] << 8) | bytes[4];
	const end = Math.min(5 + recordLen, bytes.byteLength);
	if (end < 42) return null;
	let p = 5;
	// handshake: type(1) len(3)
	if (bytes[p] !== 0x01) return null;
	const hsLen = (bytes[p + 1] << 16) | (bytes[p + 2] << 8) | bytes[p + 3];
	const hsEnd = Math.min(p + 4 + hsLen, end);
	p += 4;
	// version(2) random(32)
	p += 2 + 32;
	// session id
	if (p + 1 > hsEnd) return null;
	const sidLen = bytes[p++];
	p += sidLen;
	// cipher suites
	if (p + 2 > hsEnd) return null;
	const csLen = (bytes[p] << 8) | bytes[p + 1];
	p += 2 + csLen;
	// compression methods
	if (p + 1 > hsEnd) return null;
	const compLen = bytes[p++];
	p += compLen;
	// extensions
	if (p + 2 > hsEnd) return null;
	const extTotal = (bytes[p] << 8) | bytes[p + 1];
	p += 2;
	const extEnd = Math.min(p + extTotal, hsEnd);
	while (p + 4 <= extEnd) {
		const extType = (bytes[p] << 8) | bytes[p + 1];
		const extLen = (bytes[p + 2] << 8) | bytes[p + 3];
		p += 4;
		if (extType === 0x0000 && p + extLen <= extEnd) {
			// server_name extension
			let q = p;
			if (q + 2 > p + extLen) return null;
			const listLen = (bytes[q] << 8) | bytes[q + 1];
			q += 2;
			const listEnd = Math.min(q + listLen, p + extLen);
			if (q + 3 <= listEnd) {
				const nameType = bytes[q];
				if (nameType === 0x00) {
					const nameLen = (bytes[q + 1] << 8) | bytes[q + 2];
					q += 3;
					if (q + nameLen <= listEnd) {
						return new TextDecoder().decode(bytes.subarray(q, q + nameLen));
					}
				}
			}
		}
		p += extLen;
	}
	return null;
}
