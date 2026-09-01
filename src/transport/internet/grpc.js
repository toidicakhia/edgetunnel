/**
 * src/transport/internet/grpc.js
 * gRPC transport — mirror of Xray-core transport/internet/grpc.
 *
 * Framing: [1B compression flag = 0][4B BE protobuf length][protobuf].
 * Protobuf messages:
 *   Hunk      { bytes data = 1 }                 (field 1 wiretype 2 → 0x0a)
 *   MultiHunk { repeated bytes data = 1 }        (per-element length-delimited)
 * Service/method resolution (encoding/customSeviceName.go + config.go):
 *   - legacy (no leading '/'): service = PathEscape(ServiceName),
 *     streams 'Tun' / 'TunMulti'.
 *   - custom path '/a/b|b2': service = PathEscape('/a' + '/' + 'b'),
 *     Tun = PathEscape('b'), TunMulti = PathEscape('b2'); client uses part0,
 *     server part1.
 */

/** Encode a single Hunk message: [0][4BBE len][proto: 0a <len> <data>]. */
export function encodeHunk(data) {
	const chunk = data instanceof Uint8Array ? data : new Uint8Array(data);
	// protobuf: field 1 varint len
	const protoLen = 1 + varintLen(chunk.byteLength) + chunk.byteLength;
	const frame = new Uint8Array(5 + protoLen);
	frame[0] = 0; // compression flag
	frame[1] = (protoLen >>> 24) & 0xff;
	frame[2] = (protoLen >>> 16) & 0xff;
	frame[3] = (protoLen >>> 8) & 0xff;
	frame[4] = protoLen & 0xff;
	frame[5] = 0x0a; // field 1, wire type 2
	let off = 6;
	off += writeVarint(frame, off, chunk.byteLength);
	frame.set(chunk, off);
	return frame;
}

/** Encode a MultiHunk batch: each element a length-delimited bytes subfield. */
export function encodeMultiHunk(chunks) {
	const parts = [];
	let totalProto = 0;
	for (const c of chunks) {
		const chunk = c instanceof Uint8Array ? c : new Uint8Array(c);
		const el = new Uint8Array(1 + varintLen(chunk.byteLength) + chunk.byteLength);
		el[0] = 0x0a;
		let off = 1;
		off += writeVarint(el, off, chunk.byteLength);
		el.set(chunk, off);
		parts.push(el);
		totalProto += el.byteLength;
	}
	const frame = new Uint8Array(5 + totalProto);
	frame[0] = 0;
	frame[1] = (totalProto >>> 24) & 0xff;
	frame[2] = (totalProto >>> 16) & 0xff;
	frame[3] = (totalProto >>> 8) & 0xff;
	frame[4] = totalProto & 0xff;
	let off = 5;
	for (const p of parts) {
		frame.set(p, off);
		off += p.byteLength;
	}
	return frame;
}

/** Parse one gRPC message: returns { payload: Uint8Array, consumed: number } or null. */
export function parseGRPCMessage(bytes) {
	if (bytes.byteLength < 5) return null;
	if (bytes[0] !== 0) throw new Error('grpc: compressed messages unsupported');
	const len = (bytes[1] << 24) | (bytes[2] << 16) | (bytes[3] << 8) | bytes[4];
	if (5 + len > bytes.byteLength) return null;
	return { payload: bytes.subarray(5, 5 + len), consumed: 5 + len };
}

function varintLen(value) {
	let len = 1;
	while (value > 127) {
		value >>>= 7;
		len++;
	}
	return len;
}

function writeVarint(bytes, offset, value) {
	let n = value >>> 0;
	let off = offset;
	while (n > 127) {
		bytes[off++] = (n & 0x7f) | 0x80;
		n >>>= 7;
	}
	bytes[off++] = n;
	return off - offset;
}

