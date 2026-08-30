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

/**
 * gRPC method path resolution (customSeviceName.go + config.go getServiceName
 * / getTunStreamName / getTunMultiStreamName).
 *
 * @param {string} serviceName config value (may be legacy or '/a/b|c')
 * @returns {{ service: string, tun: string, tunMulti: string }}
 */
export function resolveGRPCNames(serviceName = '') {
	const escape = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) =>
		'%' + c.charCodeAt(0).toString(16).toUpperCase()
	);
	if (!serviceName.startsWith('/')) {
		return { service: escape(serviceName), tun: 'Tun', tunMulti: 'TunMulti' };
	}
	// '/a/b|c' style
	const lastSlash = serviceName.lastIndexOf('/');
	const head = serviceName.slice(1, Math.max(lastSlash, 1)); // 'a/b'
	const ending = serviceName.slice(lastSlash + 1); // 'b|c'
	const parts = head.split('/').map(escape);
	const service = parts.join('/');
	const [tunRaw, tunMultiRaw = ''] = ending.split('|');
	return { service, tun: escape(tunRaw), tunMulti: escape(tunMultiRaw) };
}

/** Build the method path '/service/tun' for a stream. */
export function grpcMethodPath(names, stream) {
	return `/${names.service}/${stream}`;
}

/**
 * Incremental gRPC frame stream decoder: feed bytes, get payloads.
 * Handles payload splitting across chunks.
 */
export class GRPCFrameDecoder {
	constructor() {
		this.buffer = new Uint8Array(0);
	}

	/** Feed bytes; returns array of decoded payloads (Uint8Array each). */
	push(chunk) {
		const data = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
		if (this.buffer.byteLength) {
			const merged = new Uint8Array(this.buffer.byteLength + data.byteLength);
			merged.set(this.buffer, 0);
			merged.set(data, this.buffer.byteLength);
			this.buffer = merged;
		} else {
			this.buffer = data;
		}
		const payloads = [];
		let off = 0;
		while (true) {
			if (this.buffer.byteLength - off < 5) break;
			const compress = this.buffer[off];
			if (compress !== 0) {
				throw new Error('grpc: compressed message unsupported');
			}
			const len =
				(this.buffer[off + 1] << 24) |
				(this.buffer[off + 2] << 16) |
				(this.buffer[off + 3] << 8) |
				this.buffer[off + 4];
			if (this.buffer.byteLength - off - 5 < len) break;
			payloads.push(this.buffer.subarray(off + 5, off + 5 + len));
			off += 5 + len;
		}
		if (off > 0) this.buffer = this.buffer.subarray(off);
		return payloads;
	}
}

/**
 * Extract payload from a decoded Hunk protobuf (field 1 length-delimited).
 * Returns null if the message is not a Hunk/bytes field 1.
 */
export function decodeHunkPayload(protoBytes) {
	// [0x0a][varint len][data]
	if (!protoBytes || protoBytes.byteLength < 2 || protoBytes[0] !== 0x0a) return null;
	const first = protoBytes[1];
	if (first < 128) {
		if (2 + first > protoBytes.byteLength) return null;
		return protoBytes.subarray(2, 2 + first);
	}
	// multi-byte varint
	let len = 0;
	let shift = 0;
	let off = 1;
	while (off < protoBytes.byteLength && shift < 28) {
		const b = protoBytes[off++];
		len |= (b & 0x7f) << shift;
		if (b < 0x80) break;
		shift += 7;
	}
	if (off + len > protoBytes.byteLength) return null;
	return protoBytes.subarray(off, off + len);
}