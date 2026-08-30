/**
 * src/common/serial.js
 * Big-endian integer helpers — mirror of Xray-core common/serial/serial.go.
 * ReadUint16 / WriteUint16 / WriteUint64.
 */

/** Read a big-endian uint16 from a Uint8Array at offset. */
export function readUint16(bytes, offset = 0) {
	return (bytes[offset] << 8) | bytes[offset + 1];
}

/** Append a big-endian uint16 to a Uint8Array at offset; returns bytes. */
export function writeUint16(bytes, offset, value) {
	bytes[offset] = (value >> 8) & 0xff;
	bytes[offset + 1] = value & 0xff;
	return bytes;
}

/** Read a big-endian uint32 from a Uint8Array at offset (unsigned). */
export function readUint32(bytes, offset = 0) {
	return (
		((bytes[offset] << 24) |
			(bytes[offset + 1] << 16) |
			(bytes[offset + 2] << 8) |
			bytes[offset + 3]) >>>
		0
	);
}

/** Append a big-endian uint64 (as BigInt or two uint32s) to a byte array. */
export function writeUint64(bytes, offset, hi, lo) {
	bytes[offset] = (hi >>> 24) & 0xff;
	bytes[offset + 1] = (hi >>> 16) & 0xff;
	bytes[offset + 2] = (hi >>> 8) & 0xff;
	bytes[offset + 3] = hi & 0xff;
	bytes[offset + 4] = (lo >>> 24) & 0xff;
	bytes[offset + 5] = (lo >>> 16) & 0xff;
	bytes[offset + 6] = (lo >>> 8) & 0xff;
	bytes[offset + 7] = lo & 0xff;
	return bytes;
}