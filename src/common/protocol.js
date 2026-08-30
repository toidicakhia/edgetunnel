/**
 * src/common/protocol.js
 * Protocol-level request constants — mirror of Xray-core common/protocol/headers.go.
 */

/** RequestCommand — VLESS/Trojan/SOCKS command byte (common/protocol/headers.go). */
export const RequestCommand = Object.freeze({
	TCP: 0x01,
	UDP: 0x02,
	Mux: 0x03,
	Rvs: 0x04,
});

/** Option flags used by VMess/VLESS command headers (headers.go Options). */
export const RequestOptions = Object.freeze({
	ChunkStream: 0x01,
	ConnectionReuse: 0x02,
	GlobalPadding: 0x04,
	AuthenticatedLength: 0x08,
});

/** Mux session status bytes (common/mux/frame.go). */
export const MuxStatus = Object.freeze({
	New: 0x01,
	Keep: 0x02,
	End: 0x03,
	KeepAlive: 0x04,
});

/** Mux option bytes. */
export const MuxOption = Object.freeze({
	Data: 0x00,
	Error: 0x01,
});

/**
 * Validate a command byte for a transport that accepts TCP/UDP.
 * Throws on unsupported. Returns the normalized network constant.
 */
export function validateTCPCommand(cmd) {
	if (cmd === RequestCommand.TCP) return 0x01;
	if (cmd === RequestCommand.UDP) return 0x02;
	throw new Error(`unsupported command 0x${cmd.toString(16)}`);
}