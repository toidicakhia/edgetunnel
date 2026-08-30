/**
 * src/transport/link.js
 * Transport Link — mirror of Xray-core transport/link.go.
 *
 * A Link joins the inbound side of a connection (data FROM the client) with the
 * outbound side (data TO the client). The dispatcher hands the Link to an
 * outbound handler: the handler reads link.readable (client bytes) and writes
 * link.writable (responses back to client).
 */

/**
 * @typedef {Object} Link
 * @property {ReadableStream} readable  — bytes from the client (request side)
 * @property {WritableStream} writable  — bytes back to the client (response side)
 */

/** Create a Link from separate readable/writable streams. */
export function makeLink(readable, writable) {
	return { readable, writable };
}

/** Reverse a link (swap sides) — used when dispatching chained outbounds. */
export function swapLink(link) {
	return { readable: link.writable, writable: link.readable };
}