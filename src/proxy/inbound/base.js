/**
 * src/proxy/inbound/base.js
 * Shared inbound plumbing — session context creation, pipe wiring, and
 * DNS-over-TCP up-forward semantics (8.8.4.4:53), mirroring the current
 * edgetunnel forwardUDP/forwardTrojanUDPData behavior.
 */

import { newSession, Inbound, MemoryUser } from '../../common/session.js';
import { Network, Destination } from '../../common/net.js';
import { createRequestTCPConnector } from '../config.js';
import { getValidDataLength, toUint8Array } from '../../utils/helpers.js';
import { log } from '../../utils/helpers.js';

/** Serialize writes to a WritableStream through one locked writer. */
export class SerialWriter {
	constructor(writable) {
		this.writable = writable;
		this.locked = false;
	}

	async write(bytes) {
		const data = toUint8Array(bytes);
		if (!data.byteLength) return;
		if (!this.locked) {
			this.writer = this.writable.getWriter();
			this.locked = true;
		}
		await this.writer.write(data);
	}

	async close() {
		if (!this.locked) return;
		this.locked = false;
		try {
			await this.writer.close();
		} catch {
			/* ignore */
		}
	}
}

export class InboundServer {
	/**
	 * @param {{ dispatcher: import('../../features/routing.js').Dispatcher, tag?: string }} opts
	 */
	constructor({ dispatcher, tag = 'inbound' }) {
		this.dispatcher = dispatcher;
		this.tag = tag;
	}

	/** Fresh session context with inbound tag + user. */
	createSession({ email = '', id = null } = {}) {
		const ctx = newSession();
		ctx.inbound = new Inbound({
			tag: this.tag,
			user: new MemoryUser({ email, id }),
		});
		return ctx;
	}

	makeTarget(hostname, port, isUDP = false) {
		return new Destination(hostname, port, isUDP ? Network.UDP : Network.TCP);
	}

	/**
	 * Route a TCP connection and wire the pipe to the client duplex.
	 * Returns the pipe; write initial data into it before pumping.
	 */
	async dispatchTCP(ctx, dest) {
		return this.dispatcher.dispatch(ctx, dest);
	}

	/**
	 * Pump client bytes into the pipe (with initial data first), then close
	 * the pipe's input side on client EOF; interrupt the pipe on error.
	 */
	async pumpIncoming(duplexReadable, pipeWritable, initialData = null) {
		const writer = pipeWritable.getWriter();
		try {
			if (getValidDataLength(initialData) > 0) {
				await writer.write(toUint8Array(initialData));
			}
			const reader = duplexReadable.getReader();
			try {
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (value?.byteLength) await writer.write(value);
				}
			} finally {
				reader.releaseLock();
			}
		} finally {
			try {
				await writer.close();
			} catch {
				/* pipe already interrupted */
			}
		}
	}

	/**
	 * Pump outbound response bytes to the client writable.
	 * Stream error (outbound died) is surfaced through onError.
	 */
	async pumpOutgoing(pipeReadable, duplexWritable) {
		await pipeReadable.pipeTo(duplexWritable, { preventClose: true });
	}

	/**
	 * Forward one DNS query over TCP to 8.8.4.4:53 (current edgetunnel
	 * forwardUDP semantics). The query is TCP-framed (2B length) when it is
	 * not already. Each response chunk is passed through onResponse which
	 * returns fragments (Array of Uint8Array) to write to the client.
	 *
	 * @param {Request} request
	 * @param {Uint8Array} query raw DNS payload (may carry TCP length prefix)
	 * @param {{ onResponse?: (chunk: Uint8Array) => Promise<Uint8Array[]|Uint8Array|null>, onError?: (err) => void }} opts
	 */
	async forwardDNS(request, query, { onResponse = null, onError = null } = {}) {
		const payload = toUint8Array(query);
		const requestData =
			payload.byteLength >= 2 && ((payload[0] << 8) | payload[1]) === payload.byteLength - 2
				? payload
				: (() => {
						const out = new Uint8Array(payload.byteLength + 2);
						out[0] = (payload.byteLength >>> 8) & 0xff;
						out[1] = payload.byteLength & 0xff;
						out.set(payload, 2);
						return out;
					})();
		try {
			const tcpConnector = createRequestTCPConnector(request);
			const tcpSocket = tcpConnector({ hostname: '8.8.4.4', port: 53 });
			const writer = tcpSocket.writable.getWriter();
			await writer.write(requestData);
			writer.releaseLock();
			const reader = tcpSocket.readable.getReader();
			try {
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					const chunk = toUint8Array(value);
					if (!chunk.byteLength) continue;
					let fragments = null;
					if (onResponse) {
						fragments = await onResponse(chunk);
					}
					if (fragments) {
						const list = Array.isArray(fragments) ? fragments : [fragments];
						for (const fragment of list) {
							if (fragment?.byteLength) await this.emit(fragment);
						}
					}
				}
			} finally {
				reader.releaseLock();
			}
		} catch (err) {
			log(`[UDPforward] DNS forward failed: ${err?.message || err}`);
			if (onError) onError(err);
		}
	}

	/** Emit response bytes to the client — overridden by protocol servers. */
	async emit(bytes) {
		throw new Error('emit not implemented');
	}
}
