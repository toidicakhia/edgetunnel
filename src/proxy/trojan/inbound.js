/**
 * src/proxy/trojan/inbound.js
 * Trojan inbound server — Xray-core proxy/trojan/inbound + current edgetunnel
 * flow (UDP = DNS-only via forwardTrojanUDPData semantics: address-port header
 * echoed in response frames; local speed-test 204).
 */

import { parseTrojanRequest, parseTrojanUDPPackets, encodeTrojanUDPPacket } from './encoding.js';
import { InboundServer, SerialWriter } from '../inbound/base.js';
import { LocalSpeedTest } from '../speedtest.js';
import { getTrojanPasswordHashes, matchTrojanPassword } from './encoding.js';
import { concatByteData, toUint8Array } from '../../utils/helpers.js';
import { log } from '../../utils/helpers.js';

export class TrojanServer extends InboundServer {
	/**
	 * @param {{ dispatcher, password: string }} opts
	 */
	constructor({ dispatcher, password }) {
		super({ dispatcher, tag: 'trojan' });
		this.password = password;
		this.passwordHashes = getTrojanPasswordHashes(password);
	}

	matches(data) {
		return matchTrojanPassword(data, this.passwordHashes);
	}

	/**
	 * @param {{ readable, writable, close: () => void, closed: Promise<void> }} duplex
	 * @param {{ firstChunk: Uint8Array, request: Request, chainProxyType?: string|null }} opts
	 */
	async handleDuplex(duplex, { firstChunk, request, chainProxyType = null }) {
		const bytes = toUint8Array(firstChunk);
		const parsed = parseTrojanRequest(bytes, this.password);
		if (parsed?.hasError) throw new Error(parsed.message || 'Invalid trojan request');
		const { port, hostname, isUDP, rawClientData } = parsed;

		if (LocalSpeedTest.shouldHandle(hostname, chainProxyType)) {
			const speedTest = new LocalSpeedTest({
				send: async (chunk) => {
					await duplex.writable.write(chunk);
				},
			});
			await speedTest.enter(null, rawClientData);
			// Remaining bytes after the header are the first speed-test request
			return this._pumpToHandler(duplex.readable, (chunk) => speedTest.handleData(chunk));
		}

		if (isUDP) {
			log(`[trojan] UDP DNS session from ${hostname}:${port}`);
			const output = new SerialWriter(duplex.writable);
			let udpBuffer = new Uint8Array(0);
			const forward = async (chunk) => {
				udpBuffer = concatByteData(udpBuffer, toUint8Array(chunk));
				const { packets, rest } = parseTrojanUDPPackets(udpBuffer, new Uint8Array(0));
				udpBuffer = rest;
				for (const packet of packets) {
					if (packet.dest.port !== 53) throw new Error('UDP is not supported');
					if (!packet.payload?.byteLength) continue;
					await this.forwardDNS(request, packet.payload, {
						onResponse: async (respChunk) => {
							// deframe TCP DNS [2B len][resp] and re-emit trojan frames
							await this._emitFramedTrojanResponse(output, packet, respChunk);
							return null;
						},
					});
				}
			};
			return this._pumpToHandler(duplex.readable, forward);
		}

		const rawClientData = rawClientData;
		const ctx = this.createSession({ email: this.password, id: this.password });
		const dest = this.makeTarget(hostname, port, false);
		const link = await this.dispatcher.dispatch(ctx, dest);
		const incoming = this.pumpIncoming(duplex.readable, link.writable, rawClientData);
		const outgoing = this.pumpOutgoing(link.readable, duplex.writable);
		await Promise.allSettled([incoming, outgoing, link.closed]);
		duplex.close();
	}

	/** Same as handleDuplex TCP path but without re-parsing (classification known). */
	async handlePreparedTCP(duplex, { hostname, port, rawClientData, request }) {
		const ctx = this.createSession({ email: this.password, id: this.password });
		const dest = this.makeTarget(hostname, port, false);
		const link = await this.dispatcher.dispatch(ctx, dest);
		const incoming = this.pumpIncoming(duplex.readable, link.writable, rawClientData);
		const outgoing = this.pumpOutgoing(link.readable, duplex.writable);
		await Promise.allSettled([incoming, outgoing, link.closed]);
		duplex.close();
	}

	async _emitFramedTrojanResponse(output, packet, respChunk) {
		// deframe the DNS TCP response (2B length prefix), echo the request's
		// address+port header in each frame (old forwardTrojanUDPData behavior)
		const input = toUint8Array(respChunk);
		const header = packet.addressPortHeader;
		let cursor = 0;
		while (cursor + 2 <= input.byteLength) {
			const len = (input[cursor] << 8) | input[cursor + 1];
			const start = cursor + 2;
			const end = start + len;
			if (end > input.byteLength) break;
			const payload = input.subarray(start, end);
			const frame = new Uint8Array(header.byteLength + 2 + 2 + 2 + payload.byteLength);
			frame.set(header, 0);
			frame[header.byteLength] = (payload.byteLength >>> 8) & 0xff;
			frame[header.byteLength + 1] = payload.byteLength & 0xff;
			frame[header.byteLength + 2] = 0x0d;
			frame[header.byteLength + 3] = 0x0a;
			frame.set(payload, header.byteLength + 4);
			await output.write(frame);
			cursor = end;
			if (end >= input.byteLength) return;
		}
	}

	async _pumpToHandler(readable, handler) {
		const reader = readable.getReader();
		try {
			while (true) {
				const { done, value } = await reader.read();
				if (done) break;
				if (value?.byteLength) await handler(value);
			}
		} finally {
			reader.releaseLock();
		}
	}
}