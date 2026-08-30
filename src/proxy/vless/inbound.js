/**
 * src/proxy/vless/inbound.js
 * VLESS inbound server — Xray-core proxy/vless/inbound + current edgetunnel
 * flow (response header [version, 0], UDP = DNS-only, local speed-test 204).
 *
 * handleDuplex(duplex, firstChunk): parses the VLESS header from the first
 * client chunk and routes the connection to the dispatcher.
 */

import { parseVLESSRequest, encodeVLESSResponseHeader } from './encoding.js';
import { InboundServer, SerialWriter } from '../inbound/base.js';
import { LocalSpeedTest } from '../speedtest.js';
import { getValidDataLength, toUint8Array } from '../../utils/helpers.js';
import { log } from '../../utils/helpers.js';

export class VlessServer extends InboundServer {
	/**
	 * @param {{ dispatcher, uuid: string }} opts
	 */
	constructor({ dispatcher, uuid }) {
		super({ dispatcher, tag: 'vless' });
		this.uuid = uuid;
	}

	/**
	 * @param {{ readable, writable, close: () => void, closed: Promise<void> }} duplex
	 * @param {{ firstChunk: Uint8Array, request: Request, chainProxyType?: string|null }} opts
	 */
	async handleDuplex(duplex, { firstChunk, request, chainProxyType = null }) {
		const bytes = toUint8Array(firstChunk);
		const parsed = parseVLESSRequest(bytes, this.uuid);
		if (parsed?.hasError) throw new Error(parsed.message || 'Invalid VLESS request');
		const { port, hostname, version, isUDP, rawClientData } = parsed;
		const respHeader = encodeVLESSResponseHeader(version);

		// Local speed-test short-circuit (no chain proxy configured)
		if (LocalSpeedTest.shouldHandle(hostname, chainProxyType)) {
			const speedTest = new LocalSpeedTest({
				send: async (chunk) => {
					await duplex.writable.write(chunk);
				},
			});
			await speedTest.enter(respHeader, rawClientData);
			return this._pumpToHandler(duplex.readable, (chunk) => speedTest.handleData(chunk));
		}

		if (isUDP) {
			if (port !== 53) throw new Error('UDP is not supported');
			log(`[VLESS] UDP DNS session from ${hostname}:${port}`);
			const output = new SerialWriter(duplex.writable);
			let prefixPending = respHeader && respHeader.byteLength > 0;
			const forward = async (query) => {
				await this.forwardDNS(request, query, {
					onResponse: async (chunk) => {
						await this._writeWithPrefix(output, chunk, () => {
							const prefix = prefixPending ? respHeader : null;
							prefixPending = false;
							return prefix;
						});
						return null; // written via _writeWithPrefix
					},
				});
			};
			if (getValidDataLength(rawClientData) > 0) await forward(rawClientData);
			return this._pumpToHandler(duplex.readable, forward);
		}

		const ctx = this.createSession({ email: this.uuid, id: this.uuid });
		const dest = this.makeTarget(hostname, port, false);
		const link = await this.dispatcher.dispatch(ctx, dest);

		// Response header precedes the first outbound byte
		const writer = duplex.writable.getWriter();
		await writer.write(respHeader);
		writer.releaseLock();

		const incoming = this.pumpIncoming(duplex.readable, link.writable, rawClientData);
		const outgoing = this.pumpOutgoing(link.readable, duplex.writable);

		await Promise.allSettled([incoming, outgoing, link.closed]);
		duplex.close();
	}

	async _writeWithPrefix(output, chunk, getPrefix) {
		const prefix = getPrefix ? getPrefix() : null;
		if (prefix && prefix.byteLength) await output.write(prefix);
		if (chunk?.byteLength) await output.write(chunk);
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