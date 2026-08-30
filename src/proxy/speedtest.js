/**
 * src/proxy/speedtest.js
 * Local 204 speed-test mode — ported from src/handlers/ws.js
 * (handleWSLocalSpeedTestData / enableWSLocalSpeedTestMode).
 *
 * When active, incoming data is buffered and parsed as HTTP/1.x requests;
 * each complete request gets a 204 response (built by transport grain).
 */

import { concatByteData, getValidDataLength, toUint8Array } from '../utils/helpers.js';
import { isSpeedTestSite, buildWSLocal204Response } from '../transport/internet/grain.js';
import { vlessTextDecoder } from '../proxy/vless/encoding.js';

const REQUEST_LIMIT = 64 * 1024;

function findHTTPRequestHeaderEnd(data) {
	for (let i = 0; i <= data.byteLength - 4; i++) {
		if (data[i] === 0x0d && data[i + 1] === 0x0a && data[i + 2] === 0x0d && data[i + 3] === 0x0a)
			return i + 4;
	}
	return -1;
}

/**
 * Local speed-test responder.
 * @param {{ send: (bytes: Uint8Array) => Promise<void> }} output — where the
 *   204 response bytes go (raw duplex writable or a protocol-encrypted socket).
 */
export class LocalSpeedTest {
	constructor(output) {
		this.output = output;
		this.active = false;
		this.firstResponseHeader = null;
		this.cache = new Uint8Array(0);
	}

	static shouldHandle(hostname, chainProxyType) {
		return isSpeedTestSite(hostname) && chainProxyType === null;
	}

	/** Enter speed-test mode; optionally process the first request data. */
	async enter(respHeader, firstRequestData) {
		this.active = true;
		this.firstResponseHeader = respHeader;
		this.cache = new Uint8Array(0);
		if (getValidDataLength(firstRequestData) > 0) await this.handleData(firstRequestData);
	}

	async handleData(data) {
		if (!this.active) return;
		const chunk = toUint8Array(data);
		if (!chunk.byteLength) return;
		if (this.cache.byteLength + chunk.byteLength > REQUEST_LIMIT) {
			throw new Error('WS local speed-test request is too large');
		}
		this.cache = concatByteData(this.cache, chunk);
		while (this.cache.byteLength) {
			const headerEnd = findHTTPRequestHeaderEnd(this.cache);
			if (headerEnd === -1) return;
			const headerText = vlessTextDecoder.decode(this.cache.subarray(0, headerEnd));
			const contentLengthMatch = headerText.match(/(?:^|\r\n)content-length\s*:\s*(\d+)/i);
			const contentLength = contentLengthMatch ? Number(contentLengthMatch[1]) : 0;
			const requestLength = headerEnd + contentLength;
			if (!Number.isSafeInteger(contentLength) || requestLength > REQUEST_LIMIT) {
				throw new Error('WS local speed-test request body is too large');
			}
			if (this.cache.byteLength < requestLength) return;
			this.cache = this.cache.slice(requestLength);
			const respHeader = this.firstResponseHeader;
			this.firstResponseHeader = null;
			await this.output.send(buildWSLocal204Response(respHeader));
		}
	}
}