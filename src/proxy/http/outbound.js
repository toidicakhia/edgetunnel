/**
 * src/proxy/http/outbound.js
 * HTTP CONNECT chain outbound handler (plain http + https upstream).
 */

import { Handler } from '../../features/outbound.js';
import { attachSocket, createRequestTCPConnector } from '../../transport/internet/tcp.js';
import { httpConnect, httpsConnect } from './client.js';

export class HttpConnectChainHandler extends Handler {
	/**
	 * @param {string} tag
	 * @param {{ request?: Request, proxyParams?: { hostname, port, username?, password? }, https?: boolean }} opts
	 */
	constructor(tag, { request = null, proxyParams = null, https = false } = {}) {
		super(tag);
		this.request = request;
		this.proxyParams = proxyParams;
		this.https = https;
		this._connector = null;
	}

	getConnector() {
		if (!this._connector) this._connector = createRequestTCPConnector(this.request);
		return this._connector;
	}

	async dial(ctx, dest) {
		const connector = this.getConnector();
		if (!connector) throw new Error('http chain: no connector');
		const proxy = this.proxyParams;
		if (!proxy?.hostname) throw new Error('http chain: no proxy configured');
		if (this.https || (proxy.isHttps !== undefined ? proxy.isHttps : false)) {
			return httpsConnect(dest.address, dest.port, new Uint8Array(0), connector, {
				...proxy,
				// httpsConnect expects parsedSocks5 { hostname, port, username, password }
			});
		}
		return httpConnect(dest.address, dest.port, new Uint8Array(0), false, connector, proxy);
	}

	async dispatch(ctx, link) {
		const dest = ctx.outbound?.target;
		if (!dest) throw new Error('http chain: no target');
		const socket = await this.dial(ctx, dest);
		return attachSocket(socket, link);
	}
}