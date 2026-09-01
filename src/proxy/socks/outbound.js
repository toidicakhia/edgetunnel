/**
 * src/proxy/socks/outbound.js
 * SOCKS5 chain outbound handler — routes link bytes through a socks5 upstream.
 */

import { Handler } from '../../features/outbound.js';
import { attachSocket, createRequestTCPConnector } from '../../transport/internet/tcp.js';
import { socks5Connect } from './client.js';

export class Socks5ChainHandler extends Handler {
	/**
	 * @param {string} tag handler tag (e.g. 'socks5')
	 * @param {{ request?: Request, proxyParams?: { hostname: string, port: number, username?: string, password?: string } }} opts
	 */
	constructor(tag, { request = null, proxyParams = null } = {}) {
		super(tag);
		this.request = request;
		this.proxyParams = proxyParams;
		this._connector = null;
	}

	getConnector() {
		if (!this._connector) {
			this._connector = createRequestTCPConnector(this.request);
		}
		return this._connector;
	}

	async dial(ctx, dest) {
		const connector = this.getConnector();
		if (!connector) throw new Error('socks5: no connector');
		const proxy = this.proxyParams;
		if (!proxy?.hostname) throw new Error('socks5: no proxy configured');
		return socks5Connect(dest.address, dest.port, new Uint8Array(0), connector, proxy);
	}

	async dispatch(ctx, link) {
		const dest = ctx.outbound?.target;
		if (!dest) throw new Error('socks5: no target');
		const socket = await this.dial(ctx, dest);
		return attachSocket(socket, link);
	}
}
