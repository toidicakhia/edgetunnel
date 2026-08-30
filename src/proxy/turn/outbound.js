/**
 * src/proxy/turn/outbound.js
 * TURN (coturn) chain outbound handler.
 */

import { Handler } from '../../features/outbound.js';
import { attachSocket, createRequestTCPConnector } from '../../transport/internet/tcp.js';
import { turnConnect } from './client.js';

export class TurnChainHandler extends Handler {
	/**
	 * @param {string} tag
	 * @param {{ request?: Request, proxyParams?: { hostname, port, username?, password? } }} opts
	 */
	constructor(tag, { request = null, proxyParams = null } = {}) {
		super(tag);
		this.request = request;
		this.proxyParams = proxyParams;
		this._connector = null;
	}

	getConnector() {
		if (!this._connector) this._connector = createRequestTCPConnector(this.request);
		return this._connector;
	}

	async dial(ctx, dest) {
		const connector = this.getConnector();
		if (!connector) throw new Error('turn: no connector');
		const proxy = this.proxyParams;
		if (!proxy?.hostname) throw new Error('turn: no proxy configured');
		return turnConnect(proxy, dest.address, dest.port, connector);
	}

	async dispatch(ctx, link) {
		const dest = ctx.outbound?.target;
		if (!dest) throw new Error('turn: no target');
		const socket = await this.dial(ctx, dest);
		return attachSocket(socket, link);
	}
}