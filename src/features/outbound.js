/**
 * src/features/outbound.js
 * Outbound handler & manager interfaces — mirror of Xray-core features/outbound.
 */

import { Feature } from './feature.js';

/** outbound.Handler — one outbound sink (Runnable + Tag + Dispatch(link)). */
export class Handler extends Feature {
	constructor(tag) {
		super();
		this.tag = tag;
		this.proxySettings = null;
		this.senderSettings = null;
	}

	type() {
		return Handler;
	}

	/**
	 * Dispatch a transport Link (reader/writer) toward the target.
	 * @param {import('../common/session.js').SessionContext} ctx
	 * @param {{reader: ReadableStream-like, writer: WritableStream-like}} link
	 */
	async dispatch(_ctx, _link) {
		throw new Error('outbound handler dispatch not implemented');
	}

	/**
	 * Dial a raw connection to dest (used by chained outbounds).
	 */
	async dial(_ctx, _dest) {
		throw new Error('outbound handler dial not implemented');
	}

	getTag() {
		return this.tag;
	}
}

/** outbound.Manager — tagged registry + default handler selection. */
export class Manager extends Feature {
	type() {
		return Manager;
	}

	async addHandler(_handler) {
		throw new Error('outbound manager addHandler not implemented');
	}
	async removeHandler(_tag) {
		throw new Error('outbound manager removeHandler not implemented');
	}
	getHandler(_tag) {
		return null;
	}
	getDefaultHandler() {
		return this.getHandler('freedom') || null;
	}
	listHandlers() {
		return [];
	}

	/**
	 * Prefix select (outbound.HandlerSelector): returns handlers whose tag starts
	 * with one of the prefixes.
	 */
	select(prefixes) {
		return this.listHandlers().filter((h) => prefixes.some((p) => h.tag.startsWith(p)));
	}
}