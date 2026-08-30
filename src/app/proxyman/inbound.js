/**
 * src/app/proxyman/inbound.js
 * Inbound handler manager — mirror of Xray-core app/proxyman/inbound.go.
 */

import { Manager } from '../../features/inbound.js';

export class InboundManager extends Manager {
	constructor() {
		super();
		this.handlers = new Map();
	}

	type() {
		return Manager;
	}

	async start() {
		for (const handler of this.handlers.values()) {
			if (typeof handler.start === 'function') await handler.start();
		}
	}

	async close() {
		for (const handler of this.handlers.values()) {
			if (typeof handler.close === 'function') await handler.close();
		}
	}

	async addHandler(handler) {
		this.handlers.set(handler.tag, handler);
	}

	async removeHandler(tag) {
		this.handlers.delete(tag);
	}

	getHandler(tag) {
		return this.handlers.get(tag) || null;
	}

	listHandlers() {
		return [...this.handlers.values()];
	}
}