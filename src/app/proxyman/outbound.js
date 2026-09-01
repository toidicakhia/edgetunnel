/**
 * src/app/proxyman/outbound.js
 * Outbound handler manager — mirror of Xray-core app/proxyman/outbound.go.
 */

import { Manager } from '../../features/outbound.js';

export class OutboundManager extends Manager {
	constructor() {
		super();
		this.handlers = new Map();
		this.defaultTag = '';
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
		if (!this.defaultTag || !this.handlers.has(this.defaultTag)) {
			this.defaultTag = handler.tag;
		}
	}

	async removeHandler(tag) {
		this.handlers.delete(tag);
		if (this.defaultTag === tag) {
			this.defaultTag = this.handlers.keys().next().value || '';
		}
	}

	getHandler(tag) {
		return this.handlers.get(tag) || null;
	}

	getDefaultHandler() {
		return (
			(this.defaultTag && this.handlers.get(this.defaultTag)) ||
			this.handlers.values().next().value ||
			null
		);
	}

	setDefaultHandler(tag) {
		if (this.handlers.has(tag)) this.defaultTag = tag;
	}

	listHandlers() {
		return [...this.handlers.values()];
	}

	/** buildHandlerRegistry iterator for rule groups. */
	select(prefixes) {
		const out = [];
		for (const [tag, h] of this.handlers) {
			if (prefixes.some((p) => tag.startsWith(p))) out.push(h);
		}
		return out;
	}
}
