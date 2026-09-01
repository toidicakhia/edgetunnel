/**
 * src/features/inbound.js
 * Inbound handler & manager interfaces — mirror of Xray-core features/inbound.
 */

import { Feature } from './feature.js';

/** inbound.Handler — one protocol listener (Runnable + Tag). */
export class Handler extends Feature {
	constructor(tag) {
		super();
		this.tag = tag;
	}

	type() {
		return Handler;
	}
}

/** inbound.Manager — registry of inbound handlers. */
export class Manager extends Feature {
	type() {
		return Manager;
	}

	async addHandler(_handler) {
		throw new Error('inbound manager addHandler not implemented');
	}
	async removeHandler(_tag) {
		throw new Error('inbound manager removeHandler not implemented');
	}
	getHandler(_tag) {
		return null;
	}
	listHandlers() {
		return [];
	}
}
