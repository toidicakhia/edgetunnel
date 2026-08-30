/**
 * src/features/stats.js
 * Stats feature — mirror of Xray-core features/stats.
 */

import { Feature } from './feature.js';

/** A single counter (atomic-ish for single-threaded JS). */
export class Counter {
	constructor(name, value = 0) {
		this.name = name;
		this.value = value;
	}

	add(delta) {
		this.value += delta;
		return this.value;
	}

	clear() {
		this.value = 0;
	}
}

/** Online user map entry. */
export class OnlineUser {
	constructor({ user = null, lastSeen = Date.now() } = {}) {
		this.user = user;
		this.lastSeen = lastSeen;
	}
}

/** stats.Manager — counters, online maps, channels. */
export class Manager extends Feature {
	type() {
		return Manager;
	}

	register() {
		throw new Error('stats manager register not implemented');
	}
	getOrRegister() {
		throw new Error('stats manager getOrRegister not implemented');
	}
	unregister() {
		throw new Error('stats manager unregister not implemented');
	}
}

/** NoopManager — default fallback (no-op counters). */
export class NoopManager extends Manager {
	constructor() {
		super();
		this.registry = new Map();
	}

	async start() {}
	async close() {}

	register(counter) {
		this.registry.set(counter.name, counter);
		return counter;
	}
	getOrRegister(name, init = 0) {
		let c = this.registry.get(name);
		if (!c) {
			c = new Counter(name, init);
			this.registry.set(name, c);
		}
		return c;
	}
	unregister(name) {
		this.registry.delete(name);
	}
	listCounters() {
		return [...this.registry.values()];
	}
}