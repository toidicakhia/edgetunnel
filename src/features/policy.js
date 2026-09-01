/**
 * src/features/policy.js
 * Policy feature — mirror of Xray-core features/policy + policy defaults.
 */

import { Feature } from './feature.js';

/** Session policy — per-connection timeouts and buffer guidance. */
export class SessionPolicy {
	constructor({
		connectionIdle = 300_000, // 300s idle (SessionDefault)
		uplinkOnly = 90_000,
		downlinkOnly = 90_000,
		handshake = 60_000,
		statsUplink = true,
		statsDownlink = true,
		bufferSize = -1, // -1 = system default
	} = {}) {
		this.connectionIdle = connectionIdle;
		this.uplinkOnly = uplinkOnly;
		this.downlinkOnly = downlinkOnly;
		this.handshake = handshake;
		this.statsUplink = statsUplink;
		this.statsDownlink = statsDownlink;
		this.bufferSize = bufferSize;
	}

	static default() {
		return new SessionPolicy();
	}
}

/** System policy. */
export class SystemPolicy {
	constructor({ statsUplink = true, statsDownlink = true, bufferSize = -1 } = {}) {
		this.statsUplink = statsUplink;
		this.statsDownlink = statsDownlink;
		this.bufferSize = bufferSize;
	}
}

/** policy.Manager — level → SessionPolicy + system policy. */
export class Manager extends Feature {
	type() {
		return Manager;
	}

	forLevel(_level) {
		return SessionPolicy.default();
	}
	forSystem() {
		return new SystemPolicy();
	}
}

/** DefaultManager — fallback feature installed when none configured. */
export class DefaultManager extends Manager {
	constructor() {
		super();
		this.levels = new Map();
	}

	setLevel(level, policy) {
		this.levels.set(level, policy);
	}

	forLevel(level) {
		return this.levels.get(level) || SessionPolicy.default();
	}
}
