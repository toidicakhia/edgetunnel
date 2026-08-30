/**
 * src/app/stats/manager.js
 * Stats manager — mirror of Xray-core app/stats.
 * Counters registered per user email + uplink/downlink.
 */

import { NoopManager } from '../../features/stats.js';

export class StatsManager extends NoopManager {
	constructor() {
		super();
		this.onlineUsers = new Map();
	}

	type() {
		return NoopManager;
	}

	/** Counters: 'user>>><email>>>traffic>>>uplink' style names. */
	counterFor(email, dir) {
		return this.getOrRegister(`user>>>${email}>>>traffic>>>${dir}`);
	}

	recordUserTraffic(email, uplinkBytes, downlinkBytes) {
		if (!email) return;
		this.counterFor(email, 'uplink').add(uplinkBytes);
		this.counterFor(email, 'downlink').add(downlinkBytes);

		const now = Date.now();
		const existing = this.onlineUsers.get(email);
		if (existing) {
			existing.lastSeen = now;
		} else {
			this.onlineUsers.set(email, { email, lastSeen: now });
		}
	}

	/**
	 * The handler layer may request a KV snapshot (log.json shape):
	 * { users: { email: { uplink, downlink, lastSeen } }, counters: {...} }
	 */
	snapshot() {
		const users = {};
		for (const [email, u] of this.onlineUsers) {
			users[email] = {
				uplink: this.getOrRegister(`user>>>${email}>>>traffic>>>uplink`).value,
				downlink: this.getOrRegister(`user>>>${email}>>>traffic>>>downlink`).value,
				lastSeen: u.lastSeen,
			};
		}
		const counters = {};
		for (const [name, c] of this.registry) counters[name] = c.value;
		return { users, counters };
	}
}