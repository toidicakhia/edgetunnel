/**
 * src/app/policy/manager.js
 * Policy manager — mirror of Xray-core app/policy.
 * Level → SessionPolicy overrides + system policy.
 */

import { DefaultManager, SessionPolicy, SystemPolicy } from '../../features/policy.js';

export class PolicyManager extends DefaultManager {
	constructor({ levels = {} } = {}) {
		super();
		for (const [level, cfg] of Object.entries(levels || {})) {
			this.setLevel(Number(level), new SessionPolicy(cfg || {}));
		}
		this.systemPolicy = new SystemPolicy();
	}

	type() {
		return DefaultManager;
	}
}

export { SessionPolicy, SystemPolicy };