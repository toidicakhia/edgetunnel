/**
 * src/core/instance.js
 * Feature assembly — mirror of Xray-core core/xray.go.
 *
 * An Instance owns features[] and provides:
 *   - addFeature / getFeature / requireFeatures (with dependency resolution)
 *   - start() / close() lifecycle, cascading to features in order
 *   - defaults injection when required features are missing
 */

import { Feature } from '../features/feature.js';
import { LocalDNS } from '../features/dns.js';
import { DefaultManager as DefaultPolicyManager } from '../features/policy.js';
import { DefaultRouter } from '../features/routing.js';
import { NoopManager as NoopStatsManager } from '../features/stats.js';

export class Instance {
	constructor() {
		this.features = [];
		this.running = false;
		this.pendingResolutions = [];
		this.pendingOptionalResolutions = [];
	}

	isRunning() {
		return this.running;
	}

	/** Register a feature. Resolves pending RequireFeatures callbacks when possible. */
	addFeature(feature) {
		if (!(feature instanceof Feature) && typeof feature?.type !== 'function') {
			throw new Error('addFeature: not a feature');
		}
		this.features.push(feature);
		this._resolvePending();
		return feature;
	}

	/** Fetch a registered feature by class/type, or null. */
	getFeature(featureType) {
		if (typeof featureType === 'string') {
			return this.features.find((f) => String(f.type?.()) === featureType) || null;
		}
		return this.features.find((f) => {
			const t = f.type?.();
			return t === featureType || t?.name === featureType?.name;
		}) || null;
	}

	/** Fetch a feature or throw. */
	mustGetFeature(featureType) {
		const f = this.getFeature(featureType);
		if (!f) throw new Error(`required feature not found: ${featureType?.name || featureType}`);
		return f;
	}

	/**
	 * RequireFeatures(callback, optional) — call `callback(...features)` once all
	 * requested feature types are registered. Mirrors core/xray.go resolution.
	 *
	 * @param {Function} callback callback(...features)
	 * @param {Array<Function>} callback.depTypes feature types (constructor refs)
	 * @param {boolean} [optional]
	 */
	requireFeatures(callback, optional = false) {
		const depTypes = callback.depTypes || [];
		const pending = optional ? this.pendingOptionalResolutions : this.pendingResolutions;
		const resolution = {
			callback,
			depTypes,
			done: false,
		};
		pending.push(resolution);
		this._tryResolve(resolution);
		return resolution;
	}

	_tryResolve(resolution) {
		const features = resolution.depTypes.map((t) => this.getFeature(t));
		if (features.every((f) => f !== null)) {
			resolution.done = true;
			// remove from pending
			this.pendingResolutions = this.pendingResolutions.filter((r) => r !== resolution);
			this.pendingOptionalResolutions = this.pendingOptionalResolutions.filter((r) => r !== resolution);
			try {
				resolution.callback(...features);
			} catch (err) {
				// resolution callback errors are surfaced at require time, non-fatal
				resolution.error = err;
			}
		}
	}

	_resolvePending() {
		for (const r of [...this.pendingResolutions, ...this.pendingOptionalResolutions]) {
			if (!r.done) this._tryResolve(r);
		}
	}

	/** Start all features in registration order. */
	async start() {
		if (this.running) return;
		this.running = true;
		for (const feature of this.features) {
			if (typeof feature.start === 'function') await feature.start();
		}
	}

	/** Close all features (reverse order, errors aggregated). */
	async close() {
		if (!this.running) return;
		this.running = false;
		const errors = [];
		for (let i = this.features.length - 1; i >= 0; i--) {
			const feature = this.features[i];
			try {
				if (typeof feature.close === 'function') await feature.close();
			} catch (err) {
				errors.push(err);
			}
		}
		if (errors.length) throw new AggregateError(errors, 'instance close errors');
	}

	/** Install default fallback features (mirrors core/xray.go initInstanceWithConfig). */
	installDefaults({ dnsResolver = null } = {}) {
		if (!this.getFeature(LocalDNS)) {
			this.addFeature(new LocalDNS(dnsResolver));
		}
		if (!this.getFeature(DefaultPolicyManager)) {
			this.addFeature(new DefaultPolicyManager());
		}
		if (!this.getFeature(DefaultRouter)) {
			this.addFeature(new DefaultRouter());
		}
		if (!this.getFeature(NoopStatsManager)) {
			this.addFeature(new NoopStatsManager());
		}
	}
}

/** Reflect-style helper: require features of specific classes. */
export function depTypes(...types) {
	return (fn) => {
		fn.depTypes = types;
		return fn;
	};
}