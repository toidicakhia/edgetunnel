/**
 * src/features/feature.js
 * Base feature contract — mirror of Xray-core features/feature.go.
 * A Feature = common.HasType + common.Runnable: every app/* module implements this.
 */

export class Feature {
	/** Type discriminator for GetFeature/RequireFeatures. */
	type() {
		throw new Error('feature.type() not implemented');
	}

	/** Start the feature (idempotent). */
	async start() {}

	/** Close the feature (idempotent). */
	async close() {}

	/** Human-readable tag, e.g. 'dispatcher'. */
	get name() {
		return this.constructor.name;
	}
}
