/**
 * src/core/context.js
 * Instance-in-context — mirror of Xray-core core/context.go.
 */

const XRAY_KEY = Symbol('xray.instance');

/** Attach the instance to a context carrier. */
export function withInstance(ctx, instance) {
	ctx.instance = instance;
	return ctx;
}

/** Read the instance from a context carrier, or null. */
export function instanceFromContext(ctx) {
	return ctx?.instance || null;
}

/** Read the instance or throw. */
export function mustFromContext(ctx) {
	const inst = instanceFromContext(ctx);
	if (!inst) throw new Error('xray instance not found in context');
	return inst;
}

export { XRAY_KEY };