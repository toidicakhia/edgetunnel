/**
 * src/features/routing.js
 * Routing interfaces — mirror of Xray-core features/routing.
 */

import { Feature } from './feature.js';

/**
 * routing.Dispatcher — turns a connection into outbound traffic.
 * dispatch(ctx, destination) → { reader, writer } Link
 */
export class Dispatcher extends Feature {
	type() {
		return Dispatcher;
	}

	async dispatch(_ctx, _destination) {
		throw new Error('dispatcher.dispatch not implemented');
	}
}

/**
 * routing.Router — route decision from session context.
 * pickRoute(ctx) → { tag, ruleTag?, groupTags? } or throws ErrNoClue.
 */
export class Router extends Feature {
	type() {
		return Router;
	}

	pickRoute(_ctx) {
		const err = new Error('no matching route');
		err.code = 'ErrNoClue';
		throw err;
	}
}

/** Default router always returns ErrNoClue (installed when none configured). */
export class DefaultRouter extends Router {
	async start() {}
	async close() {}
	pickRoute() {
		const err = new Error('no matching route');
		err.code = 'ErrNoClue';
		throw err;
	}
}

/**
 * Route — a decision from pickRoute.
 * @returns {Route}
 */
export function newRoute(tag, { ruleTag = '', groupTags = [] } = {}) {
	return { tag, ruleTag, groupTags };
}
