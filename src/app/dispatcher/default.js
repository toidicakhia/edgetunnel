/**
 * src/app/dispatcher/default.js
 * Default dispatcher — mirror of Xray-core app/dispatcher/default.go.
 *
 * dispatch(ctx, dest):
 *   1. build the pipe Link (readable = client bytes, writable = response path)
 *   2. routedDispatch: forced outbound tag → router.pickRoute → default handler
 *   3. hand the Link to the chosen outbound handler; return the Link to the
 *      inbound handler (which feeds readable and drains writable)
 */

import { Dispatcher, Router } from '../../features/routing.js';
import { Manager as OutboundManager } from '../../features/outbound.js';
import { pipe } from '../../transport/pipe.js';
import { logError } from '../../common/log.js';

export class DefaultDispatcher extends Dispatcher {
	constructor(instance, { sniffing = null } = {}) {
		super();
		this.instance = instance;
		this.sniffing = sniffing; // { enabled, routeOnly } or null
	}

	type() {
		return Dispatcher;
	}

	async start() {}
	async close() {}

	/** Route: forced tag → router → default; returns the outbound handler. */
	_routedDispatch(ctx) {
		const outboundManager = this.instance.getFeature(OutboundManager);
		const router = this.instance.getFeature(Router);

		let handler = null;
		if (ctx.forcedOutboundTag) {
			handler = outboundManager?.getHandler?.(ctx.forcedOutboundTag) || null;
		}
		if (!handler && router) {
			try {
				const route = router.pickRoute(ctx);
				handler = route ? outboundManager?.getHandler?.(route.tag) || null : null;
			} catch (err) {
				if (err.code !== 'ErrNoClue') throw err;
				handler = null;
			}
		}
		if (!handler) handler = outboundManager?.getDefaultHandler?.() || null;
		if (!handler) {
			throw new Error('no available outbound handler');
		}
		return handler;
	}

	/**
	 * Dispatch to a destination.
	 * @param {import('../../common/session.js').SessionContext} ctx
	 * @param {import('../../common/net.js').Destination} dest
	 * @returns {{ readable: ReadableStream, writable: WritableStream, interrupt: () => void, closed: Promise<void> }}
	 */
	async dispatch(ctx, dest) {
		if (!ctx.outbound) {
			ctx.addOutbound({ target: dest, originalTarget: dest, tag: 'dispatcher' });
		}
		const p = pipe();
		const link = { readable: p.readable, writable: p.writable };
		const handler = this._routedDispatch(ctx);
		ctx.addOutbound({ target: dest, tag: handler.getTag?.() || handler.tag || '' });
		// dispatch async; errors interrupt the pipe + session
		handler
			.dispatch(ctx, link)
			.then(() => p.interrupt())
			.catch((err) => {
				p.interrupt();
				ctx.interrupt();
				if (!ctx.content.attributes.get('silent-error')) {
					logError(`[dispatcher] ${ctx.target?.toString?.() || ''}: ${err?.message || err}`);
				}
			});
		return p;
	}
}