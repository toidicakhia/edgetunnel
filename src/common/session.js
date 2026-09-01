/**
 * src/common/session.js
 * Session context — mirror of Xray-core common/session/session.go + context.go.
 *
 * A session.Context travels with every request and carries:
 *   inbound  — who connected, which inbound tag, user
 *   outbound — the resolved outbound chain + original/target destinations
 *   content  — sniffing request + sniffed protocol + attributes
 */

import { Done } from './signal.js';

/** session.Content — mirrors session.Content. */
class Content {
	constructor({ protocol = '', sniffingRequest = null, attributes = null, skipDNSResolve = false } = {}) {
		this.protocol = protocol;
		this.sniffingRequest = sniffingRequest;
		this.attributes = attributes || new Map();
		this.skipDNSResolve = skipDNSResolve;
	}
}

/** session.Inbound — mirrors session.Inbound. */
export class Inbound {
	constructor({ source = null, local = null, gateway = null, tag = '', name = '', user = null, vlessRoute = null } = {}) {
		this.source = source; // Destination (remote addr)
		this.local = local; // Destination (local addr)
		this.gateway = gateway;
		this.tag = tag;
		this.name = name;
		this.user = user; // MemoryUser { email, level, id }
		this.vlessRoute = vlessRoute;
		this.conn = null;
		this.timer = null;
	}
}

/** MemoryUser — lightweight user (protocol.MemoryUser). */
export class MemoryUser {
	constructor({ email = '', level = 0, id = null, account = null } = {}) {
		this.email = email;
		this.level = level;
		this.id = id;
		this.account = account; // protocol account: { uuid?, password? }
	}
}

/**
 * SessionContext — the mutable carrier attached to a request lifecycle.
 * Mirrors the union of session.ContextWith* accessors.
 */
export class SessionContext {
	constructor() {
		this.inbound = null;
		this.outbounds = []; // chain of outbound hops; last = current
		this.content = new Content();
		this.sockopt = null;
		this.forcedOutboundTag = '';
		this.dispatcher = null;
		this.instance = null;
		this.interrupted = new Done();
	}

	get outbound() {
		return this.outbounds.length ? this.outbounds[this.outbounds.length - 1] : null;
	}

	get target() {
		return this.outbound?.target || null;
	}

	/** append an outbound hop (chaining) */
	addOutbound(ob) {
		this.outbounds.push(ob);
		return ob;
	}

	/** push a forced outbound tag (session.SetForcedOutboundTagToContext) */
	setForcedOutboundTag(tag) {
		this.forcedOutboundTag = tag;
	}

	interrupt() {
		this.interrupted.close();
	}

	/** Returns when interrupted. */
	waitInterrupted() {
		return this.interrupted.wait();
	}
}

/** Create a fresh SessionContext. */
export function newSession() {
	return new SessionContext();
}

