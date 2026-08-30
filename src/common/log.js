/**
 * src/common/log.js
 * Logging message model + handler registry — mirror of Xray-core common/log.
 * The actual sink (console / KV) lives in app/log.
 */

export const Severity = Object.freeze({
	UNKNOWN: 0,
	ERROR: 1,
	WARNING: 2,
	INFO: 3,
	DEBUG: 4,
});

/** GeneralMessage — structured log entry (common/log/log.go GeneralMessage). */
export class GeneralMessage {
	/**
	 * @param {number} severity Severity value
	 * @param {string|string[]} content log content
	 */
	constructor(severity, content) {
		this.severity = severity;
		this.content = Array.isArray(content) ? content.join('') : String(content);
	}
}

/** AccessMessage — access-log entry (common/log/access.go). */
export class AccessMessage {
	/**
	 * @param {object} opts
	 * @param {string} opts.from source (ip:port)
	 * @param {string} opts.to   destination (host:port)
	 * @param {string} opts.status 'accepted' | 'rejected'
	 * @param {string} [opts.reason] rejection reason
	 * @param {string} [opts.email] user email
	 * @param {string} [opts.detour] outbound detour chain
	 */
	constructor({ from, to, status, reason = '', email = '', detour = '' }) {
		this.from = from;
		this.to = to;
		this.status = status;
		this.reason = reason;
		this.email = email;
		this.detour = detour;
	}
}

/**
 * maskAddress — MaskAddress from app/log/log.go: masks user email and IP tail.
 * Used so logs don't leak full credentials.
 */
export function maskAddress(text) {
	// mask email user portion
	return String(text).replace(/([^@\s]+)@/, (m, user) => {
		if (user.length <= 2) return '*'.repeat(user.length) + '@';
		return user.slice(0, 2) + '*'.repeat(user.length - 2) + '@';
	});
}

/** Registered log handlers. */
const handlers = new Set();
const accessHandlers = new Set();

/** Register a GeneralMessage handler: (message: GeneralMessage) => void. */
export function registerHandler(fn) {
	handlers.add(fn);
	return () => handlers.delete(fn);
}

/** Register an access-log handler: (message: AccessMessage) => void. */
export function registerAccessHandler(fn) {
	accessHandlers.add(fn);
	return () => accessHandlers.delete(fn);
}

/** Dispatch a general log message to all handlers. */
export function record({ severity = Severity.INFO, content = '' } = {}) {
	const msg = new GeneralMessage(severity, content);
	for (const fn of handlers) {
		try {
			fn(msg);
		} catch {
			/* handler errors never break logging */
		}
	}
}

/** Dispatch an access message. */
export function recordAccess(msg) {
	for (const fn of accessHandlers) {
		try {
			fn(msg);
		} catch {
			/* ignore */
		}
	}
}

/** Convenience leveled loggers. */
export const logDebug = (content) => record({ severity: Severity.DEBUG, content });
export const logInfo = (content) => record({ severity: Severity.INFO, content });
export const logWarn = (content) => record({ severity: Severity.WARNING, content });
export const logError = (content) => record({ severity: Severity.ERROR, content });