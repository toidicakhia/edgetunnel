/**
 * src/common/log.js
 * Logging message model + handler registry — mirror of Xray-core common/log.
 * The actual sink (console / KV) lives in app/log.
 */

const Severity = Object.freeze({
	UNKNOWN: 0,
	ERROR: 1,
	WARNING: 2,
	INFO: 3,
	DEBUG: 4,
});

/** GeneralMessage — structured log entry (common/log/log.go GeneralMessage). */
class GeneralMessage {
	/**
	 * @param {number} severity Severity value
	 * @param {string|string[]} content log content
	 */
	constructor(severity, content) {
		this.severity = severity;
		this.content = Array.isArray(content) ? content.join('') : String(content);
	}
}

/** Registered log handlers. */
const handlers = new Set();

/** Dispatch a general log message to all handlers. */
function record({ severity = Severity.INFO, content = '' } = {}) {
	const msg = new GeneralMessage(severity, content);
	for (const fn of handlers) {
		try {
			fn(msg);
		} catch {
			/* handler errors never break logging */
		}
	}
}

export const logError = (content) => record({ severity: Severity.ERROR, content });