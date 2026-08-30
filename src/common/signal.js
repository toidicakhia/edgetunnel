/**
 * src/common/signal.js
 * Completion signals and change notifiers — mirror of Xray-core common/signal.
 */

/**
 * done.Instance — a one-shot, idempotent completion signal (common/signal/done/done.go).
 * - wait() resolves (never rejects) once close() is called (even if already closed).
 * - done() returns true once closed.
 * - close() is idempotent and broadcasts to all waiters.
 */
export class Done {
	constructor() {
		this._done = false;
		this._waiters = [];
	}

	get() {
		return this._done;
	}
	done() {
		return this._done;
	}

	/** Resolve all waiters. Idempotent. Returns true if this call performed the close. */
	close() {
		if (this._done) return false;
		this._done = true;
		const waiters = this._waiters;
		this._waiters = [];
		for (const resolve of waiters) resolve();
		return true;
	}

	/** Promise that resolves once closed. */
	wait() {
		if (this._done) return Promise.resolve();
		return new Promise((resolve) => this._waiters.push(resolve));
	}
}

/**
 * signal.Notifier — non-blocking change notification (common/signal/notifier.go).
 * signal() records the change; wait() returns a promise (or resolved promise) for the change.
 */
export class Notifier {
	constructor() {
		this._signal = null;
	}

	/** Non-blocking record of a change. */
	signal() {
		this._signal = Promise.resolve();
	}

	/** Promise resolving immediately if signaled, otherwise when signal() is called. */
	wait() {
		if (this._signal) return this._signal;
		return new Promise((resolve) => {
			const prev = this.wait.bind(this);
			this.wait = () => {
				this.wait = prev;
				return this.wait();
			};
			this._resolve = resolve;
		});
	}

	_resolve() {}
}

/**
 * createDone — factory helper returning { done, wait, close } plain object.
 * Useful where callers prefer a plain API.
 */
export function createDone() {
	const d = new Done();
	return {
		get done() {
			return d.done();
		},
		wait: () => d.wait(),
		close: () => d.close(),
	};
}