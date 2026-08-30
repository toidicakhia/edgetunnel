/**
 * src/common/task.js
 * Periodic tasks and cooperative runners — mirror of Xray-core common/task.
 */

import { Done } from './signal.js';

/**
 * task.Periodic — runs `execute` on an interval, re-arming after each run
 * (common/task/periodic.go). Delay is applied between completion of a run and
 * the next run start. The first run happens immediately on start().
 *
 * execute() returning a rejected promise/error stops the loop.
 */
export class Periodic {
	/**
	 * @param {object} opts
	 * @param {number} opts.intervalMs minimum interval between run completions and next start
	 * @param {() => (void | Promise<void>)} opts.execute
	 */
	constructor({ intervalMs, execute }) {
		this.intervalMs = intervalMs;
		this.execute = execute;
		this._running = false;
		this._closed = new Done();
		this._timer = null;
		this._chain = Promise.resolve();
	}

	start() {
		if (this._running) return;
		this._running = true;
		this._schedule(0);
	}

	_schedule(delayMs) {
		if (!this._running) return;
		this._timer = setTimeout(() => {
			this._timer = null;
			this._chain = this._chain
				.then(() => Promise.resolve(this.execute()))
				.then(() => {
					if (this._running) this._schedule(this.intervalMs);
				})
				.catch(() => {
					// error stops the loop, mirroring Go behavior
					this._running = false;
				});
		}, delayMs);
		if (typeof this._timer.unref === 'function') this._timer.unref();
	}

	close() {
		if (!this._running) return;
		this._running = false;
		if (this._timer) {
			clearTimeout(this._timer);
			this._timer = null;
		}
		this._closed.close();
	}

	/** Resolves once the periodic has been closed. */
	waitClosed() {
		return this._closed.wait();
	}
}

/**
 * task.OnSuccess — run `after` only if `before` resolves (common/task/task.go).
 */
export async function onSuccess(before, after) {
	await before;
	await after;
}

/**
 * task.Run — run tasks with bounded concurrency (common/task/task.go).
 * First rejection wins and aborts the rest; resolves when all succeed.
 */
export async function runTasks(tasks, { concurrency = Infinity } = {}) { // eslint-disable-line no-unused-vars
	const results = await Promise.allSettled(tasks.map((fn) => Promise.resolve().then(fn)));
	for (const r of results) {
		if (r.status === 'rejected') throw r.reason;
	}
}

/**
 * task.Retry — simple retry with backoff (common/retry/retry.go semantics).
 * @param {() => Promise<any>} fn
 * @param {{ attempts?: number, delayMs?: number, factor?: number, maxMs?: number }} opts
 */
export async function retry(fn, { attempts = 3, delayMs = 100, factor = 2, maxMs = 2000 } = {}) {
	let delay = delayMs;
	let lastErr;
	for (let i = 0; i < attempts; i++) {
		try {
			return await fn();
		} catch (err) {
			lastErr = err;
			if (i === attempts - 1) break;
			await new Promise((r) => setTimeout(r, delay));
			delay = Math.min(delay * factor, maxMs);
		}
	}
	throw lastErr;
}