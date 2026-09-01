/**
 * src/transport/pipe.js
 * In-memory byte pipe with backpressure and interrupt —
 * mirror of Xray-core transport/pipe.
 *
 * pipe() returns a { readable, writable } pair. Writes block until the reader
 * consumes (backpressure) unless `discardOverflow` is set. Closing/aborting
 * either side propagates to the other (EOF / error).
 */

import { Done } from '../common/signal.js';

/**
 * Create an in-memory pipe.
 * @param {{ highWaterMark?: number, discardOverflow?: boolean }} opts
 * @returns {{ readable: ReadableStream, writable: WritableStream, interrupt: () => void, closed: Promise<void> }}
 */
export function pipe({ highWaterMark = 4 * 1024 * 1024, discardOverflow = false } = {}) {
	let buffered = 0;
	const queue = [];
	const interruptDone = new Done();
	let waiters = [];
	let readableEnded = false;
	let writableEnded = false;
	let resolveClosed;
	const closed = new Promise((r) => (resolveClosed = r));

	const notify = () => {
		const w = waiters;
		waiters = [];
		for (const fn of w) fn();
	};

	const readable = new ReadableStream({
		pull(controller) {
			if (interruptDone.done() && queue.length === 0) {
				controller.close();
				return;
			}
			if (queue.length === 0 && !writableEnded && !interruptDone.done()) {
				// wait for data or end
				return new Promise((resolve) => waiters.push(resolve));
			}
			if (queue.length === 0) {
				controller.close();
				return;
			}
			const { data, size } = queue.shift();
			buffered -= size;
			controller.enqueue(data);
			notify(); // unblock writers
		},
		cancel() {
			readableEnded = true;
			notify();
		},
	});

	const writable = new WritableStream({
		async write(chunk) {
			if (interruptDone.done() || readableEnded) throw new Error('pipe: reader closed');
			const data = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
			if (discardOverflow && buffered + data.byteLength > highWaterMark) {
				// drop oldest to keep the newest (mirrors DiscardOverflow option semantics)
				while (buffered + data.byteLength > highWaterMark && queue.length > 1) {
					buffered -= queue.shift().size;
				}
			}
			while (buffered + data.byteLength > highWaterMark && !readableEnded && !interruptDone.done()) {
				await new Promise((resolve) => waiters.push(resolve));
			}
			if (interruptDone.done() || readableEnded) throw new Error('pipe: reader closed');
			const size = data.byteLength;
			queue.push({ data, size });
			buffered += size;
			notify();
		},
		close() {
			writableEnded = true;
			notify();
		},
		abort(reason) {
			writableEnded = true;
			notify();
			if (reason) interruptDone.close();
		},
	});

	const interrupt = () => {
		interruptDone.close();
		notify();
	};

	// settle closed when both sides end
	Promise.allSettled([
		readable.closed.catch(() => {}),
		writable.closed.catch(() => {}),
	]).then(() => resolveClosed());

	return { readable, writable, interrupt, closed };
}

