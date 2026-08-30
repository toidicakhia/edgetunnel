/**
 * src/transport/internet/grain.js
 * edgetunnel worker framing shim — chunk bundling for CF Worker streams.
 * Moved from src/core/grain.js (kept verbatim; no Xray-core equivalent).
 */
import {
	downlinkGrainLowWaterBytes,
	downlinkGrainMaxWaitRounds,
	downlinkGrainPacketBytes,
	downlinkGrainTailThreshold,
	uplinkBundleTargetBytes,
	uplinkQueueMaxBytes,
	uplinkQueueMaxEntries,
} from '../../constants.js';
import { closeSocketQuietly, webSocketSendAndAwait } from './tcp.js';
import { getValidDataLength, log, toUint8Array } from '../../utils/helpers.js';


export function createGrainBundler(capacity, copyBundleResult = false) {
	let queue = [];
	let head = 0;
	let byteCount = 0;
	let bundleBuffer = null;

	const isEmpty = () => head >= queue.length;
	const compact = () => {
		if (head > 32 && head * 2 >= queue.length) {
			queue = queue.slice(head);
			head = 0;
		}
	};
	const dequeue = () => {
		if (isEmpty()) return null;
		const item = queue[head];
		queue[head++] = undefined;
		byteCount -= item.chunk.byteLength;
		compact();
		return item;
	};

	return {
		get byteCount() {
			return byteCount;
		},
		get entryCount() {
			return queue.length - head;
		},
		get isEmpty() {
			return isEmpty();
		},
		clear(processItem = null) {
			if (processItem) {
				for (let i = head; i < queue.length; i++) {
					if (queue[i]) processItem(queue[i]);
				}
			}
			queue = [];
			head = 0;
			byteCount = 0;
		},
		collect(item) {
			if (!item?.chunk?.byteLength) return false;
			queue.push(item);
			byteCount += item.chunk.byteLength;
			return true;
		},
		bundle() {
			const first = dequeue();
			if (!first) return null;
			const items = [first];
			if (isEmpty() || first.chunk.byteLength >= capacity)
				return { chunk: first.chunk, items };

			let totalBytes = first.chunk.byteLength;
			let end = head;
			while (end < queue.length) {
				const nextBytes = totalBytes + queue[end].chunk.byteLength;
				if (nextBytes > capacity) break;
				totalBytes = nextBytes;
				end++;
			}
			if (end === head) return { chunk: first.chunk, items };

			const output = (bundleBuffer ||= new Uint8Array(capacity));
			output.set(first.chunk, 0);
			let offset = first.chunk.byteLength;
			while (head < end) {
				const next = queue[head];
				queue[head++] = undefined;
				byteCount -= next.chunk.byteLength;
				items.push(next);
				output.set(next.chunk, offset);
				offset += next.chunk.byteLength;
			}
			compact();
			const bundled = output.subarray(0, totalBytes);
			return { chunk: copyBundleResult ? bundled.slice() : bundled, items };
		},
	};
}

export function createUplinkGrainBundleStream(targetBytes = uplinkBundleTargetBytes) {
	const identity =
		typeof IdentityTransformStream !== 'undefined'
			? new IdentityTransformStream()
			: new TransformStream();
	const writer = identity.writable.getWriter();
	const buffer = new Uint8Array(targetBytes);
	let bufferLength = 0;
	let timer = null;
	let pendingWrite = null;
	let flushChain = Promise.resolve();

	const cleanupTimer = () => {
		if (timer) {
			clearTimeout(timer);
			timer = null;
		}
	};

	const serialWrite = async (chunk) => {
		if (pendingWrite) await pendingWrite;
		pendingWrite = writer.write(chunk);
		try {
			await pendingWrite;
		} finally {
			pendingWrite = null;
		}
	};

	const doFlush = async () => {
		if (bufferLength) {
			const chunk = buffer.slice(0, bufferLength);
			bufferLength = 0;
			await serialWrite(chunk);
		}
	};

	const queueFlush = () => {
		flushChain = flushChain.then(() => doFlush()).catch(() => {});
	};

	const startTimer = () => {
		if (timer) return;
		timer = setTimeout(() => {
			timer = null;
			queueFlush();
		}, 1);
	};

	return {
		readable: identity.readable,
		write: async (chunk) => {
			const data = toUint8Array(chunk);
			if (!data.byteLength) return;
			if (data.byteLength >= targetBytes) {
				cleanupTimer();
				if (bufferLength) await doFlush();
				await serialWrite(data);
				return;
			}
			if (bufferLength + data.byteLength >= targetBytes) {
				const output = new Uint8Array(bufferLength + data.byteLength);
				output.set(buffer.subarray(0, bufferLength), 0);
				output.set(data, bufferLength);
				bufferLength = 0;
				cleanupTimer();
				await serialWrite(output);
			} else {
				buffer.set(data, bufferLength);
				bufferLength += data.byteLength;
				startTimer();
			}
		},
		end: async () => {
			cleanupTimer();
			try {
				await flushChain;
				await doFlush();
				await writer.close();
			} finally {
				try {
					writer.releaseLock();
				} catch {}
			}
		},
	};
}

export function createUplinkWriteQueue({
	getWriter,
	getConnectionTask = null,
	releaseWriter,
	retryConnection,
	closeConnection,
	name = 'uplink queue',
}) {
	const grain = createGrainBundler(uplinkBundleTargetBytes);
	let draining = false;
	let closed = false;
	let idleResolvers = [];
	let activeCompletions = null;

	const settleCompletions = (completions, err = null) => {
		if (!completions) return;
		for (const completion of completions) {
			if (err) completion.reject(err);
			else completion.resolve();
		}
	};

	const resolveIdle = () => {
		if (grain.byteCount || draining || !idleResolvers.length) return;
		const resolvers = idleResolvers;
		idleResolvers = [];
		for (const resolve of resolvers) resolve();
	};

	const clear = (err = null) => {
		const closeErr = err || (closed ? new Error(`${name}: queue closed`) : null);
		if (closeErr) {
			grain.clear((item) => settleCompletions(item.completions, closeErr));
			settleCompletions(activeCompletions, closeErr);
			activeCompletions = null;
		} else grain.clear();
		resolveIdle();
	};

	const bundle = () => {
		const packed = grain.bundle();
		if (!packed) return null;
		let allowRetry = true;
		let completions = null;
		for (const item of packed.items) {
			allowRetry = allowRetry && item.allowRetry;
			if (item.completions)
				completions = completions ? completions.concat(item.completions) : item.completions;
		}
		return { chunk: packed.chunk, allowRetry, completions };
	};

	const waitForAvailableWriter = async () => {
		const writer = getWriter();
		if (writer) return writer;
		const connectionTask = getConnectionTask?.();
		if (connectionTask) await connectionTask;
		return getWriter();
	};

	const drain = async () => {
		if (draining || closed) return;
		draining = true;
		try {
			for (;;) {
				if (closed) break;
				const item = bundle();
				if (!item) break;
				const completions = item.completions || null;
				activeCompletions = completions;
				try {
					let writer = await waitForAvailableWriter();
					if (closed) break;
					if (!writer) throw new Error(`${name}: remote writer unavailable`);
					try {
						await writer.write(item.chunk);
					} catch (err) {
						releaseWriter?.();
						if (closed) break;
						if (!item.allowRetry || typeof retryConnection !== 'function') throw err;
						await retryConnection();
						if (closed) break;
						writer = getWriter();
						if (!writer) throw err;
						await writer.write(item.chunk);
					}
					settleCompletions(completions);
				} catch (err) {
					settleCompletions(completions, err);
					throw err;
				} finally {
					if (activeCompletions === completions) activeCompletions = null;
				}
			}
		} catch (err) {
			closed = true;
			clear(err);
			log(`[${name}] write failed: ${err?.message || err}`);
			try {
				closeConnection?.(err);
			} catch {}
		} finally {
			draining = false;
			if (!closed && !grain.isEmpty) drain();
			else resolveIdle();
		}
	};

	const enqueue = (data, allowRetry = true, waitForFlush = false) => {
		if (closed) return false;
		// firstPacketparse stage has no writer no connection task；return false pass to upper layerprotocolparse。
		// sessionEstablishedRedialCollect，drain will wait for new writer，avoid data being mistaken asfirstPacket。
		if (!getWriter() && !getConnectionTask?.()) return false;
		const chunk = toUint8Array(data);
		if (!chunk.byteLength) return true;
		const nextBytes = grain.byteCount + chunk.byteLength;
		const nextItems = grain.entryCount + 1;
		if (nextBytes > uplinkQueueMaxBytes || nextItems > uplinkQueueMaxEntries) {
			closed = true;
			const err = Object.assign(
				new Error(`${name}: upload queue overflow (${nextBytes}B/${nextItems})`),
				{ isQueueOverflow: true }
			);
			clear(err);
			log(`[${name}] queue exceeded，closeConnection`);
			try {
				closeConnection?.(err);
			} catch {}
			throw err;
		}
		let completionPromise = null;
		let completions = null;
		if (waitForFlush) {
			completions = [];
			completionPromise = new Promise((resolve, reject) =>
				completions.push({ resolve, reject })
			);
		}
		grain.collect({ chunk, allowRetry, completions });
		if (!draining) drain();
		return waitForFlush ? completionPromise.then(() => true) : true;
	};

	return {
		write(data, allowRetry = true) {
			return enqueue(data, allowRetry, false);
		},
		writeAndAwait(data, allowRetry = true) {
			return enqueue(data, allowRetry, true);
		},
		async waitEmpty() {
			if (!grain.byteCount && !draining) return;
			await new Promise((resolve) => idleResolvers.push(resolve));
		},
		clear() {
			closed = true;
			clear();
		},
	};
}

export function createDownlinkGrainSender(webSocket, headerData = null, isActive = null) {
	const packetCap = downlinkGrainPacketBytes;
	const tailBytes = downlinkGrainTailThreshold;
	const grain = createGrainBundler(packetCap, true);
	let header = typeof headerData === 'function' ? null : headerData;
	const getResponseHeader =
		typeof headerData === 'function'
			? headerData
			: () => {
					const value = header;
					header = null;
					return value;
				};
	let flushTimer = null;
	let generation = 0;
	let scheduledGeneration = 0;
	let waitRounds = 0;
	let flushPromise = null;
	let directSendPromise = null;
	let forceDrain = false;
	let stopStarted = false;
	let activeSendCount = 0;
	let activeDirectSendCount = 0;
	let activeSendError = null;
	let activeSendWaiters = [];
	const waitForActiveSendComplete = () => {
		if (!activeSendCount && !activeDirectSendCount) return Promise.resolve();
		return new Promise((resolve) => activeSendWaiters.push(resolve));
	};
	const markSendComplete = () => {
		if (activeSendCount || activeDirectSendCount || !activeSendWaiters.length) return;
		const resolvers = activeSendWaiters;
		activeSendWaiters = [];
		for (const resolve of resolvers) resolve();
	};
	const checkActiveSendError = () => {
		if (!activeSendError) return;
		const err = activeSendError;
		grain.clear();
		throw err;
	};
	const isCurrentSenderActive = () => forceDrain || !isActive || isActive();
	const closeActiveConnection = () => {
		if (isCurrentSenderActive()) closeSocketQuietly(webSocket);
	};

	const sendRawChunk = async (chunk) => {
		if (!isCurrentSenderActive()) return;
		if (webSocket.readyState !== WebSocket.OPEN) throw new Error('ws.readyState is not open');
		chunk = prependResponseHeader(chunk);
		await webSocketSendAndAwait(webSocket, chunk);
	};

	const serialSendRawChunk = async (chunk) => {
		while (directSendPromise) await directSendPromise;
		const sendTask = sendRawChunk(chunk);
		directSendPromise = sendTask;
		try {
			await sendTask;
		} finally {
			if (directSendPromise === sendTask) directSendPromise = null;
		}
	};

	const prependResponseHeader = (chunk) => {
		const responseHeader = getResponseHeader();
		if (!responseHeader) return chunk;
		const merged = new Uint8Array(responseHeader.length + chunk.byteLength);
		merged.set(responseHeader, 0);
		merged.set(chunk, responseHeader.length);
		return merged;
	};

	const flush = async () => {
		while (flushPromise) await flushPromise;
		if (flushTimer) clearTimeout(flushTimer);
		flushTimer = null;
		waitRounds = 0;
		if (!isCurrentSenderActive()) {
			grain.clear();
			return;
		}
		const sendtask = (async () => {
			for (;;) {
				if (!isCurrentSenderActive()) {
					grain.clear();
					break;
				}
				const packed = grain.bundle();
				if (!packed) break;
				await serialSendRawChunk(packed.chunk);
			}
		})();
		flushPromise = sendtask
			.catch((err) => {
				activeSendError ||= err;
				throw err;
			})
			.finally(() => {
				flushPromise = null;
			});
		return flushPromise;
	};

	const scheduleFlush = () => {
		if (!isCurrentSenderActive()) {
			grain.clear();
			return;
		}
		if (grain.isEmpty || flushTimer) return;
		if (grain.byteCount >= packetCap || packetCap - grain.byteCount < tailBytes) {
			flush().catch(closeActiveConnection);
			return;
		}
		flushTimer = setTimeout(() => {
			flushTimer = null;
			if (!isCurrentSenderActive()) {
				grain.clear();
				return;
			}
			if (grain.isEmpty) return;
			if (grain.byteCount >= packetCap || packetCap - grain.byteCount < tailBytes) {
				flush().catch(closeActiveConnection);
				return;
			}
			if (
				waitRounds < downlinkGrainMaxWaitRounds &&
				(generation !== scheduledGeneration || grain.byteCount < downlinkGrainLowWaterBytes)
			) {
				waitRounds++;
				scheduledGeneration = generation;
				scheduleFlush();
				return;
			}
			flush().catch(closeActiveConnection);
		}, 1);
	};

	return {
		async directSend(data) {
			if (stopStarted || !isCurrentSenderActive()) return;
			activeDirectSendCount++;
			try {
				const chunk = toUint8Array(data);
				if (!chunk.byteLength) return;
				await serialSendRawChunk(chunk);
			} catch (err) {
				activeSendError ||= err;
				throw err;
			} finally {
				activeDirectSendCount--;
				markSendComplete();
			}
		},
		async send(data) {
			if (stopStarted || !isCurrentSenderActive()) return;
			activeSendCount++;
			try {
				const chunk = toUint8Array(data);
				if (!chunk.byteLength) return;
				let offset = 0;
				const totalBytes = chunk.byteLength;
				while (offset < totalBytes) {
					const remainingBytes = totalBytes - offset;
					if (grain.isEmpty && remainingBytes >= packetCap) {
						const sendBytes = Math.min(packetCap, remainingBytes);
						const view =
							offset || sendBytes !== totalBytes
								? chunk.subarray(offset, offset + sendBytes)
								: chunk;
						await serialSendRawChunk(view);
						offset += sendBytes;
						continue;
					}
					const copyBytes = Math.min(packetCap - grain.byteCount, totalBytes - offset);
					if (!copyBytes) {
						await flush();
						continue;
					}
					grain.collect({
						chunk:
							offset || copyBytes !== totalBytes
								? chunk.subarray(offset, offset + copyBytes)
								: chunk,
					});
					offset += copyBytes;
					generation++;
					if (grain.byteCount >= packetCap || packetCap - grain.byteCount < tailBytes)
						await flush();
					else scheduleFlush();
				}
			} catch (err) {
				activeSendError ||= err;
				throw err;
			} finally {
				activeSendCount--;
				markSendComplete();
			}
		},
		flush,
		async stopAndFlush() {
			if (stopStarted) {
				await waitForActiveSendComplete();
				while (directSendPromise) await directSendPromise;
				checkActiveSendError();
				await flush();
				return;
			}
			stopStarted = true;
			forceDrain = true;
			if (flushTimer) clearTimeout(flushTimer);
			flushTimer = null;
			await waitForActiveSendComplete();
			while (directSendPromise) await directSendPromise;
			checkActiveSendError();
			await flush();
		},
	};
}

export async function connectStreams(
	remoteSocket,
	webSocket,
	headerData,
	retryFunc,
	isCurrentSocket = null,
	remoteConnWrapper = null
) {
	let header = headerData,
		hasData = false,
		reader,
		useBYOB = false,
		readError = null;
	const BYOBSingleReadLimit = 64 * 1024;
	const currentIsConnectionStillValid = () => !isCurrentSocket || isCurrentSocket();
	const downlinkSender = createDownlinkGrainSender(
		webSocket,
		header,
		currentIsConnectionStillValid
	);
	header = null;
	const downlinkController = { stopAndFlush: () => downlinkSender.stopAndFlush() };
	if (remoteConnWrapper) remoteConnWrapper.downlinkController = downlinkController;
	try {
		remoteSocket.closed?.catch?.(() => {});
	} catch {}

	try {
		reader = remoteSocket.readable.getReader({ mode: 'byob' });
		useBYOB = true;
	} catch {
		reader = remoteSocket.readable.getReader();
	}

	try {
		if (!useBYOB) {
			while (true) {
				const { done, value } = await reader.read();
				if (!currentIsConnectionStillValid()) break;
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (value.byteLength >= downlinkGrainPacketBytes) {
					await downlinkSender.flush();
					await downlinkSender.directSend(value);
				} else {
					await downlinkSender.send(value);
				}
			}
		} else {
			let readBuffer = new ArrayBuffer(BYOBSingleReadLimit);
			while (true) {
				const { done, value } = await reader.read(
					new Uint8Array(readBuffer, 0, BYOBSingleReadLimit)
				);
				if (!currentIsConnectionStillValid()) break;
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (value.byteLength >= downlinkGrainPacketBytes) {
					await downlinkSender.flush();
					await downlinkSender.directSend(value);
					readBuffer = new ArrayBuffer(BYOBSingleReadLimit);
				} else {
					await downlinkSender.send(value.slice());
					readBuffer =
						value.buffer.byteLength >= BYOBSingleReadLimit
							? value.buffer
							: new ArrayBuffer(BYOBSingleReadLimit);
				}
			}
		}
		if (currentIsConnectionStillValid()) await downlinkSender.flush();
	} catch (err) {
		readError = err;
	} finally {
		if (currentIsConnectionStillValid() && webSocket.readyState === WebSocket.OPEN) {
			try {
				await downlinkSender.stopAndFlush();
			} catch (err) {
				readError ||= err;
			}
		}
		if (remoteConnWrapper?.downlinkController === downlinkController)
			remoteConnWrapper.downlinkController = null;
		try {
			await reader.cancel();
		} catch {}
		try {
			reader.releaseLock();
		} catch {}
		try {
			remoteSocket.close();
		} catch {}
	}
	if (
		!hasData &&
		retryFunc &&
		webSocket.readyState === WebSocket.OPEN &&
		currentIsConnectionStillValid()
	) {
		try {
			await retryFunc();
			return;
		} catch (err) {
			readError ||= err;
		}
	}
	if (!currentIsConnectionStillValid()) return;
	if (readError) log(`[TCPdownlink] read failed: ${readError?.message || readError}`);
	closeSocketQuietly(webSocket);
}

export function isSpeedTestSite(hostname) {
	const speedTestDomains = ['speed.cloudflare.com', 'cp.cloudflare.com'];
	hostname = hostname.toLowerCase();
	return speedTestDomains.some(
		(domain) => hostname === domain || hostname.endsWith('.' + domain)
	);
}

export function buildLocal204Response(respHeader = null) {
	const local204Response = new TextEncoder().encode(
		'HTTP/1.1 204 No Content\r\n' + 'Content-Length: 0\r\n' + 'Connection: close\r\n' + '\r\n'
	);
	if (getValidDataLength(respHeader) === 0) return local204Response;
	const protocolResponseHeader = toUint8Array(respHeader);
	const response = new Uint8Array(
		protocolResponseHeader.byteLength + local204Response.byteLength
	);
	response.set(protocolResponseHeader, 0);
	response.set(local204Response, protocolResponseHeader.byteLength);
	log(`[TCPforward] buildLocal204Response: ${response.byteLength}B`);
	return response;
}

export function buildWSLocal204Response(respHeader = null) {
	const WSlocal204Response = new TextEncoder().encode(
		'HTTP/1.1 204 No Content\r\n' +
			'Content-Length: 0\r\n' +
			'Connection: keep-alive\r\n' +
			'\r\n'
	);
	if (getValidDataLength(respHeader) === 0) return WSlocal204Response;
	const protocolResponseHeader = toUint8Array(respHeader);
	const response = new Uint8Array(
		protocolResponseHeader.byteLength + WSlocal204Response.byteLength
	);
	response.set(protocolResponseHeader, 0);
	response.set(WSlocal204Response, protocolResponseHeader.byteLength);
	return response;
}

///////////////////////////////////////////////////////SOCKS5/HTTPfunction///////////////////////////////////////////////
