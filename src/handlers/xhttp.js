/**
 * src/handlers/xhttp.js
 * Auto-generated from _worker.js refactor
 * Original: edgetunnel 2.1 (2026-08-11)
 */
import {
	buildLocal204Response,
	createUplinkGrainBundleStream,
	isSpeedTestSite,
} from '../core/grain.js';
import { closeSocketQuietly, forwardTCP, forwardUDP } from '../core/tcp.js';
import { forwardTrojanUDPData, uuidBytesMatch, vlessTextDecoder } from '../core/protocol.js';
import { log } from '../utils/helpers.js';
import { sha224 } from '../utils/crypto.js';

export const HPACKHuffmanCodeLen = [
	13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
	28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5, 5,
	6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
	6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23,
	23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22, 21, 20,
	22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22,
	22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19, 21, 26,
	27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25,
	25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26, 30,
];

export function getXHTTPPaddingIdentifiers(yourUUID) {
	return { head: yourUUID.slice(1, 7), key: '_' + yourUUID.slice(25, 31) };
}

export function calculateHPACKHuffmanByteLength(str) {
	const bytes = new TextEncoder().encode(str);
	let totalBits = 0;
	for (let i = 0; i < bytes.length; i++) {
		totalBits += HPACKHuffmanCodeLen[bytes[i]];
	}
	return Math.ceil(totalBits / 8);
}

export function extractXHTTPPaddingValue(request, localPaddingHeader, localPaddingKey) {
	const headerValue = request.headers.get(localPaddingHeader);
	if (headerValue) {
		try {
			const parsedURL = new URL(headerValue, 'https://x.invalid');
			const queryValue = parsedURL.searchParams.get(localPaddingKey);
			if (queryValue) return queryValue;
		} catch (e) {}
		return headerValue;
	}
	const requestURL = new URL(request.url);
	return requestURL.searchParams.get(localPaddingKey) || '';
}

export function validateXHTTPPadding(request, localPaddingHeader, localPaddingKey) {
	const paddingValue = extractXHTTPPaddingValue(request, localPaddingHeader, localPaddingKey);
	if (!paddingValue) return true;
	const huffmanlength = calculateHPACKHuffmanByteLength(paddingValue);
	return huffmanlength >= 98 && huffmanlength <= 1002;
}

export const xhttpBase62Charset = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

export function generateXHTTPPaddingString(length) {
	const charsetLen = xhttpBase62Charset.length;
	let result = '';
	for (let i = 0; i < length; i++) {
		result += xhttpBase62Charset[Math.floor(Math.random() * charsetLen)];
	}
	return result;
}

export async function handleXHTTPRequest(request, yourUUID, proxyContext = {}) {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const { head: localPaddingHeader, key: localPaddingKey } = getXHTTPPaddingIdentifiers(yourUUID);
	if (!validateXHTTPPadding(request, localPaddingHeader, localPaddingKey))
		return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const firstPacket = await readXHTTPFirstPacket(reader, yourUUID);
	if (!firstPacket) {
		try {
			reader.releaseLock();
		} catch (e) {}
		return new Response('Invalid request', { status: 400 });
	}
	if (isSpeedTestSite(firstPacket.hostname) && proxyContext.proxyType === null) {
		try {
			reader.releaseLock();
		} catch (e) {}
		return new Response(buildLocal204Response(firstPacket.respHeader), {
			status: 200,
			headers: {
				'Content-Type': 'application/octet-stream',
				'X-Accel-Buffering': 'no',
				'Cache-Control': 'no-store',
			},
		});
	}
	if (firstPacket.isUDP && firstPacket.protocol !== 'trojan' && firstPacket.port !== 53) {
		try {
			reader.releaseLock();
		} catch (e) {}
		return new Response('UDP is not supported', { status: 400 });
	}

	const responseHeaders = new Headers({
		'Content-Type': 'application/octet-stream',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store',
	});

	try {
		const responseURL = new URL('https://x.invalid/');
		responseURL.searchParams.set(
			localPaddingKey,
			generateXHTTPPaddingString(100 + Math.floor(Math.random() * 901))
		);
		responseHeaders.set(localPaddingHeader, responseURL.toString());
	} catch (e) {}

	if (firstPacket.isUDP)
		return handleXHTTPUDPRequest(firstPacket, reader, request, proxyContext, responseHeaders);

	try {
		reader.releaseLock();
	} catch (e) {}

	const remoteConnWrapper = {
		socket: null,
		connectingPromise: null,
		retryConnect: null,
		downlinkDrain: Promise.resolve(),
	};
	const abortController = new AbortController();
	let isCleaned = false;
	const cleanup = (reason) => {
		if (isCleaned) return;
		isCleaned = true;
		try {
			abortController.abort(reason);
		} catch (e) {}
		invalidateTCPConnectorGeneration(remoteConnWrapper);
	};

	const placeholderWS = { readyState: WebSocket.OPEN };

	let socket;
	try {
		socket = await forwardTCP(
			firstPacket.hostname,
			firstPacket.port,
			firstPacket.rawData,
			placeholderWS,
			firstPacket.respHeader,
			remoteConnWrapper,
			yourUUID,
			request,
			proxyContext,
			firstPacket.protocol === 'trojan',
			firstPacket.rawData,
			true
		);
	} catch (err) {
		log(`[XHTTP-Pipe] connection failed: ${err?.message || err}`);
		cleanup(err);
		return new Response('bad gateway', { status: 502 });
	}
	if (!socket) {
		cleanup(new Error('socket is null'));
		return new Response('bad gateway', { status: 502 });
	}

	const uplinkPromise = (async () => {
		const uplinkBundler = createUplinkGrainBundleStream();
		const pipePromise = uplinkBundler.readable.pipeTo(socket.writable, {
			signal: abortController.signal,
		});
		void pipePromise.catch(cleanup);
		const uplinkReader = request.body.getReader();
		const cancelUplinkReader = () => {
			try {
				uplinkReader.cancel(abortController.signal.reason).catch(() => {});
			} catch (e) {}
		};
		abortController.signal.addEventListener('abort', cancelUplinkReader, { once: true });
		try {
			try {
				while (true) {
					const { done, value } = await uplinkReader.read();
					if (done) break;
					if (value?.byteLength) await uplinkBundler.write(value);
				}
			} finally {
				abortController.signal.removeEventListener('abort', cancelUplinkReader);
				try {
					uplinkReader.releaseLock();
				} catch (e) {}
			}
		} finally {
			try {
				await uplinkBundler.end();
			} catch (e) {}
		}
		await pipePromise;
	})();

	const responseStream =
		typeof IdentityTransformStream !== 'undefined'
			? new IdentityTransformStream()
			: new TransformStream();
	const downlinkPromise = (async () => {
		const writer = responseStream.writable.getWriter();
		try {
			if (getValidDataLength(firstPacket.respHeader) > 0)
				await writer.write(firstPacket.respHeader);
		} catch (error) {
			try {
				await writer.abort(error);
			} catch (e) {}
			throw error;
		} finally {
			try {
				writer.releaseLock();
			} catch (e) {}
		}
		await socket.readable.pipeTo(responseStream.writable, { signal: abortController.signal });
	})();

	void uplinkPromise.catch(cleanup);
	void downlinkPromise.then(() => cleanup(), cleanup);
	void Promise.allSettled([uplinkPromise, downlinkPromise]);

	return new Response(responseStream.readable, { status: 200, headers: responseHeaders });
}

export function handleXHTTPUDPRequest(firstPacket, reader, request, proxyContext, responseHeaders) {
	const trojanUDPContext = {
		buffer: new Uint8Array(0),
		proxyAddress: proxyContext.trojanProxyAddress,
	};
	return new Response(
		new ReadableStream({
			async start(controller) {
				let isClosed = false;
				let udpRespHeader = firstPacket.respHeader;
				const httpBridge = {
					readyState: WebSocket.OPEN,
					send(data) {
						if (isClosed) return;
						try {
							const chunk =
								data instanceof Uint8Array
									? data
									: data instanceof ArrayBuffer
										? new Uint8Array(data)
										: ArrayBuffer.isView(data)
											? new Uint8Array(
													data.buffer,
													data.byteOffset,
													data.byteLength
												)
											: new Uint8Array(data);
							controller.enqueue(chunk);
						} catch (e) {
							isClosed = true;
							this.readyState = WebSocket.CLOSED;
						}
					},
					close() {
						if (isClosed) return;
						isClosed = true;
						this.readyState = WebSocket.CLOSED;
						try {
							controller.close();
						} catch (e) {}
					},
				};
				let forwardFailed = false;
				try {
					if (firstPacket.protocol === 'trojan') {
						trojanUDPContext.targetHost = firstPacket.hostname;
						trojanUDPContext.targetPort = firstPacket.port;
						if (trojanUDPContext.proxyAddress)
							await forwardTrojanUDPData(
								firstPacket.rawData,
								httpBridge,
								trojanUDPContext,
								request
							);
					}
					if (
						!(firstPacket.protocol === 'trojan' && trojanUDPContext.proxyAddress) &&
						firstPacket.rawData?.byteLength
					) {
						if (firstPacket.protocol === 'trojan')
							await forwardTrojanUDPData(
								firstPacket.rawData,
								httpBridge,
								trojanUDPContext,
								request
							);
						else
							await forwardUDP(
								firstPacket.rawData,
								httpBridge,
								udpRespHeader,
								request
							);
						udpRespHeader = null;
					}
					while (true) {
						const { done, value } = await reader.read();
						if (done) break;
						if (!value || value.byteLength === 0) continue;
						if (firstPacket.protocol === 'trojan')
							await forwardTrojanUDPData(
								value,
								httpBridge,
								trojanUDPContext,
								request
							);
						else await forwardUDP(value, httpBridge, udpRespHeader, request);
						udpRespHeader = null;
					}
				} catch (err) {
					forwardFailed = true;
					log(`[XHTTP-forward] processing failed: ${err?.message || err}`);
					closeSocketQuietly(httpBridge);
				} finally {
					const keepTrojanUDPProxyDown =
						!forwardFailed &&
						firstPacket.protocol === 'trojan' &&
						trojanUDPContext.proxyAddress &&
						trojanUDPContext.proxySocket;
					if (!keepTrojanUDPProxyDown) {
						try {
							trojanUDPContext.proxySocket?.close();
						} catch (e) {}
						closeSocketQuietly(httpBridge);
					}
					try {
						reader.releaseLock();
					} catch (e) {}
				}
			},
			cancel() {
				try {
					trojanUDPContext.proxySocket?.close();
				} catch (e) {}
				try {
					reader.releaseLock();
				} catch (e) {}
			},
		}),
		{ status: 200, headers: responseHeaders }
	);
}

export function getValidDataLength(data) {
	if (!data) return 0;
	if (typeof data.byteLength === 'number') return data.byteLength;
	if (typeof data.length === 'number') return data.length;
	return 0;
}

export function invalidateTCPConnectorGeneration(remoteConnWrapper) {
	if (!remoteConnWrapper) return;
	remoteConnWrapper.generation =
		(Number.isInteger(remoteConnWrapper.generation) ? remoteConnWrapper.generation : 0) + 1;
	const socket = remoteConnWrapper.socket;
	remoteConnWrapper.socket = null;
	remoteConnWrapper.downlinkController = null;
	remoteConnWrapper.downlinkDrain = Promise.resolve();
	try {
		socket?.close?.();
	} catch (e) {}
}

export function startTCPConnectorGeneration(remoteConnWrapper) {
	if (!Number.isInteger(remoteConnWrapper.generation)) remoteConnWrapper.generation = 0;
	const generation = ++remoteConnWrapper.generation;
	const previousSocket = remoteConnWrapper.socket;
	remoteConnWrapper.socket = null;
	const previousDownlink = remoteConnWrapper.downlinkController;
	remoteConnWrapper.downlinkController = null;
	const previousDrain = remoteConnWrapper.downlinkDrain || Promise.resolve();
	let currentDrain;
	try {
		currentDrain = previousDownlink?.stopAndFlush?.() || Promise.resolve();
	} catch (error) {
		currentDrain = Promise.reject(error);
	}
	const downlinkDrain = Promise.all([previousDrain, currentDrain]);
	// Installation awaits this promise; attach a handler immediately in case draining fails before dialing completes.
	downlinkDrain.catch(() => {});
	remoteConnWrapper.downlinkDrain = downlinkDrain;
	try {
		previousSocket?.close?.();
	} catch (e) {}
	return { generation, downlinkDrain };
}

export async function readXHTTPFirstPacket(reader, token) {
	const decoder = vlessTextDecoder;

	const tryParseVLESSFirstPacket = (data) => {
		const length = data.byteLength;
		if (length < 18) return { status: 'need_more' };
		if (!uuidBytesMatch(data, 1, token)) return { status: 'invalid' };

		const optLen = data[17];
		const cmdIndex = 18 + optLen;
		if (length < cmdIndex + 1) return { status: 'need_more' };

		const cmd = data[cmdIndex];
		if (cmd !== 1 && cmd !== 2) return { status: 'invalid' };

		const portIndex = cmdIndex + 1;
		if (length < portIndex + 3) return { status: 'need_more' };

		const port = (data[portIndex] << 8) | data[portIndex + 1];
		const addressType = data[portIndex + 2];
		const addressIndex = portIndex + 3;
		let headerLen = -1;
		let hostname = '';

		if (addressType === 1) {
			if (length < addressIndex + 4) return { status: 'need_more' };
			hostname = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
			headerLen = addressIndex + 4;
		} else if (addressType === 2) {
			if (length < addressIndex + 1) return { status: 'need_more' };
			const domainLen = data[addressIndex];
			if (length < addressIndex + 1 + domainLen) return { status: 'need_more' };
			hostname = decoder.decode(
				data.subarray(addressIndex + 1, addressIndex + 1 + domainLen)
			);
			headerLen = addressIndex + 1 + domainLen;
		} else if (addressType === 3) {
			if (length < addressIndex + 16) return { status: 'need_more' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = addressIndex + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			headerLen = addressIndex + 16;
		} else return { status: 'invalid' };

		if (!hostname) return { status: 'invalid' };

		return {
			status: 'ok',
			result: {
				protocol: 'vl' + 'ess',
				hostname,
				port,
				isUDP: cmd === 2,
				rawData: data.subarray(headerLen),
				respHeader: new Uint8Array([data[0], 0]),
				rawData: null,
			},
		};
	};

	const tryParseTrojanFirstPacket = (data) => {
		const passwordHash = sha224(token);
		const passwordHashbytes = new TextEncoder().encode(passwordHash);
		const length = data.byteLength;
		if (length < 58) return { status: 'need_more' };
		if (data[56] !== 0x0d || data[57] !== 0x0a) return { status: 'invalid' };
		for (let i = 0; i < 56; i++) {
			if (data[i] !== passwordHashBytes[i]) return { status: 'invalid' };
		}

		const socksStart = 58;
		if (length < socksStart + 2) return { status: 'need_more' };
		const cmd = data[socksStart];
		if (cmd !== 1 && cmd !== 3) return { status: 'invalid' };
		const isUDP = cmd === 3;

		const atype = data[socksStart + 1];
		let cursor = socksStart + 2;
		let hostname = '';

		if (atype === 1) {
			if (length < cursor + 4) return { status: 'need_more' };
			hostname = `${data[cursor]}.${data[cursor + 1]}.${data[cursor + 2]}.${data[cursor + 3]}`;
			cursor += 4;
		} else if (atype === 3) {
			if (length < cursor + 1) return { status: 'need_more' };
			const domainLen = data[cursor];
			if (length < cursor + 1 + domainLen) return { status: 'need_more' };
			hostname = decoder.decode(data.subarray(cursor + 1, cursor + 1 + domainLen));
			cursor += 1 + domainLen;
		} else if (atype === 4) {
			if (length < cursor + 16) return { status: 'need_more' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = cursor + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			cursor += 16;
		} else return { status: 'invalid' };

		if (!hostname) return { status: 'invalid' };
		if (length < cursor + 4) return { status: 'need_more' };

		const port = (data[cursor] << 8) | data[cursor + 1];
		if (data[cursor + 2] !== 0x0d || data[cursor + 3] !== 0x0a) return { status: 'invalid' };
		const dataOffset = cursor + 4;

		return {
			status: 'ok',
			result: {
				protocol: 'trojan',
				hostname,
				port,
				isUDP,
				rawData: data.subarray(dataOffset),
				rawData: data,
				respHeader: null,
			},
		};
	};

	let buffer = new Uint8Array(1024);
	let offset = 0;

	while (true) {
		const { value, done } = await reader.read();
		if (done) {
			if (offset === 0) return null;
			break;
		}

		const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
		if (offset + chunk.byteLength > buffer.byteLength) {
			const newBuffer = new Uint8Array(
				Math.max(buffer.byteLength * 2, offset + chunk.byteLength)
			);
			newBuffer.set(buffer.subarray(0, offset));
			buffer = newBuffer;
		}

		buffer.set(chunk, offset);
		offset += chunk.byteLength;

		const currentData = buffer.subarray(0, offset);
		const trojanResult = tryParseTrojanFirstPacket(currentData);
		if (trojanResult.status === 'ok') return { ...trojanResult.result, reader };

		const vlessResult = tryParseVLESSFirstPacket(currentData);
		if (vlessResult.status === 'ok') return { ...vlessResult.result, reader };

		if (trojanResult.status === 'invalid' && vlessResult.status === 'invalid') return null;
	}

	const finalData = buffer.subarray(0, offset);
	const finalTrojanResult = tryParseTrojanFirstPacket(finalData);
	if (finalTrojanResult.status === 'ok') return { ...finalTrojanResult.result, reader };
	const finalVlessResult = tryParseVLESSFirstPacket(finalData);
	if (finalVlessResult.status === 'ok') return { ...finalVlessResult.result, reader };
	return null;
}
///////////////////////////////////////////////////////////////////////gRPCtransport data///////////////////////////////////////////////
