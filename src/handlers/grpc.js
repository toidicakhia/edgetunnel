/**
 * src/handlers/grpc.js
 * Auto-generated from _worker.js refactor
 * Original: edgetunnel 2.1 (2026-08-11)
 */
import { downlinkGrainPacketBytes } from '../constants.js';
import { buildLocal204Response, createUplinkWriteQueue, isSpeedTestSite } from '../core/grain.js';
import { forwardTCP, forwardUDP, invalidateTCPConnectorGeneration } from '../core/tcp.js';
import { forwardTrojanUDPData, parseTrojanRequest, parseVLESSRequest } from '../core/protocol.js';
import { getValidDataLength, log, toUint8Array } from '../utils/helpers.js';
import { parseVMessRequest, vmessCreateResponseHeader } from '../core/vmess.js';

export async function handleGRPCRequest(request, yourUUID, proxyContext = {}) {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const remoteConnWrapper = {
		socket: null,
		connectingPromise: null,
		retryConnect: null,
		downlinkDrain: Promise.resolve(),
	};
	const invalidateRemote = () => invalidateTCPConnectorGeneration(remoteConnWrapper);
	let isDnsQuery = false;
	const trojanUDPContext = {
		buffer: new Uint8Array(0),
		proxyAddress: proxyContext.trojanProxyAddress,
	};
	let isTrojan = null;
	let currentWriteSocket = null;
	let remoteWriter = null;
	let grpcUplinkWriteQueue = null;

	//log('[gRPC] start processing bidirectional stream');
	const grpcHeaders = new Headers({
		'Content-Type': 'application/grpc',
		'grpc-status': '0',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store',
	});

	const downlinkBufferLimit = downlinkGrainPacketBytes;
	const downlinkFlushInterval = 1;

	return new Response(
		new ReadableStream({
			async start(controller) {
				let isClosed = false;
				let sendqueue = [];
				let queueByteCount = 0;
				let flushTimer = null;
				let flushMicrotaskisQueued = false;
				const grpcBridge = {
					readyState: WebSocket.OPEN,
					send(data) {
						if (isClosed) return;
						const chunk = data instanceof Uint8Array ? data : new Uint8Array(data);
						const lenBytesarray = [];
						let remaining = chunk.byteLength >>> 0;
						while (remaining > 127) {
							lenBytesarray.push((remaining & 0x7f) | 0x80);
							remaining >>>= 7;
						}
						lenBytesarray.push(remaining);
						const lenBytes = new Uint8Array(lenBytesarray);
						const protobufLen = 1 + lenBytes.length + chunk.byteLength;
						const frame = new Uint8Array(5 + protobufLen);
						frame[0] = 0;
						frame[1] = (protobufLen >>> 24) & 0xff;
						frame[2] = (protobufLen >>> 16) & 0xff;
						frame[3] = (protobufLen >>> 8) & 0xff;
						frame[4] = protobufLen & 0xff;
						frame[5] = 0x0a;
						frame.set(lenBytes, 6);
						frame.set(chunk, 6 + lenBytes.length);
						sendqueue.push(frame);
						queueByteCount += frame.byteLength;
						scheduleFlushSendQueue();
					},
					close() {
						if (this.readyState === WebSocket.CLOSED) return;
						flushSendQueue(true);
						isClosed = true;
						this.readyState = WebSocket.CLOSED;
						try {
							controller.close();
						} catch {}
					},
				};

				const flushSendQueue = (force = false) => {
					flushMicrotaskisQueued = false;
					if (flushTimer) {
						clearTimeout(flushTimer);
						flushTimer = null;
					}
					if ((!force && isClosed) || queueByteCount === 0) return;
					const out = new Uint8Array(queueByteCount);
					let offset = 0;
					for (const item of sendqueue) {
						out.set(item, offset);
						offset += item.byteLength;
					}
					sendqueue = [];
					queueByteCount = 0;
					try {
						controller.enqueue(out);
					} catch {
						isClosed = true;
						grpcBridge.readyState = WebSocket.CLOSED;
					}
				};

				const scheduleFlushSendQueue = () => {
					if (queueByteCount >= downlinkBufferLimit) {
						flushSendQueue();
						return;
					}
					if (flushMicrotaskisQueued || flushTimer) return;
					flushMicrotaskisQueued = true;
					queueMicrotask(() => {
						flushMicrotaskisQueued = false;
						if (isClosed || queueByteCount === 0 || flushTimer) return;
						flushTimer = setTimeout(flushSendQueue, downlinkFlushInterval);
					});
				};

				const closeConnection = () => {
					if (isClosed) return;
					grpcUplinkWriteQueue?.clear();
					invalidateRemote();
					flushSendQueue(true);
					isClosed = true;
					grpcBridge.readyState = WebSocket.CLOSED;
					if (flushTimer) clearTimeout(flushTimer);
					if (remoteWriter) {
						try {
							remoteWriter.releaseLock();
						} catch {}
						remoteWriter = null;
					}
					currentWriteSocket = null;
					try {
						reader.releaseLock();
					} catch {}
					try {
						trojanUDPContext.proxySocket?.close();
					} catch {}
					try {
						controller.close();
					} catch {}
				};

				const releaseRemoteWriter = () => {
					if (remoteWriter) {
						try {
							remoteWriter.releaseLock();
						} catch {}
						remoteWriter = null;
					}
					currentWriteSocket = null;
				};

				const uplinkWriteQueue = (grpcUplinkWriteQueue = createUplinkWriteQueue({
					getWriter: () => {
						const socket = remoteConnWrapper.socket;
						if (!socket) return null;
						if (socket !== currentWriteSocket) {
							releaseRemoteWriter();
							currentWriteSocket = socket;
							remoteWriter = socket.writable.getWriter();
						}
						return remoteWriter;
					},
					getConnectionTask: () => remoteConnWrapper.connectingPromise,
					releaseWriter: releaseRemoteWriter,
					retryConnection: async () => {
						if (typeof remoteConnWrapper.retryConnect !== 'function')
							throw new Error('retry unavailable');
						await remoteConnWrapper.retryConnect();
					},
					closeConnection,
					name: 'gRPCuplink',
				}));

				const writeToRemote = async (payload, allowRetry = true) => {
					return uplinkWriteQueue.writeAndAwait(payload, allowRetry);
				};

				let forwardFailed = false;
				try {
					let pending = new Uint8Array(0);
					while (true) {
						const { done, value } = await reader.read();
						if (done) break;
						if (!value || value.byteLength === 0) continue;
						const currentChunk =
							value instanceof Uint8Array ? value : new Uint8Array(value);
						const merged = new Uint8Array(pending.length + currentChunk.length);
						merged.set(pending, 0);
						merged.set(currentChunk, pending.length);
						pending = merged;
						while (pending.byteLength >= 5) {
							const grpcLen =
								((pending[1] << 24) >>> 0) |
								(pending[2] << 16) |
								(pending[3] << 8) |
								pending[4];
							const frameSize = 5 + grpcLen;
							if (pending.byteLength < frameSize) break;
							const grpcPayload = pending.subarray(5, frameSize);
							pending = pending.slice(frameSize);
							if (!grpcPayload.byteLength) continue;
							let payload = grpcPayload;
							if (payload.byteLength >= 2 && payload[0] === 0x0a) {
								let shift = 0;
								let offset = 1;
								let varintvalid = false;
								while (offset < payload.length) {
									const current = payload[offset++];
									if ((current & 0x80) === 0) {
										varintvalid = true;
										break;
									}
									shift += 7;
									if (shift > 35) break;
								}
								if (varintvalid) payload = payload.subarray(offset);
							}
							if (!payload.byteLength) continue;
							if (isDnsQuery) {
								if (isTrojan)
									await forwardTrojanUDPData(
										payload,
										grpcBridge,
										trojanUDPContext,
										request
									);
								else await forwardUDP(payload, grpcBridge, null, request);
								continue;
							}
							if (remoteConnWrapper.socket || remoteConnWrapper.connectingPromise) {
								if (!(await writeToRemote(payload)))
									throw new Error('Remote socket is not ready');
							} else {
								const firstPacketbytes = toUint8Array(payload);
								let isVMess = false;
								let vmessParsed = null;
								if (isTrojan === null) {
									// Try VMess first
									try {
										const vmessTry = await parseVMessRequest(
											firstPacketbytes,
											yourUUID
										);
										if (!vmessTry.hasError) {
											isVMess = true;
											vmessParsed = vmessTry;
											isTrojan = false;
										} else {
											isTrojan =
												firstPacketbytes.byteLength >= 58 &&
												firstPacketbytes[56] === 0x0d &&
												firstPacketbytes[57] === 0x0a;
										}
									} catch {
										isTrojan =
											firstPacketbytes.byteLength >= 58 &&
											firstPacketbytes[56] === 0x0d &&
											firstPacketbytes[57] === 0x0a;
									}
								}
								if (isVMess) {
									const {
										port,
										hostname,
										isUDP,
										rawClientData,
										security,
										responseHeader,
									} = vmessParsed;
									log(
										`[gRPC] VMess firstPacket: ${hostname}:${port} | UDP: ${isUDP ? 'yes' : 'no'} | sec: ${security}`
									);
									if (
										isSpeedTestSite(hostname) &&
										proxyContext.proxyType === null
									) {
										grpcBridge.send(
											buildLocal204Response(
												new Uint8Array([responseHeader || 0])
											)
										);
										return;
									}
									if (isUDP) {
										if (port !== 53)
											throw new Error('VMess UDP non-DNS not supported');
										isDnsQuery = true;
										trojanUDPContext.targetHost = hostname;
										trojanUDPContext.targetPort = port;
										// For VMess UDP, rawClientData is first DNS query (may be chunked)
										// Simplified: treat as raw
										if (rawClientData && rawClientData.byteLength)
											await forwardUDP(
												rawClientData,
												grpcBridge,
												null,
												request
											);
									} else {
										// For VMess TCP, need to handle body encryption
										// For now, handle first body as raw (for none) or try to decrypt
										const firstBody = rawClientData;
										// If security is not none, try to handle chunked body
										const respHeaderBytes = await vmessCreateResponseHeader(
											responseHeader || 0,
											vmessParsed.bodyKey,
											vmessParsed.bodyIV
										);
										grpcBridge.send(respHeaderBytes);
										await forwardTCP(
											hostname,
											port,
											firstBody,
											grpcBridge,
											null,
											remoteConnWrapper,
											yourUUID,
											request,
											proxyContext
										);
									}
								} else if (isTrojan) {
									const parseResult = parseTrojanRequest(
										firstPacketbytes,
										yourUUID
									);
									if (parseResult?.hasError)
										throw new Error(
											parseResult.message || 'Invalid trojan request'
										);
									const { port, hostname, rawClientData, isUDP } = parseResult;
									log(
										`[gRPC] trojanfirstPacket: ${hostname}:${port} | UDP: ${isUDP ? 'yes' : 'no'}`
									);
									if (
										isSpeedTestSite(hostname) &&
										proxyContext.proxyType === null
									) {
										grpcBridge.send(buildLocal204Response());
										return;
									}
									if (isUDP) {
										isDnsQuery = true;
										trojanUDPContext.targetHost = hostname;
										trojanUDPContext.targetPort = port;
										if (trojanUDPContext.proxyAddress)
											await forwardTrojanUDPData(
												firstPacketbytes,
												grpcBridge,
												trojanUDPContext,
												request
											);
										else if (getValidDataLength(rawClientData) > 0)
											await forwardTrojanUDPData(
												rawClientData,
												grpcBridge,
												trojanUDPContext,
												request
											);
									} else {
										await forwardTCP(
											hostname,
											port,
											rawClientData,
											grpcBridge,
											null,
											remoteConnWrapper,
											yourUUID,
											request,
											proxyContext,
											true,
											firstPacketbytes
										);
									}
								} else {
									isTrojan = false;
									const parseResult = parseVLESSRequest(
										firstPacketbytes,
										yourUUID
									);
									if (parseResult?.hasError)
										throw new Error(
											parseResult.message || 'Invalid VLESS request'
										);
									const { port, hostname, version, isUDP, rawClientData } =
										parseResult;
									log(
										`[gRPC] VLESSfirstPacket: ${hostname}:${port} | UDP: ${isUDP ? 'yes' : 'no'}`
									);
									const respHeader = new Uint8Array([version, 0]);
									if (
										isSpeedTestSite(hostname) &&
										proxyContext.proxyType === null
									) {
										grpcBridge.send(buildLocal204Response(respHeader));
										return;
									}
									if (isUDP) {
										if (port !== 53) throw new Error('UDP is not supported');
										isDnsQuery = true;
									}
									grpcBridge.send(respHeader);
									const rawData = rawClientData;
									if (isDnsQuery) {
										if (isTrojan)
											await forwardTrojanUDPData(
												rawData,
												grpcBridge,
												trojanUDPContext,
												request
											);
										else await forwardUDP(rawData, grpcBridge, null, request);
									} else
										await forwardTCP(
											hostname,
											port,
											rawData,
											grpcBridge,
											null,
											remoteConnWrapper,
											yourUUID,
											request,
											proxyContext
										);
								}
							}
						}
						flushSendQueue();
					}
					await uplinkWriteQueue.waitEmpty();
				} catch (err) {
					forwardFailed = true;
					log(`[gRPCforward] processing failed: ${err?.message || err}`);
				} finally {
					const keepTrojanUDPProxyDown =
						!forwardFailed &&
						isDnsQuery &&
						isTrojan &&
						trojanUDPContext.proxyAddress &&
						trojanUDPContext.proxySocket;
					if (keepTrojanUDPProxyDown) {
						uplinkWriteQueue.clear();
						invalidateRemote();
						releaseRemoteWriter();
						try {
							reader.releaseLock();
						} catch {}
					} else {
						closeConnection();
					}
				}
			},
			cancel() {
				grpcUplinkWriteQueue?.clear();
				invalidateRemote();
				try {
					trojanUDPContext.proxySocket?.close();
				} catch {}
				try {
					reader.releaseLock();
				} catch {}
			},
		}),
		{ status: 200, headers: grpcHeaders }
	);
}
