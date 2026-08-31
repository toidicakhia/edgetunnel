/**
 * src/handlers/ws.js
 * Auto-generated from _worker.js refactor
 * Original: edgetunnel 2.1 (2026-08-11)
 */
import {
	uplinkQueueMaxBytes,
	uplinkQueueMaxEntries,
	wsMaxEarlyDataBytes,
	wsMaxEarlyHeaderLength,
} from '../constants.js';
import {
	SSAEADDecrypt,
	SSAEADEncrypt,
	SSDeriveMasterKey,
	SSDeriveSessionKey,
	SS_AEAD_TAG_LENGTH,
	SS_NONCE_LENGTH,
	SS_SUPPORTED_CIPHERS,
	forwardTrojanUDPData,
	getTrojanPasswordHashes,
	matchTrojanPassword,
	parseTrojanRequest,
	parseVLESSRequest,
	ssTextDecoder,
	uuidBytesMatch,
	vlessTextDecoder,
} from '../core/protocol.js';
import { buildWSLocal204Response, createUplinkWriteQueue, isSpeedTestSite } from '../core/grain.js';
import { closeSocketQuietly, forwardTCP, forwardUDP, invalidateTCPConnectorGeneration, webSocketSendAndAwait } from '../core/tcp.js';
import { concatByteData, getValidDataLength, log, toUint8Array } from '../utils/helpers.js';
import {
	parseVMessRequest,
	vmessCreateResponseHeader,
	vmessEncryptChunk,
	vmessDecryptChunk,
	PureSha256,
	ShakeSizeParser,
	getCmdKey,
	decodeAuthID,
} from '../core/vmess.js';


export function isValidWSEarlyData(bytes, token) {
	if (!bytes?.byteLength) return false;
	if (bytes.byteLength >= 18 && bytes[0] === 0 && uuidBytesMatch(bytes, 1, token)) return true;
	if (bytes.byteLength >= 16) {
		try {
			const cmdKey = getCmdKey(token);
			if (decodeAuthID(bytes.subarray(0, 16), cmdKey)) return true;
		} catch {}
	}
	if (bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a) {
		const expectedHashes = getTrojanPasswordHashes(token);
		return matchTrojanPassword(bytes, expectedHashes);
	}
	if (bytes.byteLength >= 50) return true;
	return false;
}

export function decodeWSEarlyData(header, token) {
	if (!header) return null;
	if (header.length > wsMaxEarlyHeaderLength) throw new Error('early data is too large');

	let bytes;
	const Uint8ArrayBase64 = /** @type {any} */ (Uint8Array);
	if (typeof Uint8ArrayBase64.fromBase64 === 'function') {
		try {
			bytes = Uint8ArrayBase64.fromBase64(header, { alphabet: 'base64url' });
		} catch {}
	}
	if (!bytes) {
		let normalized = header.replace(/-/g, '+').replace(/_/g, '/');
		const padding = normalized.length % 4;
		if (padding) normalized += '='.repeat(4 - padding);
		let binaryString;
		try {
			binaryString = atob(normalized);
		} catch {}
		if (!binaryString) return null;
		bytes = new Uint8Array(binaryString.length);
		for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
	}

	if (bytes.byteLength > wsMaxEarlyDataBytes) throw new Error('early data is too large');
	return isValidWSEarlyData(bytes, token) ? bytes : null;
}

///////////////////////////////////////////////////////////////////////WStransport data///////////////////////////////////////////////

export async function handleWSRequest(request, yourUUID, url, proxyContext = {}) {
	const wsSocketPair = new WebSocketPair();
	const [clientSock, serverSock] = Object.values(wsSocketPair);
	try {
		/** @type {any} */ (serverSock).accept({ allowHalfOpen: true });
	} catch {}
	serverSock.binaryType = 'arraybuffer';
	const remoteConnWrapper = {
		socket: null,
		connectingPromise: null,
		retryConnect: null,
		downlinkDrain: Promise.resolve(),
	};
	const invalidateRemote = () => invalidateTCPConnectorGeneration(remoteConnWrapper);
	let isDnsQuery = false;
	let isTrojan = null;
	const trojanUDPContext = {
		buffer: new Uint8Array(0),
		proxyAddress: proxyContext.trojanProxyAddress,
	};
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
	const ssModeDisableEarlyData = !!url.searchParams.get('enc');
	let wsExplicitTransferChain = Promise.resolve();
	let wsExplicitTransferStopReceiving = false,
		wsExplicitTransferFailed = false,
		wsExplicitTransferFinishingEnqueued = false;
	let wsExplicitQueueBytes = 0,
		wsExplicitQueueEntries = 0;
	let determineProtocolType = null,
		currentWriteSocket = null,
		remoteWriter = null;
	let vmessContext = null,
		vmessInitTask = null,
		ssContext = null,
		ssInitTask = null;
	let wsLocalSpeedTestMode = false,
		wsLocalSpeedTestResponseSocket = null;
	let wsLocalSpeedTestRequestCache = new Uint8Array(0);
	let wsLocalSpeedTestFirstPacketResponseHeader = null;
	const wsLocalSpeedTestRequestLimit = 64 * 1024;


	const sendWSLocalSpeedTestResponse = async () => {
		if (!wsLocalSpeedTestResponseSocket) return;
		const respHeader = wsLocalSpeedTestFirstPacketResponseHeader;
		wsLocalSpeedTestFirstPacketResponseHeader = null;
		await webSocketSendAndAwait(
			wsLocalSpeedTestResponseSocket,
			buildWSLocal204Response(respHeader)
		);
	};

	const findHTTPRequestHeaderEnd = (data) => {
		for (let i = 0; i <= data.byteLength - 4; i++) {
			if (
				data[i] === 0x0d &&
				data[i + 1] === 0x0a &&
				data[i + 2] === 0x0d &&
				data[i + 3] === 0x0a
			)
				return i + 4;
		}
		return -1;
	};

	const handleWSLocalSpeedTestData = async (data) => {
		const chunk = toUint8Array(data);
		if (!chunk.byteLength) return;
		if (
			wsLocalSpeedTestRequestCache.byteLength + chunk.byteLength >
			wsLocalSpeedTestRequestLimit
		)
			throw new Error('WS local speed-test request is too large');
		wsLocalSpeedTestRequestCache = concatByteData(wsLocalSpeedTestRequestCache, chunk);

		while (wsLocalSpeedTestRequestCache.byteLength) {
			const headerEnd = findHTTPRequestHeaderEnd(wsLocalSpeedTestRequestCache);
			if (headerEnd === -1) return;
			const headerText = vlessTextDecoder.decode(
				wsLocalSpeedTestRequestCache.subarray(0, headerEnd)
			);
			const contentLengthMatch = headerText.match(/(?:^|\r\n)content-length\s*:\s*(\d+)/i);
			const contentLength = contentLengthMatch ? Number(contentLengthMatch[1]) : 0;
			const requestLength = headerEnd + contentLength;
			if (
				!Number.isSafeInteger(contentLength) ||
				requestLength > wsLocalSpeedTestRequestLimit
			)
				throw new Error('WS local speed-test request body is too large');
			if (wsLocalSpeedTestRequestCache.byteLength < requestLength) return;
			wsLocalSpeedTestRequestCache = wsLocalSpeedTestRequestCache.slice(requestLength);
			await sendWSLocalSpeedTestResponse();
		}
	};

	const enableWSLocalSpeedTestMode = async (
		responseSocket,
		respHeader = null,
		firstRequestData = null
	) => {
		wsLocalSpeedTestMode = true;
		wsLocalSpeedTestResponseSocket = responseSocket;
		wsLocalSpeedTestRequestCache = new Uint8Array(0);
		wsLocalSpeedTestFirstPacketResponseHeader = respHeader;
		if (getValidDataLength(firstRequestData) > 0)
			await handleWSLocalSpeedTestData(firstRequestData);
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

	const uplinkWriteQueue = createUplinkWriteQueue({
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
		closeConnection: (err) => handleWSExplicitTransferError(err),
		name: 'WSuplink',
	});

	const writeToRemote = async (chunk, allowRetry = true) => {
		return uplinkWriteQueue.write(chunk, allowRetry);
	};

	const getSSContext = async () => {
		if (ssContext) return ssContext;
		if (!ssInitTask) {
			ssInitTask = (async () => {
				const requestCipherMethod = (url.searchParams.get('enc') || '').toLowerCase();
				const preferredCipherConfig =
					SS_SUPPORTED_CIPHERS[requestCipherMethod] ||
					SS_SUPPORTED_CIPHERS['aes-128-gcm'];
				const inboundCandidateCipherConfigs = [
					preferredCipherConfig,
					...Object.values(SS_SUPPORTED_CIPHERS).filter(
						(c) => c.method !== preferredCipherConfig.method
					),
				];
				const inboundMasterKeyTaskBuffer = new Map();
				const getInboundMasterKeyTask = (config) => {
					if (!inboundMasterKeyTaskBuffer.has(config.method))
						inboundMasterKeyTaskBuffer.set(
							config.method,
							SSDeriveMasterKey(yourUUID, config.keyLen)
						);
					return inboundMasterKeyTaskBuffer.get(config.method);
				};
				const inboundState = {
					buffer: new Uint8Array(0),
					hasSalt: false,
					waitPayloadLength: null,
					decryptKey: null,
					nonceCounter: new Uint8Array(SS_NONCE_LENGTH),
					cipherConfig: null,
				};
				const initInboundDecryptState = async () => {
					const lengthCipherTotalLength = 2 + SS_AEAD_TAG_LENGTH;
					const maxSaltLen = Math.max(
						...inboundCandidateCipherConfigs.map((c) => c.saltLen)
					);
					const maxAlignScanBytes = 16;
					const maxScannableOffset = Math.min(
						maxAlignScanBytes,
						Math.max(
							0,
							inboundState.buffer.byteLength -
								(lengthCipherTotalLength +
									Math.min(
										...inboundCandidateCipherConfigs.map((c) => c.saltLen)
									))
						)
					);
					for (let offset = 0; offset <= maxScannableOffset; offset++) {
						for (const cipherConfig of inboundCandidateCipherConfigs) {
							const initMinLength =
								offset + cipherConfig.saltLen + lengthCipherTotalLength;
							if (inboundState.buffer.byteLength < initMinLength) continue;
							const salt = inboundState.buffer.subarray(
								offset,
								offset + cipherConfig.saltLen
							);
							const lengthCipher = inboundState.buffer.subarray(
								offset + cipherConfig.saltLen,
								initMinLength
							);
							const masterKey = await getInboundMasterKeyTask(cipherConfig);
							const decryptKey = await SSDeriveSessionKey(
								cipherConfig,
								masterKey,
								salt,
								['decrypt']
							);
							const nonceCounter = new Uint8Array(SS_NONCE_LENGTH);
							try {
								const lengthPlain = await SSAEADDecrypt(
									decryptKey,
									nonceCounter,
									lengthCipher
								);
								if (lengthPlain.byteLength !== 2) continue;
								const payloadLength = (lengthPlain[0] << 8) | lengthPlain[1];
								if (payloadLength < 0 || payloadLength > cipherConfig.maxChunk)
									continue;
								if (offset > 0)
									log(
										`[SS Inbound] leading noise detected ${offset}B，autoAligned`
									);
								if (cipherConfig.method !== preferredCipherConfig.method)
									log(
										`[SS Inbound] URL enc=${requestCipherMethod || preferredCipherConfig.method} actual ${cipherConfig.method} inconsistent，autoSwitched`
									);
								inboundState.buffer = inboundState.buffer.subarray(initMinLength);
								inboundState.decryptKey = decryptKey;
								inboundState.nonceCounter = nonceCounter;
								inboundState.waitPayloadLength = payloadLength;
								inboundState.cipherConfig = cipherConfig;
								inboundState.hasSalt = true;
								return true;
							} catch {}
						}
					}
					const initFailureThresholdLength =
						maxSaltLen + lengthCipherTotalLength + maxAlignScanBytes;
					if (inboundState.buffer.byteLength >= initFailureThresholdLength) {
						throw new Error(
							`SS handshake decrypt failed (enc=${requestCipherMethod || 'auto'}, candidates=${inboundCandidateCipherConfigs.map((c) => c.method).join('/')})`
						);
					}
					return false;
				};
				const inboundDecryptor = {
					async input(dataChunk) {
						const chunk = toUint8Array(dataChunk);
						if (chunk.byteLength > 0)
							inboundState.buffer = concatByteData(inboundState.buffer, chunk);
						if (!inboundState.hasSalt) {
							const initSucceeded = await initInboundDecryptState();
							if (!initSucceeded) return [];
						}
						const plaintextChunks = [];
						let rekeyAttempted = false;
						let lastConsumedLengthCipher = null;
						while (true) {
							if (inboundState.waitPayloadLength === null) {
								const lengthCipherTotalLength = 2 + SS_AEAD_TAG_LENGTH;
								if (inboundState.buffer.byteLength < lengthCipherTotalLength) break;
								const lengthCipher = inboundState.buffer.subarray(
									0,
									lengthCipherTotalLength
								);
								inboundState.buffer =
									inboundState.buffer.subarray(lengthCipherTotalLength);
								lastConsumedLengthCipher = lengthCipher;
								let lengthPlain = null;
								try {
									lengthPlain = await SSAEADDecrypt(
										inboundState.decryptKey,
										inboundState.nonceCounter,
										lengthCipher
									);
								} catch {}
								let lengthDecryptFailed = false;
								if (lengthPlain === null || lengthPlain.byteLength !== 2) {
									lengthDecryptFailed = true;
								} else {
									const payloadLength = (lengthPlain[0] << 8) | lengthPlain[1];
									if (
										payloadLength < 0 ||
										payloadLength > inboundState.cipherConfig.maxChunk
									) {
										lengthDecryptFailed = true;
									} else {
										inboundState.waitPayloadLength = payloadLength;
									}
								}
								if (lengthDecryptFailed) {
									if (rekeyAttempted) {
										throw new Error('SS length decrypt failed');
									}
									rekeyAttempted = true;
									inboundState.buffer = concatByteData(
										lengthCipher,
										inboundState.buffer
									);
									// A new SS AEAD stream (a fresh proxied TCP connection) starts
									// with a new salt on this long-lived WebSocket. Reset all
									// per-connection state so the new stream re-keys and forwards
									// to a fresh remote target instead of reusing connection 1's.
									await SSsendqueue;
									outboundEncryptor = null;
									if (ssContext) {
										ssContext.firstPacketEstablished = false;
										ssContext.targetHost = '';
										ssContext.targetPort = 0;
									}
									inboundState.hasSalt = false;
									inboundState.waitPayloadLength = null;
									inboundState.decryptKey = null;
									inboundState.nonceCounter = new Uint8Array(SS_NONCE_LENGTH);
									inboundState.cipherConfig = null;
									const initSucceeded = await initInboundDecryptState();
									if (!initSucceeded) return plaintextChunks;
									continue;
								}
							}
							const payloadCipherTotalLength =
								inboundState.waitPayloadLength + SS_AEAD_TAG_LENGTH;
							if (inboundState.buffer.byteLength < payloadCipherTotalLength) break;
							const payloadCipher = inboundState.buffer.subarray(
								0,
								payloadCipherTotalLength
							);
							inboundState.buffer =
								inboundState.buffer.subarray(payloadCipherTotalLength);
							let payloadPlain = null;
							try {
								payloadPlain = await SSAEADDecrypt(
									inboundState.decryptKey,
									inboundState.nonceCounter,
									payloadCipher
								);
							} catch {
								if (rekeyAttempted) {
									throw new Error('SS payload decrypt failed');
								}
								rekeyAttempted = true;
								inboundState.buffer = concatByteData(
									payloadCipher,
									concatByteData(lastConsumedLengthCipher, inboundState.buffer)
								);
								// A torn/corrupted payload AEAD frame: the AEAD stream is
								// unrecoverable in place. Treat it like a fresh SS AEAD stream
								// on this long-lived WebSocket: reset per-connection state so the
								// next salt re-keys and forwards to a fresh remote target.
								await SSsendqueue;
								outboundEncryptor = null;
								if (ssContext) {
									ssContext.firstPacketEstablished = false;
									ssContext.targetHost = '';
									ssContext.targetPort = 0;
								}
								inboundState.hasSalt = false;
								inboundState.waitPayloadLength = null;
								inboundState.decryptKey = null;
								inboundState.nonceCounter = new Uint8Array(SS_NONCE_LENGTH);
								inboundState.cipherConfig = null;
								const initSucceeded = await initInboundDecryptState();
								if (!initSucceeded) return plaintextChunks;
								continue;
							}
							plaintextChunks.push(payloadPlain);
							inboundState.waitPayloadLength = null;
						}
						return plaintextChunks;
					},
				};
				let outboundEncryptor = null;
				const SSsingleBatchMaxbytes = 32 * 1024;
				const getOutboundEncryptor = async () => {
					if (outboundEncryptor) return outboundEncryptor;
					if (!inboundState.cipherConfig) throw new Error('SS cipher is not negotiated');
					const outboundCipherConfig = inboundState.cipherConfig;
					const outboundMasterKey = await SSDeriveMasterKey(
						yourUUID,
						outboundCipherConfig.keyLen
					);
					const outboundRandomBytes = crypto.getRandomValues(
						new Uint8Array(outboundCipherConfig.saltLen)
					);
					const outboundCipherKey = await SSDeriveSessionKey(
						outboundCipherConfig,
						outboundMasterKey,
						outboundRandomBytes,
						['encrypt']
					);
					const outboundNonceCounter = new Uint8Array(SS_NONCE_LENGTH);
					let randomBytesSent = false;
					outboundEncryptor = {
						async encryptAndsend(dataChunk, sendChunk) {
							const plaintextData = toUint8Array(dataChunk);
							if (!randomBytesSent) {
								await sendChunk(outboundRandomBytes);
								randomBytesSent = true;
							}
							if (plaintextData.byteLength === 0) return;
							let offset = 0;
							while (offset < plaintextData.byteLength) {
								const end = Math.min(
									offset + outboundCipherConfig.maxChunk,
									plaintextData.byteLength
								);
								const payloadPlain = plaintextData.subarray(offset, end);
								const lengthPlain = new Uint8Array(2);
								lengthPlain[0] = (payloadPlain.byteLength >>> 8) & 0xff;
								lengthPlain[1] = payloadPlain.byteLength & 0xff;
								const lengthCipher = await SSAEADEncrypt(
									outboundCipherKey,
									outboundNonceCounter,
									lengthPlain
								);
								const payloadCipher = await SSAEADEncrypt(
									outboundCipherKey,
									outboundNonceCounter,
									payloadPlain
								);
								const frame = new Uint8Array(
									lengthCipher.byteLength + payloadCipher.byteLength
								);
								frame.set(lengthCipher, 0);
								frame.set(payloadCipher, lengthCipher.byteLength);
								await sendChunk(frame);
								offset = end;
							}
						},
					};
					return outboundEncryptor;
				};
				let SSsendqueue = Promise.resolve();
				const SSenqueuesend = (chunk) => {
					SSsendqueue = SSsendqueue.then(async () => {
						if (serverSock.readyState !== WebSocket.OPEN) return;
						const initializedOutboundEncryptor = await getOutboundEncryptor();
						await initializedOutboundEncryptor.encryptAndsend(
							chunk,
							async (encryptedChunk) => {
								if (
									encryptedChunk.byteLength > 0 &&
									serverSock.readyState === WebSocket.OPEN
								) {
									await webSocketSendAndAwait(serverSock, encryptedChunk.buffer);
								}
							}
						);
					}).catch((error) => {

						log(`[SSsend] encryption failed: ${error?.message || error}`);
						closeSocketQuietly(serverSock);
					});
					return SSsendqueue;
				};
				const responseSocket = {
					get readyState() {
						return serverSock.readyState;
					},
					send(data) {
						const chunk = toUint8Array(data);
						if (chunk.byteLength <= SSsingleBatchMaxbytes) {
							return SSenqueuesend(chunk);
						}
						for (let i = 0; i < chunk.byteLength; i += SSsingleBatchMaxbytes) {
							SSenqueuesend(
								chunk.subarray(
									i,
									Math.min(i + SSsingleBatchMaxbytes, chunk.byteLength)
								)
							);
						}
						return SSsendqueue;
					},
					close() {
						// SS keeps one long-lived WebSocket across multiple proxied TCP
						// connections. The WS lifecycle is owned by the client: it is torn
						// down only when the client closes it (serverSock 'close' event in
						// handleWSRequest) or on a hard error. Closing here would kill the
						// connection mid-stream when the remote TCP peer ends (connectStreams
						// finally calls closeSocketQuietly on this wrapper), surfacing
						// 'io: read/write on closed pipe' to the SS client. No-op on purpose.
					},
				};
				ssContext = {
					inboundDecryptor,
					responseSocket,
					firstPacketestablished: false,
					targetHost: '',
					targetPort: 0,
				};
				return ssContext;
			})().finally(() => {
				ssInitTask = null;
			});
		}
		return ssInitTask;
	};

	const handleSSData = async (chunk) => {

		const context = await getSSContext();
		let plaintextChunks = null;
		try {
			plaintextChunks = await context.inboundDecryptor.input(chunk);
		} catch (err) {
			const msg = err?.message || `${err}`;
			if (
				msg.includes('Decryption failed') ||
				msg.includes('SS handshake decrypt failed') ||
				msg.includes('SS length decrypt failed') ||
				msg.includes('SS payload decrypt failed')
			) {

				log(`[SS Inbound] decryption failed，connection closed: ${msg}`);
				closeSocketQuietly(serverSock);
				return;
			}
			throw err;
		}
		for (const plaintextChunk of plaintextChunks) {
			if (wsLocalSpeedTestMode) {
				await handleWSLocalSpeedTestData(plaintextChunk);
				continue;
			}
			let wasWritten = false;
			try {
				wasWritten = await writeToRemote(plaintextChunk, false);
			} catch (err) {
				if (/** @type {any} */ (err)?.isQueueOverflow) throw err;
				wasWritten = false;
			}
			if (wasWritten) continue;
			if (context.firstPacketEstablished && context.targetHost && context.targetPort > 0) {

				await forwardTCP(
					context.targetHost,
					context.targetPort,
					plaintextChunk,
					context.responseSocket,
					null,
					remoteConnWrapper,
					yourUUID,
					request,
					proxyContext
				);
				continue;
			}
			const plaintextData = toUint8Array(plaintextChunk);
			if (plaintextData.byteLength < 3) throw new Error('invalid ss data');
			const addressType = plaintextData[0];
			let cursor = 1;
			let hostname = '';
			if (addressType === 1) {
				if (plaintextData.byteLength < cursor + 4 + 2)
					throw new Error('invalid ss ipv4 length');
				hostname = `${plaintextData[cursor]}.${plaintextData[cursor + 1]}.${plaintextData[cursor + 2]}.${plaintextData[cursor + 3]}`;
				cursor += 4;
			} else if (addressType === 3) {
				if (plaintextData.byteLength < cursor + 1)
					throw new Error('invalid ss domain length');
				const domainLength = plaintextData[cursor];
				cursor += 1;
				if (plaintextData.byteLength < cursor + domainLength + 2)
					throw new Error('invalid ss domain data');
				hostname = ssTextDecoder.decode(
					plaintextData.subarray(cursor, cursor + domainLength)
				);
				cursor += domainLength;
			} else if (addressType === 4) {
				if (plaintextData.byteLength < cursor + 16 + 2)
					throw new Error('invalid ss ipv6 length');
				const ipv6 = [];
				const ipv6View = new DataView(
					plaintextData.buffer,
					plaintextData.byteOffset + cursor,
					16
				);
				for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16));
				hostname = ipv6.join(':');
				cursor += 16;
			} else {
				throw new Error(`invalid ss addressType: ${addressType}`);
			}
			if (!hostname) throw new Error(`invalid ss address: ${addressType}`);
			const port = (plaintextData[cursor] << 8) | plaintextData[cursor + 1];
			cursor += 2;
			const rawClientData = plaintextData.subarray(cursor);
			if (isSpeedTestSite(hostname) && proxyContext.proxyType === null) {
				await enableWSLocalSpeedTestMode(context.responseSocket, null, rawClientData);
				return;
			}
			context.firstPacketEstablished = true;
			context.targetHost = hostname;
			context.targetPort = port;

			await forwardTCP(
				hostname,
				port,
				rawClientData,
				context.responseSocket,
				null,
				remoteConnWrapper,
				yourUUID,
				request,
				proxyContext
			);
		}
	};

	const getVMessContext = async () => {
		if (vmessContext) return vmessContext;
		if (!vmessInitTask) {
			vmessInitTask = (async () => {
				vmessContext = {
					bodyKey: null,
					bodyIV: null,
					security: 'auto',
					option: 0,
					responseHeader: 0,
					firstPacketEstablished: false,
					targetHost: '',
					targetPort: 0,
					buffer: new Uint8Array(0),
					count: 0,
					respHeaderSent: false,
					respCount: 0,
					responseSocket: null,
				};
				return vmessContext;
			})();
		}
		return vmessInitTask;
	};

	const handleVMessData = async (chunk) => {
		const ctx = await getVMessContext();
		const data = toUint8Array(chunk);
		// Nếu first packet chưa được xử lý
		if (!ctx.firstPacketEstablished) {
			ctx.buffer = concatByteData(ctx.buffer, data);
			if (ctx.buffer.byteLength < 58) return;

			const parsed = await parseVMessRequest(ctx.buffer, yourUUID);
			if (parsed.hasError) {
				if (
					(parsed.message?.includes('too short') || parsed.message?.includes('AEAD open failed')) &&
					ctx.buffer.byteLength < 2048
				) {
					return; // Wait for more data
				}
				throw new Error(parsed.message || 'Invalid VMess request');
			}
			ctx.buffer = new Uint8Array(0);
			ctx.targetHost = parsed.hostname;
			ctx.targetPort = parsed.port;
			ctx.bodyKey = parsed.bodyKey;
			ctx.bodyIV = parsed.bodyIV;
			ctx.security = parsed.security;
			ctx.option = parsed.option;
			ctx.responseHeader = parsed.responseHeader;
			ctx.firstPacketEstablished = true;
			log(`[VMess] parsed: host=${ctx.targetHost}:${ctx.targetPort} sec=${ctx.security} rawLen=${parsed.rawClientData?.byteLength ?? 0}`);

			// Handle speed test
			if (isSpeedTestSite(ctx.targetHost) && proxyContext.proxyType === null) {
				await enableWSLocalSpeedTestMode(serverSock, null, parsed.rawClientData);
				return;
			}
			if (parsed.isUDP) {
				if (parsed.port === 53) {
					isDnsQuery = true;
					trojanUDPContext.targetHost = ctx.targetHost;
					trojanUDPContext.targetPort = ctx.targetPort;
					if (parsed.rawClientData && parsed.rawClientData.byteLength) {
						// VMess UDP body needs to be decrypted first
						// For now, treat as raw and forward via UDP
						await forwardUDP(parsed.rawClientData, serverSock, null, request);
					}
					return;
				} else {
					throw new Error('VMess UDP non-DNS not supported');
				}
			}
			// Derive response keys for AEAD
			const bodyKeyHash = new PureSha256().update(ctx.bodyKey).digest();
			const bodyIVHash = new PureSha256().update(ctx.bodyIV).digest();
			ctx.respBodyKey = bodyKeyHash.slice(0, 16);
			ctx.respBodyIV = bodyIVHash.slice(0, 16);
			ctx.respCount = 0;
			ctx.respHeaderSent = false;
			ctx.respShakeParser = (ctx.option & 0x04) ? new ShakeSizeParser(ctx.respBodyIV) : null;
			ctx.reqShakeParser = ((ctx.option & 0x04) || (ctx.option & 0x08)) ? new ShakeSizeParser(ctx.bodyIV) : null;

			// Create VMess response socket that encrypts response with sequential queue
			let sendQueue = Promise.resolve();
			const vmessResponseSocket = {
				get readyState() {
					return serverSock.readyState;
				},
				send(dataChunk) {
					sendQueue = sendQueue
						.then(async () => {
							if (serverSock.readyState !== WebSocket.OPEN) return;
							const chunkBytes = toUint8Array(dataChunk);
							if (!chunkBytes.byteLength) return;
							let headerBytes = new Uint8Array(0);
							if (!ctx.respHeaderSent) {
								ctx.respHeaderSent = true;
								headerBytes = await vmessCreateResponseHeader(
									ctx.responseHeader,
									ctx.bodyKey,
									ctx.bodyIV
								);
							}
							// VMess protocol max chunk plaintext size is 16384 - 16 = 16368 bytes (2^14 limit)
							const maxChunkPlain = 16384 - 16;
							let offset = 0;
							let isFirstInSend = true;
							while (offset < chunkBytes.byteLength) {
								const end = Math.min(offset + maxChunkPlain, chunkBytes.byteLength);
								const slice = chunkBytes.subarray(offset, end);
								offset = end;
								if (ctx.security === 'none') {
									const lenBuf = new Uint8Array([
										(slice.length >>> 8) & 0xff,
										slice.length & 0xff,
									]);
									const slicePacket = concatByteData(lenBuf, slice);
									const packet =
										isFirstInSend && headerBytes.length
											? concatByteData(headerBytes, slicePacket)
											: slicePacket;
									await webSocketSendAndAwait(serverSock, packet);
								} else {
									// Xray server: NextPaddingLen() BEFORE Encode() — both consume SHAKE128;
									// padding bytes are sent clear AFTER the ciphertext and included in the size
									let padLen = 0;
									if (ctx.respShakeParser) {
										padLen = ctx.respShakeParser.nextPaddingLen();
									}
									const encChunk = await vmessEncryptChunk(
										slice,
										ctx.respBodyKey,
										ctx.respBodyIV,
										ctx.respCount++,
										ctx.security === 'auto' ? 'aes-128-gcm' : ctx.security
									);
									let lenToEncode = encChunk.length + padLen;
									let lenBuf;
									if (ctx.respShakeParser) {
										lenBuf = ctx.respShakeParser.encode(lenToEncode);
									} else {
										lenBuf = new Uint8Array([
											(lenToEncode >>> 8) & 0xff,
											lenToEncode & 0xff,
										]);
									}
									let bodyPacket = concatByteData(lenBuf, encChunk);
									if (padLen > 0) {
										bodyPacket = concatByteData(
											bodyPacket,
											crypto.getRandomValues(new Uint8Array(padLen))
										);
									}
									const packet =
										isFirstInSend && headerBytes.length
											? concatByteData(headerBytes, bodyPacket)
											: bodyPacket;
									await webSocketSendAndAwait(serverSock, packet);
								}
								isFirstInSend = false;
							}
						})
						.catch((error) => {
							log(`[VMess-send] encryption failed: ${error?.message || error}`);
							closeSocketQuietly(serverSock);
						});
					return sendQueue;
				},
				close() {
					closeSocketQuietly(serverSock);
				},
			};
			ctx.responseSocket = vmessResponseSocket;

			// Decrypt all full chunks available in rawClientData
			let firstPlaintext = new Uint8Array(0);
			const hasPadding = (ctx.option & 0x08) !== 0;
			if (parsed.rawClientData && parsed.rawClientData.byteLength) {
				ctx.buffer = concatByteData(ctx.buffer, parsed.rawClientData);
				if (ctx.security === 'none') {
					firstPlaintext = ctx.buffer;
					ctx.buffer = new Uint8Array(0);
				} else {
					while (ctx.buffer.length >= 2) {
						// Xray calls NextPaddingLen() BEFORE Decode() — both consume SHAKE128
						let padLen = 0;
						if (hasPadding && ctx.reqShakeParser) {
							padLen = ctx.reqShakeParser.nextPaddingLen();
						}
						let len;
						if (ctx.reqShakeParser) {
							len = ctx.reqShakeParser.decode(ctx.buffer.subarray(0, 2));
						} else {
							len = (ctx.buffer[0] << 8) | ctx.buffer[1];
						}
						if (len === 0) {
							ctx.buffer = new Uint8Array(0);
							break;
						}
						if (ctx.buffer.length < 2 + len) break;
						// Xray includes padding in the wire size but strips it BEFORE decrypt
						const actualLen = len - padLen;
						if (actualLen <= 0) {
							ctx.buffer = ctx.buffer.slice(2 + len);
							continue;
						}
						const chunkData = ctx.buffer.slice(2, 2 + actualLen);
						ctx.buffer = ctx.buffer.slice(2 + len);
						let decrypted;
						try {
							decrypted = await vmessDecryptChunk(
								chunkData,
								ctx.bodyKey,
								ctx.bodyIV,
								ctx.count++,
								ctx.security === 'auto' ? 'aes-128-gcm' : ctx.security
							);
						} catch (e) {
							throw new Error('VMess chunk decrypt failed: ' + e.message);
						}
						if (decrypted && decrypted.byteLength) {
							firstPlaintext = concatByteData(firstPlaintext, decrypted);
						}
					}
				}
			}

			// Establish TCP connection ONCE with all decrypted initial plaintext
			log(`[VMess] forwardTCP: ${ctx.targetHost}:${ctx.targetPort} plainLen=${firstPlaintext.byteLength} sec=${ctx.security}`);
			await forwardTCP(
				ctx.targetHost,
				ctx.targetPort,
				firstPlaintext,
				vmessResponseSocket,
				null,
				remoteConnWrapper,
				yourUUID,
				request,
				proxyContext
			);
			return;
		}

		// Subsequent packets: handle VMess body chunks
		if (ctx.security === 'none') {
			await writeToRemote(data);
			return;
		}
		const hasPadding = (ctx.option & 0x08) !== 0;
		ctx.buffer = concatByteData(ctx.buffer, data);
		while (ctx.buffer.length >= 2) {
			// Xray calls NextPaddingLen() BEFORE Decode() — both consume SHAKE128
			let padLen = 0;
			if (hasPadding && ctx.reqShakeParser) {
				padLen = ctx.reqShakeParser.nextPaddingLen();
			}
			let len;
			if (ctx.reqShakeParser) {
				len = ctx.reqShakeParser.decode(ctx.buffer.subarray(0, 2));
			} else {
				len = (ctx.buffer[0] << 8) | ctx.buffer[1];
			}
			if (len === 0) {
				ctx.buffer = new Uint8Array(0);
				break;
			}
			if (ctx.buffer.length < 2 + len) break;
			// Xray includes padding in the wire size but strips it BEFORE decrypt
			const actualLen = len - padLen;
			if (actualLen <= 0) {
				ctx.buffer = ctx.buffer.slice(2 + len);
				continue;
			}
			const chunkData = ctx.buffer.slice(2, 2 + actualLen);
			ctx.buffer = ctx.buffer.slice(2 + len);
			let decrypted;
			try {
				decrypted = await vmessDecryptChunk(
					chunkData,
					ctx.bodyKey,
					ctx.bodyIV,
					ctx.count++,
					ctx.security === 'auto' ? 'aes-128-gcm' : ctx.security
				);
			} catch (e) {
				throw new Error('VMess chunk decrypt failed: ' + e.message);
			}
			if (decrypted && decrypted.byteLength) {
				await writeToRemote(decrypted);
			}
		}
	};

	const handleWSInboundData = async (chunk) => {
		let currentChunkBytes = null;
		if (isDnsQuery) {
			if (isTrojan)
				return await forwardTrojanUDPData(chunk, serverSock, trojanUDPContext, request);
			return await forwardUDP(chunk, serverSock, null, request);
		}
		if (determineProtocolType === 'ss') {
			await handleSSData(chunk);
			return;
		}
		if (determineProtocolType === 'vmess') {
			await handleVMessData(chunk);
			return;
		}
		if (wsLocalSpeedTestMode) {
			await handleWSLocalSpeedTestData(chunk);
			return;
		}
		if (await writeToRemote(chunk)) return;

		if (determineProtocolType === null) {
			if (url.searchParams.get('enc')) {
				determineProtocolType = 'ss';
			} else {
				currentChunkBytes = currentChunkBytes || toUint8Array(chunk);
				const bytes = currentChunkBytes;
				if (bytes.byteLength >= 18 && bytes[0] === 0 && uuidBytesMatch(bytes, 1, yourUUID)) {
					determineProtocolType = 'VLESS';
				} else if (
					bytes.byteLength >= 58 &&
					bytes[56] === 0x0d &&
					bytes[57] === 0x0a &&
					matchTrojanPassword(bytes, getTrojanPasswordHashes(yourUUID))
				) {
					determineProtocolType = 'trojan';
				} else if (bytes.byteLength >= 16) {
					try {
						const cmdKey = getCmdKey(yourUUID);
						if (decodeAuthID(bytes.subarray(0, 16), cmdKey)) {
							determineProtocolType = 'vmess';
						}
					} catch {}
				}

				if (determineProtocolType === null) {
					const isTrojanDelimiter =
						bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a;
					const isValidTrojanCmd =
						bytes.byteLength < 60 ||
						bytes[58] === 0x01 ||
						bytes[58] === 0x03 ||
						bytes[58] === 0x7f;
					determineProtocolType =
						isTrojanDelimiter && isValidTrojanCmd ? 'trojan' : 'VLESS';
				}
			}
			isTrojan = determineProtocolType === 'trojan';
			log(
				`[WSforward] protocolType: ${determineProtocolType} | from: ${url.host} | UA: ${request.headers.get('user-agent') || 'unknown'}`
			);
		}

		if (determineProtocolType === 'vmess') {
			await handleVMessData(chunk);
			return;
		}

		if (determineProtocolType === 'ss') {
			await handleSSData(chunk);
			return;
		}
		if (await writeToRemote(chunk)) return;
		if (determineProtocolType === 'trojan') {
			const parseResult = parseTrojanRequest(chunk, yourUUID);
			if (parseResult?.hasError)
				throw new Error(parseResult.message || 'Invalid trojan request');
			const { port, hostname, rawClientData, isUDP } = parseResult;
			if (isSpeedTestSite(hostname) && proxyContext.proxyType === null) {
				await enableWSLocalSpeedTestMode(serverSock, null, rawClientData);
				return;
			}
			if (isUDP) {
				isDnsQuery = true;
				trojanUDPContext.targetHost = hostname;
				trojanUDPContext.targetPort = port;
				if (trojanUDPContext.proxyAddress)
					return forwardTrojanUDPData(
						currentChunkBytes || toUint8Array(chunk),
						serverSock,
						trojanUDPContext,
						request
					);
				if (getValidDataLength(rawClientData) > 0)
					return forwardTrojanUDPData(
						rawClientData,
						serverSock,
						trojanUDPContext,
						request
					);
				return;
			}
			await forwardTCP(
				hostname,
				port,
				rawClientData,
				serverSock,
				null,
				remoteConnWrapper,
				yourUUID,
				request,
				proxyContext,
				true,
				currentChunkBytes || toUint8Array(chunk)
			);
		} else {
			isTrojan = false;
			currentChunkBytes = currentChunkBytes || toUint8Array(chunk);
			const bytes = currentChunkBytes;
			const parseResult = parseVLESSRequest(bytes, yourUUID);
			if (parseResult?.hasError)
				throw new Error(parseResult.message || 'Invalid VLESS request');
			const { port, hostname, version, isUDP, rawClientData } = parseResult;
			const respHeader = new Uint8Array([version, 0]);
			if (isSpeedTestSite(hostname) && proxyContext.proxyType === null) {
				await enableWSLocalSpeedTestMode(serverSock, respHeader, rawClientData);
				return;
			}
			if (isUDP) {
				if (port === 53) isDnsQuery = true;
				else throw new Error('UDP is not supported');
			}
			const rawData = rawClientData;
			if (isDnsQuery) {
				if (isTrojan)
					return forwardTrojanUDPData(rawData, serverSock, trojanUDPContext, request);
				return forwardUDP(rawData, serverSock, respHeader, request);
			}
			await forwardTCP(
				hostname,
				port,
				rawData,
				serverSock,
				respHeader,
				remoteConnWrapper,
				yourUUID,
				request,
				proxyContext
			);
		}
	};

	const handleWSExplicitTransferError = (err) => {

		if (wsExplicitTransferFailed) return;
		wsExplicitTransferFailed = true;
		wsExplicitTransferStopReceiving = true;
		wsExplicitQueueBytes = 0;
		wsExplicitQueueEntries = 0;
		const msg = err?.message || `${err}`;
		if (msg.includes('Network connection lost') || msg.includes('ReadableStream is closed')) {
			log(`[WSforward] connection ended: ${msg}`);
		} else {
			log(`[WSforward] processing failed: ${msg}`);
		}
		uplinkWriteQueue.clear();
		releaseRemoteWriter();
		invalidateRemote();
		try {
			trojanUDPContext.proxySocket?.close();
		} catch {}
		closeSocketQuietly(serverSock);
	};

	const appendWSExplicitTransferTask = (task) => {
		wsExplicitTransferChain = wsExplicitTransferChain
			.then(task)
			.catch(handleWSExplicitTransferError);
		return wsExplicitTransferChain;
	};

	const enqueueWSExplicitTransfer = (data) => {
		if (wsExplicitTransferStopReceiving || wsExplicitTransferFailed) return;
		const chunkSize = Math.max(0, getValidDataLength(data));
		const nextBytes = wsExplicitQueueBytes + chunkSize;
		const nextItems = wsExplicitQueueEntries + 1;
		if (nextBytes > uplinkQueueMaxBytes || nextItems > uplinkQueueMaxEntries) {
			handleWSExplicitTransferError(
				new Error(`[WSexplicit transfer] queue overflow: ${nextBytes}B/${nextItems}`)
			);
			return;
		}
		wsExplicitQueueBytes = nextBytes;
		wsExplicitQueueEntries = nextItems;
		appendWSExplicitTransferTask(async () => {
			wsExplicitQueueBytes = Math.max(0, wsExplicitQueueBytes - chunkSize);
			wsExplicitQueueEntries = Math.max(0, wsExplicitQueueEntries - 1);
			if (wsExplicitTransferFailed) return;
			await handleWSInboundData(data);
		});
	};

	const finishWSExplicitTransfer = () => {
		if (wsExplicitTransferFinishingEnqueued) return;
		wsExplicitTransferFinishingEnqueued = true;
		wsExplicitTransferStopReceiving = true;
		appendWSExplicitTransferTask(async () => {
			if (wsExplicitTransferFailed) return;
			await uplinkWriteQueue.waitEmpty();
			releaseRemoteWriter();
			invalidateRemote();
			try {
				trojanUDPContext.proxySocket?.close();
			} catch {}
		});
	};

	serverSock.addEventListener('message', (event) => {
		enqueueWSExplicitTransfer(event.data);
	});
	serverSock.addEventListener('close', () => {
		closeSocketQuietly(serverSock);
		finishWSExplicitTransfer();
	});
	serverSock.addEventListener('error', (err) => {
		handleWSExplicitTransferError(err);
	});

	// SS disabled in sec-websocket-protocol early-data mode, avoid protocol value (e.g. "binary") mistaken as base64 data injection first packet caused by AEAD decryption failed
	if (!ssModeDisableEarlyData && earlyDataHeader) {
		try {
			const bytes = decodeWSEarlyData(earlyDataHeader, yourUUID);
			if (bytes?.byteLength) enqueueWSExplicitTransfer(bytes);
		} catch (error) {
			handleWSExplicitTransferError(error);
		}
	}

	const responseHeaders = { 'Sec-WebSocket-Extensions': '' };
	if (earlyDataHeader) {
		responseHeaders['Sec-WebSocket-Protocol'] = earlyDataHeader;
	}

	return new Response(null, {
		status: 101,
		webSocket: clientSock,
		headers: responseHeaders,
	});
}
