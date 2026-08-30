/**
 * src/core/tcp.js
 * Auto-generated from _worker.js refactor
 * Original: edgetunnel 2.1 (2026-08-11)
 */
import { PROXY_CONCURRENT_DIAL_COUNT, TCP_CONCURRENT_DIAL_COUNT, preloadRaceDial, socks5Whitelist } from '../state.js';
import { featureCodeDict } from '../constants.js';
import { connectStreams } from './grain.js';
import { connectTrojanProxy, extractTrojanProxyHandshakeData } from './protocol.js';
import { createRequestTCPConnector, httpConnect, httpsConnect, socks5Connect } from './proxy.js';
import { doHQuery, resolveAddressPort } from '../utils/doh.js';
import { getValidDataLength, startTCPConnectorGeneration } from '../handlers/xhttp.js';
import { isIPHostname, isIPv4 } from '../utils/network.js';
import { log, toUint8Array } from '../utils/helpers.js';
import { sstpConnect } from './sstp.js';
import { turnConnect } from './turn.js';


export async function forwardTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, yourUUID, request = null, proxyContext = {}, allowTrojanProxy = false, trojanProxyFirstPacketData = null, connectOnly = false) {
	const ctxproxyIP = proxyContext.proxyIP || '';
	const ctxproxyType = proxyContext.proxyType !== undefined ? proxyContext.proxyType : null;
	const ctxproxyGlobal = proxyContext.proxyGlobal !== undefined ? proxyContext.proxyGlobal : false;
	const ctxproxyParams = proxyContext.proxyParams || {};
	const ctxproxyFallback = proxyContext.proxyFallback !== undefined ? proxyContext.proxyFallback : true;
	let proxyArrayIndex = 0;
	log(`[TCPforward] target: ${host}:${portNum} | proxyIP: ${ctxproxyIP} | proxyFallback: ${ctxproxyFallback ? 'yes' : 'no'} | proxyType: ${ctxproxyType || 'proxyip'} | global: ${ctxproxyGlobal ? 'yes' : 'no'}`);
	const CONNECTION_TIMEOUT_MS = 1000;
	let firstPacketSentViaProxy = false;
	const tcpConnector = createRequestTCPConnector(request);
	const useTrojanProxy = allowTrojanProxy && (proxyContext.trojanProxyAddress || null);
	const trojanProxyTarget = useTrojanProxy ? proxyContext.trojanProxyAddress : null;
	const trojanProxyHandshakeData = useTrojanProxy ? extractTrojanProxyHandshakeData(trojanProxyFirstPacketData, rawData) : null;
	let pendingResponseHeader = respHeader;
	const extractResponseHeader = () => {
		const header = pendingResponseHeader;
		pendingResponseHeader = null;
		return header;
	};
	if (!Number.isInteger(remoteConnWrapper.generation)) remoteConnWrapper.generation = 0;

	const installCurrentConnection = async (socket, generation, downlinkDrain, retryFunc = null) => {
		try { await downlinkDrain } catch (e) {
			if (remoteConnWrapper.downlinkDrain === downlinkDrain) remoteConnWrapper.downlinkDrain = Promise.resolve();
			try { socket?.close?.() } catch (_) { }
			if (remoteConnWrapper.generation === generation) closeSocketQuietly(ws);
			throw e;
		}
		if (remoteConnWrapper.downlinkDrain === downlinkDrain) remoteConnWrapper.downlinkDrain = Promise.resolve();
		const isConnectionStillValid = () => remoteConnWrapper.generation === generation && remoteConnWrapper.socket === socket;
		if (remoteConnWrapper.generation !== generation || ws.readyState !== WebSocket.OPEN) {
			try { socket?.close?.() } catch (e) { }
			if (remoteConnWrapper.generation === generation) remoteConnWrapper.socket = null;
			throw new Error('connection superseded or client closed');
		}
		remoteConnWrapper.socket = socket;
		if (connectOnly) return socket;
		connectStreams(socket, ws, extractResponseHeader, retryFunc, isConnectionStillValid, remoteConnWrapper).catch(err => {
			if (!isConnectionStillValid()) return;
			log(`[TCPdownlink] processing failed: ${err?.message || err}`);
			try { socket?.close?.() } catch (e) { }
			closeSocketQuietly(ws);
		});
		return true;
	};

	async function waitForConnectionEstablished(remoteSock, timeoutMs = CONNECTION_TIMEOUT_MS) {
		await Promise.race([
			remoteSock.opened,
			new Promise((_, reject) => setTimeout(() => reject(new Error('connection timeout')), timeoutMs))
		]);
	}

	async function opentcpConnector(address, port) {
		const remoteSock = tcpConnector({ hostname: address, port });
		try {
			await waitForConnectionEstablished(remoteSock);
			return remoteSock;
		} catch (err) {
			try { remoteSock?.close?.() } catch (e) { }
			throw err;
		}
	}

	async function writeFirstPacket(remoteSock, data) {
		if (getValidDataLength(data) <= 0) return;
		const writer = remoteSock.writable.getWriter();
		try { await writer.write(toUint8Array(data)) }
		finally { try { writer.releaseLock() } catch (e) { } }
	}

	async function openCandidateConnectionsConcurrently(candidateList) {
		if (candidateList.length === 1) {
			const candidate = candidateList[0];
			return { socket: await opentcpConnector(candidate.hostname, candidate.port), candidate: candidate };
		}
		const attempts = candidateList.map(candidate => opentcpConnector(candidate.hostname, candidate.port).then(socket => ({ socket, candidate: candidate })));
		let winner = null;
		try {
			winner = await Promise.any(attempts);
			return winner;
		} finally {
			if (winner) {
				for (const attempt of attempts) {
					attempt.then(({ socket }) => {
						if (socket !== winner.socket) {
							try { socket?.close?.() } catch (e) { }
						}
					}).catch(() => { });
				}
			}
		}
	}

	async function buildPreloadRaceCandidateList(address, port) {
		if (!preloadRaceDial || isIPHostname(address)) return null;
		log(`[TCP Direct] preloadRaceDialenabled，start concurrent query ${address}  A/AAAA record`);
		const [aRecords, aaaaRecords] = await Promise.all([
			doHQuery(address, 'A'),
			doHQuery(address, 'AAAA')
		]);
		const ipv4List = [...new Set(aRecords.flatMap(r => {
			const data = r.data;
			return r.type === 1 && typeof data === 'string' && isIPv4(data) ? [data] : [];
		}))];
		const ipv6List = [...new Set(aaaaRecords.flatMap(r => {
			const data = r.data;
			return r.type === 28 && typeof data === 'string' && isIPHostname(data) ? [data] : [];
		}))];
		const dialLimit = Math.max(1, TCP_CONCURRENT_DIAL_COUNT | 0);
		const ipList = ipv4List.length >= dialLimit
			? ipv4List.slice(0, dialLimit)
			: ipv4List.concat(ipv6List.slice(0, dialLimit - ipv4List.length));
		const useRecordType = ipv4List.length > 0
			? (ipList.length > ipv4List.length ? 'A+AAAA' : 'A')
			: 'AAAA';
		if (ipList.length === 0) {
			log(`[TCP Direct] ${address}  A/AAAA no valid resolution result，preload race unavailable，fallback to original hostname direct connect。`);
			return null;
		}
		const selectedIPList = ipList;
		log(`[TCP Direct] ${address} Arecord:${ipv4List.length} AAAArecord:${ipv6List.length}，use${useRecordType}record，race dial ${selectedIPList.length}/${dialLimit}: ${selectedIPList.join(', ')}`);
		return selectedIPList.map((hostname, attempt) => ({ hostname, port, attempt, resolvedFrom: address }));
	}

	async function connectDirect(address, port, data = null, enablePreload = false) {
		const preloadCandidateList = enablePreload ? await buildPreloadRaceCandidateList(address, port) : null;
		const candidateList = preloadCandidateList || Array.from({ length: TCP_CONCURRENT_DIAL_COUNT }, (_, attempt) => ({ hostname: address, port, attempt }));
		log(preloadCandidateList
			? `[TCP Direct] concurrent attempt ${candidateList.length} routes: ${candidateList.map(candidate => `${candidate.hostname}:${candidate.port}`).join(', ')}`
			: `[TCP Direct] concurrent attempt ${candidateList.length} routes: ${address}:${port}`);
		let socket = null;
		try {
			const connectionResult = await openCandidateConnectionsConcurrently(candidateList);
			socket = connectionResult.socket;
			if (preloadCandidateList) {
				const winner = connectionResult.candidate;
				log(`[TCP Direct] preload raceresult: ${winner.hostname}:${winner.port} won，source domain: ${winner.resolvedFrom || address}`);
			}
			await writeFirstPacket(socket, data);
			return socket;
		} catch (err) {
			try { socket?.close?.() } catch (e) { }
			if (preloadCandidateList) log(`[TCP Direct] preload race failed: ${err.message || err}`);
			throw err;
		}
	}

	async function connectProxyIP(address, port, data = null, allProxyArray = null, enableProxyFallback = true) {
		if (allProxyArray && allProxyArray.length > 0) {
			const actualConcurrency = Math.max(1, Math.floor(Number(PROXY_CONCURRENT_DIAL_COUNT) || 1));
			for (let i = 0; i < allProxyArray.length; i += actualConcurrency) {
				const candidateList = [];
				for (let j = 0; j < actualConcurrency && i + j < allProxyArray.length; j++) {
					const index = (proxyArrayIndex + i + j) % allProxyArray.length;
					const [proxyAddress, proxyPort] = allProxyArray[index];
					candidateList.push({ hostname: proxyAddress, port: proxyPort, index: index });
				}
				let socket = null, candidate = null;
				try {
					log(`[Proxy Connection] concurrent attempt ${candidateList.length} routes: ${candidateList.map(candidate => `${candidate.hostname}:${candidate.port}`).join(', ')}`);
					const connectionResult = await openCandidateConnectionsConcurrently(candidateList);
					socket = connectionResult.socket;
					candidate = connectionResult.candidate;
					await writeFirstPacket(socket, data);
					log(`[Proxy Connection] successfully connected to: ${candidate.hostname}:${candidate.port} (index: ${candidate.index})`);
					proxyArrayIndex = candidate.index;
					return socket;
				} catch (err) {
					try { socket?.close?.() } catch (e) { }
					log(`[Proxy Connection] this batch connection failed: ${err.message || err}`);
				}
			}
		}

		if (enableProxyFallback) return connectDirect(address, port, data, false);
		else {
			throw new Error('[Proxy Connection] all proxy connections failed，and not enabledproxyFallback，connection terminated。');
		}
	}

	async function connecttoPry(allowsendfirstPacket = true) {
		if (remoteConnWrapper.connectingPromise) {
			await remoteConnWrapper.connectingPromise;
			return;
		}
		const { generation: currentConnectionGeneration, downlinkDrain } = startTCPConnectorGeneration(remoteConnWrapper);

		let currentSendFirstPacket = false, currentFirstPacketData = null;
		if (useTrojanProxy) {
			if (allowsendfirstPacket && !firstPacketSentViaProxy && getValidDataLength(trojanProxyFirstPacketData) > 0) {
				currentFirstPacketData = trojanProxyFirstPacketData;
				currentSendFirstPacket = getValidDataLength(rawData) > 0;
			} else {
				currentFirstPacketData = trojanProxyHandshakeData;
			}
		} else {
			currentSendFirstPacket = allowsendfirstPacket && !firstPacketSentViaProxy && getValidDataLength(rawData) > 0;
			currentFirstPacketData = currentSendFirstPacket ? rawData : null;
		}

		const currentConnectionTask = (async () => {
			let newSocket = null;
			try {
				if (useTrojanProxy) {
					log(`[trojan proxy] proxyTo: ${host}:${portNum}`);
					newSocket = await connectTrojanProxy(currentFirstPacketData, tcpConnector, trojanProxyTarget);
				} else if (ctxproxyType === 'socks5') {
					log(`[SOCKS5proxy] proxyTo: ${host}:${portNum}`);
					newSocket = await socks5Connect(host, portNum, currentFirstPacketData, tcpConnector, ctxproxyParams);
				} else if (ctxproxyType === 'http') {
					log(`[HTTPproxy] proxyTo: ${host}:${portNum}`);
					newSocket = await httpConnect(host, portNum, currentFirstPacketData, false, tcpConnector, ctxproxyParams);
				} else if (ctxproxyType === 'https') {
					log(`[HTTPSproxy] proxyTo: ${host}:${portNum}`);
					newSocket = isIPHostname(ctxproxyParams.hostname)
						? await httpsConnect(host, portNum, currentFirstPacketData, tcpConnector, ctxproxyParams)
						: await httpConnect(host, portNum, currentFirstPacketData, true, tcpConnector, ctxproxyParams);
				} else if (ctxproxyType === 'turn') {
					log(`[TURNproxy] proxyTo: ${host}:${portNum}`);
					newSocket = await turnConnect(ctxproxyParams, host, portNum, tcpConnector);
					if (getValidDataLength(currentFirstPacketData) > 0) {
						const writer = newSocket.writable.getWriter();
						try { await writer.write(toUint8Array(currentFirstPacketData)) }
						finally { try { writer.releaseLock() } catch (e) { } }
					}
				} else if (ctxproxyType === 'sstp') {
					log(`[SSTPproxy] proxyTo: ${host}:${portNum}`);
					newSocket = await sstpConnect(ctxproxyParams, host, portNum, tcpConnector);
					if (getValidDataLength(currentFirstPacketData) > 0) {
						const writer = newSocket.writable.getWriter();
						try { await writer.write(toUint8Array(currentFirstPacketData)) }
						finally { try { writer.releaseLock() } catch (e) { } }
					}
				} else {
					log(`[Proxy Connection] proxyTo: ${host}:${portNum}`);
					const allProxyArray = await resolveAddressPort(ctxproxyIP, host, yourUUID);
					newSocket = await connectProxyIP(`${featureCodeDict[0]}.tp1.${featureCodeDict[2]}.xyz`, 1, currentFirstPacketData, allProxyArray, ctxproxyFallback);
				}
				await installCurrentConnection(newSocket, currentConnectionGeneration, downlinkDrain);
				if (currentSendFirstPacket) firstPacketSentViaProxy = true;
			} catch (err) {
				try { newSocket?.close?.() } catch (e) { }
				if (remoteConnWrapper.generation === currentConnectionGeneration) {
					remoteConnWrapper.socket = null;
					closeSocketQuietly(ws);
					throw err;
				}
			}
		})();

		remoteConnWrapper.connectingPromise = currentConnectionTask;
		try {
			await currentConnectionTask;
		} finally {
			if (remoteConnWrapper.connectingPromise === currentConnectionTask) {
				remoteConnWrapper.connectingPromise = null;
			}
		}
	}
	remoteConnWrapper.retryConnect = async () => connecttoPry(!firstPacketSentViaProxy);

	if (ctxproxyType && (ctxproxyGlobal || socks5Whitelist.some(p => new RegExp(`^${p.replace(/\*/g, '.*')}$`, 'i').test(host)))) {
		log(`[TCPforward] enable SOCKS5/HTTP/HTTPS/TURN/SSTP global proxy`);
		try {
			await connecttoPry();
			if (connectOnly) return remoteConnWrapper.socket;
		} catch (err) {
			log(`[TCPforward] SOCKS5/HTTP/HTTPS/TURN/SSTP proxy connection failed: ${err.message}`);
			throw err;
		}
	} else {
		let directGeneration = remoteConnWrapper.generation;
		try {
			log(`[TCPforward] try direct connect to: ${host}:${portNum}`);
			const generationConnection = startTCPConnectorGeneration(remoteConnWrapper);
			directGeneration = generationConnection.generation;
			const initialSocket = await connectDirect(host, portNum, rawData, true);
			await installCurrentConnection(initialSocket, directGeneration, generationConnection.downlinkDrain, async () => {
				if (remoteConnWrapper.generation !== directGeneration || remoteConnWrapper.socket !== initialSocket) return;
				await connecttoPry();
			});
			if (connectOnly) return initialSocket;
		} catch (err) {
			log(`[TCPforward] direct connect ${host}:${portNum} failed: ${err.message}`);
			if (remoteConnWrapper.generation !== directGeneration) throw err;
			if (err instanceof Error && err.name === 'preload parseisEmpty') {
				closeSocketQuietly(ws);
				throw err;
			}
			if (ws.readyState !== WebSocket.OPEN) throw err;
			await connecttoPry();
			if (connectOnly) return remoteConnWrapper.socket;
		}
	}
}


export async function forwardUDP(udpChunk, webSocket, respHeader, request, responseWrapper = null) {
	const requestData = toUint8Array(udpChunk);
	const requestByteCount = requestData.byteLength;
	log(`[UDPforward] received DNS request: ${requestByteCount}B -> 8.8.4.4:53`);
	try {
		const tcpConnector = createRequestTCPConnector(request);
		const tcpSocket = tcpConnector({ hostname: '8.8.4.4', port: 53 });
		let vlessHeader = respHeader;
		const writer = tcpSocket.writable.getWriter();
		await writer.write(requestData);
		log(`[UDPforward] DNS requestwasWrittenupstream: ${requestByteCount}B`);
		writer.releaseLock();
		await tcpSocket.readable.pipeTo(new WritableStream({
			async write(chunk) {
				const rawResponse = toUint8Array(chunk);
				log(`[UDP Forward] Received DNS response: ${rawResponse.byteLength}B`);
				const wrapResult = responseWrapper ? await responseWrapper(rawResponse) : rawResponse;
				const sendFragmentList = Array.isArray(encapsulateResult) ? encapsulateResult : [encapsulateResult];
				if (!sendFragmentList.length) return;
				if (webSocket.readyState !== WebSocket.OPEN) return;
				for (const fragment of sendFragmentList) {
					const forwardedResponse = toUint8Array(fragment);
					if (!forwardedResponse.byteLength) continue;
					if (vlessHeader) {
						const response = new Uint8Array(vlessHeader.length + forwardedResponse.byteLength);
						response.set(vlessHeader, 0);
						response.set(forwardedResponse, vlessHeader.length);
						await webSocketSendAndAwait(webSocket, response.buffer);
						vlessHeader = null;
					} else {
						await webSocketSendAndAwait(webSocket, forwardedResponse);
					}
				}
			},
		}));
	} catch (error) {
		log(`[UDPforward] DNS forwardFailed: ${error?.message || error}`);
	}
}


export function closeSocketQuietly(socket) {
	try {
		if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
			socket.close();
		}
	} catch (error) { }
}


export function formatIdentifier(arr, offset = 0) {
	const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join('');
	return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}


export async function webSocketSendAndAwait(webSocket, payload) {
	const sendResult = webSocket.send(payload);
	if (sendResult && typeof sendResult.then === 'function') await sendResult;
}