/**
 * src/core/proxy.js
 * Auto-generated from _worker.js refactor
 * Original: edgetunnel 2.1 (2026-08-11)
 */
import { TlsClient } from './tls.js';
import { base64SecretDecode } from '../utils/crypto.js';
import { concatByteData, log, toUint8Array } from '../utils/helpers.js';
import { getValidDataLength } from '../handlers/xhttp.js';
import { isIPHostname, stripIPv6Brackets } from '../utils/network.js';
import { parseTrojanProxyAddress } from './protocol.js';

export async function socks5Connect(
	targetHost,
	targetPort,
	initialData,
	tcpConnector,
	parsedSocks5
) {
	const { username, password, hostname, port } = parsedSocks5 || {};
	const socket = tcpConnector({ hostname, port }),
		writer = socket.writable.getWriter(),
		reader = socket.readable.getReader();
	try {
		const authMethods =
			username && password
				? new Uint8Array([0x05, 0x02, 0x00, 0x02])
				: new Uint8Array([0x05, 0x01, 0x00]);
		await writer.write(authMethods);
		let response = await reader.read();
		if (response.done || response.value.byteLength < 2)
			throw new Error('S5 method selection failed');

		const selectedMethod = new Uint8Array(response.value)[1];
		if (selectedMethod === 0x02) {
			if (!username || !password) throw new Error('S5 requires authentication');
			const userBytes = new TextEncoder().encode(username),
				passBytes = new TextEncoder().encode(password);
			const authPacket = new Uint8Array([
				0x01,
				userBytes.length,
				...userBytes,
				passBytes.length,
				...passBytes,
			]);
			await writer.write(authPacket);
			response = await reader.read();
			if (response.done || new Uint8Array(response.value)[1] !== 0x00)
				throw new Error('S5 authentication failed');
		} else if (selectedMethod !== 0x00)
			throw new Error(`S5 unsupported auth method: ${selectedMethod}`);

		const hostBytes = new TextEncoder().encode(targetHost);
		const connectPacket = new Uint8Array([
			0x05,
			0x01,
			0x00,
			0x03,
			hostBytes.length,
			...hostBytes,
			targetPort >> 8,
			targetPort & 0xff,
		]);
		await writer.write(connectPacket);
		response = await reader.read();
		if (response.done || new Uint8Array(response.value)[1] !== 0x00)
			throw new Error('S5 connection failed');

		if (getValidDataLength(initialData) > 0) await writer.write(initialData);
		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (error) {
		try {
			writer.releaseLock();
		} catch (e) {}
		try {
			reader.releaseLock();
		} catch (e) {}
		try {
			socket.close();
		} catch (e) {}
		throw error;
	}
}

export async function httpConnect(
	targetHost,
	targetPort,
	initialData,
	HTTPSproxy = false,
	tcpConnector,
	parsedSocks5
) {
	const { username, password, hostname, port } = parsedSocks5 || {};
	const socket = HTTPSproxy
		? tcpConnector({ hostname, port }, { secureTransport: 'on', allowHalfOpen: false })
		: tcpConnector({ hostname, port });
	const writer = socket.writable.getWriter(),
		reader = socket.readable.getReader();
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	try {
		if (HTTPSproxy) await socket.opened;

		const auth =
			username && password
				? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n`
				: '';
		const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
		await writer.write(encoder.encode(request));
		writer.releaseLock();

		let responseBuffer = new Uint8Array(0),
			headerEndIndex = -1,
			bytesRead = 0;
		while (headerEndIndex === -1 && bytesRead < 8192) {
			const { done, value } = await reader.read();
			if (done || !value)
				throw new Error(
					`${HTTPSproxy ? 'HTTPS' : 'HTTP'} proxyReturns CONNECT before responsecloseConnection`
				);
			responseBuffer = new Uint8Array([...responseBuffer, ...value]);
			bytesRead = responseBuffer.length;
			const crlfcrlf = responseBuffer.findIndex(
				(_, i) =>
					i < responseBuffer.length - 3 &&
					responseBuffer[i] === 0x0d &&
					responseBuffer[i + 1] === 0x0a &&
					responseBuffer[i + 2] === 0x0d &&
					responseBuffer[i + 3] === 0x0a
			);
			if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
		}

		if (headerEndIndex === -1)
			throw new Error('proxy CONNECT response header too long or invalid');
		const statusMatch = decoder
			.decode(responseBuffer.slice(0, headerEndIndex))
			.split('\r\n')[0]
			.match(/HTTP\/\d\.\d\s+(\d+)/);
		const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
		if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300)
			throw new Error(`Connection failed: HTTP ${statusCode}`);

		reader.releaseLock();

		if (getValidDataLength(initialData) > 0) {
			const remoteWriter = socket.writable.getWriter();
			await remoteWriter.write(initialData);
			remoteWriter.releaseLock();
		}

		// CONNECT tunnel data may follow response header，backfill to readable stream first，avoidfirstPacketswallowed。
		if (bytesRead > headerEndIndex) {
			const { readable, writable } = new TransformStream();
			const transformWriter = writable.getWriter();
			await transformWriter.write(responseBuffer.subarray(headerEndIndex, bytesRead));
			transformWriter.releaseLock();
			socket.readable.pipeTo(writable).catch(() => {});
			return {
				readable,
				writable: socket.writable,
				closed: socket.closed,
				close: () => socket.close(),
			};
		}

		return socket;
	} catch (error) {
		try {
			writer.releaseLock();
		} catch (e) {}
		try {
			reader.releaseLock();
		} catch (e) {}
		try {
			socket.close();
		} catch (e) {}
		throw error;
	}
}

export async function httpsConnect(
	targetHost,
	targetPort,
	initialData,
	tcpConnector,
	parsedSocks5
) {
	const { username, password, hostname, port } = parsedSocks5 || {};
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	let tlsSocket = null;
	const tlsServerName = isIPHostname(hostname) ? '' : stripIPv6Brackets(hostname);
	const openHTTPSproxyTLS = async (allowChacha = false) => {
		const proxySocket = tcpConnector({ hostname, port });
		try {
			await proxySocket.opened;
			const socket = new TlsClient(proxySocket, {
				serverName: tlsServerName,
				insecure: true,
				allowChacha,
			});
			await socket.handshake();
			log(
				`[HTTPSproxy] TLSversion: ${socket.isTls13 ? '1.3' : '1.2'} | Cipher: 0x${socket.cipherSuite.toString(16)}${socket.cipherConfig?.chacha ? ' (ChaCha20)' : ' (AES-GCM)'}`
			);
			return socket;
		} catch (error) {
			try {
				proxySocket.close();
			} catch (e) {}
			throw error;
		}
	};
	try {
		try {
			tlsSocket = await openHTTPSproxyTLS(false);
		} catch (error) {
			if (
				!/cipher|handshake|TLSAlert|ServerHello|Finished|Unsupported|MissingTLS/i.test(
					error?.message || `${error || ''}`
				)
			)
				throw error;
			log(
				`[HTTPSproxy] AES-GCM TLS handshake failed，fallback ChaCha20 compat mode: ${error?.message || error}`
			);
			tlsSocket = await openHTTPSproxyTLS(true);
		}

		const auth =
			username && password
				? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n`
				: '';
		const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
		await tlsSocket.write(encoder.encode(request));

		let responseBuffer = new Uint8Array(0),
			headerEndIndex = -1,
			bytesRead = 0;
		while (headerEndIndex === -1 && bytesRead < 8192) {
			const value = await tlsSocket.read();
			if (!value)
				throw new Error('HTTPS proxyReturns CONNECT before responsecloseConnection');
			responseBuffer = concatByteData(responseBuffer, value);
			bytesRead = responseBuffer.length;
			const crlfcrlf = responseBuffer.findIndex(
				(_, i) =>
					i < responseBuffer.length - 3 &&
					responseBuffer[i] === 0x0d &&
					responseBuffer[i + 1] === 0x0a &&
					responseBuffer[i + 2] === 0x0d &&
					responseBuffer[i + 3] === 0x0a
			);
			if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
		}

		if (headerEndIndex === -1)
			throw new Error('HTTPS proxy CONNECT response header too long or invalid');
		const statusMatch = decoder
			.decode(responseBuffer.slice(0, headerEndIndex))
			.split('\r\n')[0]
			.match(/HTTP\/\d\.\d\s+(\d+)/);
		const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
		if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300)
			throw new Error(`Connection failed: HTTP ${statusCode}`);

		if (getValidDataLength(initialData) > 0) await tlsSocket.write(toUint8Array(initialData));
		const bufferedData =
			bytesRead > headerEndIndex ? responseBuffer.subarray(headerEndIndex, bytesRead) : null;
		let closedSettled = false,
			resolveClosed,
			rejectClosed;
		const settleClosed = (settle, value) => {
			if (!closedSettled) {
				closedSettled = true;
				settle(value);
			}
		};
		const closed = new Promise((resolve, reject) => {
			resolveClosed = resolve;
			rejectClosed = reject;
		});
		const close = () => {
			try {
				tlsSocket.close();
			} catch (e) {}
			settleClosed(resolveClosed);
		};
		const readable = new ReadableStream({
			async start(controller) {
				try {
					if (getValidDataLength(bufferedData) > 0) controller.enqueue(bufferedData);
					while (true) {
						const data = await tlsSocket.read();
						if (!data) break;
						if (data.byteLength > 0) controller.enqueue(data);
					}
					try {
						controller.close();
					} catch (e) {}
					settleClosed(resolveClosed);
				} catch (error) {
					try {
						controller.error(error);
					} catch (e) {}
					settleClosed(rejectClosed, error);
				}
			},
			cancel() {
				close();
			},
		});
		const writable = new WritableStream({
			async write(chunk) {
				await tlsSocket.write(toUint8Array(chunk));
			},
			close,
			abort(error) {
				close();
				if (error) settleClosed(rejectClosed, error);
			},
		});
		return { readable, writable, closed, close };
	} catch (error) {
		try {
			tlsSocket?.close();
		} catch (e) {}
		throw error;
	}
}

export function createRequestTCPConnector(request) {
	const requestObj = /** @type {any} */ (request);
	const fetcher = requestObj?.fetcher;
	if (!fetcher || typeof fetcher.connect !== 'function')
		throw new Error('request.fetcher.connect unavailable');
	return (options, init) =>
		init === undefined ? fetcher.connect(options) : fetcher.connect(options, init);
}
////////////////////////////////////////////TLSClient by: @Alexandre_Kojeve////////////////////////////////////////////////

export async function getProxyParams(url, uuid, defaultProxyIP = '', defaultProxyFallback = true) {
	const { searchParams } = url;
	const pathname = decodeURIComponent(url.pathname);
	const pathLower = pathname.toLowerCase();
	let proxyIP = defaultProxyIP,
		enableSOCKS5proxy = null,
		enableSOCKS5globalProxy = false,
		mySOCKS5account = '',
		parsedSocks5Address = {},
		enableproxyFallback = defaultProxyFallback;
	const proxyContext = {
		trojanProxyAddress: null,
		proxyIP,
		proxyType: null,
		proxyAccount: '',
		proxyGlobal: false,
		proxyParams: {},
		proxyFallback: enableproxyFallback,
	};
	const saveSnapshot = () => {
		proxyContext.proxyIP = proxyIP;
		proxyContext.proxyType = enableSOCKS5proxy;
		proxyContext.proxyAccount = mySOCKS5account;
		proxyContext.proxyGlobal = enableSOCKS5globalProxy;
		proxyContext.proxyParams = { ...parsedSocks5Address };
		proxyContext.proxyFallback = enableproxyFallback;
	};

	const chainProxyPathMatch = pathname.match(/\/video\/(.+)$/i);
	if (chainProxyPathMatch) {
		try {
			const chainProxyPlaintext = base64SecretDecode(
				chainProxyPathMatch[1].replace(/\/+$/, ''),
				uuid
			);
			const { type, ...chainProxyAddress } = JSON.parse(chainProxyPlaintext);
			if (!type || !proxyProtocolDefaultPorts[String(type).toLowerCase()])
				throw new Error('chainproxyTypeinvalid');
			if (!chainProxyAddress.hostname || !chainProxyAddress.port)
				throw new Error('Chain proxy missing hostname or port');
			mySOCKS5account = '';
			proxyIP = 'chain proxy';
			enableproxyFallback = false;
			enableSOCKS5globalProxy = true;
			enableSOCKS5proxy = String(type).toLowerCase();
			parsedSocks5Address = {
				username: chainProxyAddress.username,
				password: chainProxyAddress.password,
				hostname: chainProxyAddress.hostname,
				port: Number(chainProxyAddress.port),
			};
			if (isNaN(parsedSocks5Address.port)) throw new Error('chain proxyPort invalid');
			saveSnapshot();
			return proxyContext;
		} catch (err) {
			console.error('parse chainproxyParamsfailed:', err.message);
		}
	}

	mySOCKS5account =
		searchParams.get('socks5') ||
		searchParams.get('http') ||
		searchParams.get('https') ||
		searchParams.get('turn') ||
		searchParams.get('sstp') ||
		null;
	enableSOCKS5globalProxy = searchParams.has('globalproxy');
	if (searchParams.get('socks5')) enableSOCKS5proxy = 'socks5';
	else if (searchParams.get('http')) enableSOCKS5proxy = 'http';
	else if (searchParams.get('https')) enableSOCKS5proxy = 'https';
	else if (searchParams.get('turn')) enableSOCKS5proxy = 'turn';
	else if (searchParams.get('sstp')) enableSOCKS5proxy = 'sstp';

	const parseProxyURL = (value, forceGlobal = true) => {
		const match = /^(socks5|http|https|turn|sstp):\/\/(.+)$/i.exec(value || '');
		if (!match) return false;
		enableSOCKS5proxy = match[1].toLowerCase();
		mySOCKS5account = match[2].split('/')[0];
		if (forceGlobal) enableSOCKS5globalProxy = true;
		return true;
	};

	const setProxyIP = (value) => {
		proxyIP = value;
		enableSOCKS5proxy = null;
		enableproxyFallback = false;
	};

	const extractPathValue = (value) => {
		if (!value.includes('://')) {
			const slashIndex = value.indexOf('/');
			return slashIndex > 0 ? value.slice(0, slashIndex) : value;
		}
		const protocolSplit = value.split('://');
		if (protocolSplit.length !== 2) return value;
		const slashIndex = protocolSplit[1].indexOf('/');
		return slashIndex > 0
			? `${protocolSplit[0]}://${protocolSplit[1].slice(0, slashIndex)}`
			: value;
	};

	const trojanPathMatch = /\/trojan=([^?#\s]+)/i.exec(pathname);
	if (trojanPathMatch) {
		try {
			proxyContext.trojanProxyAddress = parseTrojanProxyAddress(
				trojanPathMatch[1].replace(/\/+$/, '')
			);
		} catch (err) {
			console.error('parseTrojanProxyAddressfailed:', err.message);
			proxyContext.trojanProxyAddress = null;
		}
	}

	const queryProxyIP = searchParams.get('proxyip');
	if (queryProxyIP !== null) {
		if (!parseProxyURL(queryProxyIP)) {
			setProxyIP(queryProxyIP);
			saveSnapshot();
			return proxyContext;
		}
	} else {
		let match = /\/(socks5?|http|https|turn|sstp):\/?\/?([^/?#\s]+)/i.exec(pathname);
		if (match) {
			const type = match[1].toLowerCase();
			enableSOCKS5proxy = type === 'sock' || type === 'socks' ? 'socks5' : type;
			mySOCKS5account = match[2].split('/')[0];
			enableSOCKS5globalProxy = true;
		} else if (
			(match = /\/(g?s5|socks5|g?http|g?https|g?turn|g?sstp)=([^/?#\s]+)/i.exec(pathname))
		) {
			const type = match[1].toLowerCase();
			mySOCKS5account = match[2].split('/')[0];
			enableSOCKS5proxy = type.includes('sstp')
				? 'sstp'
				: type.includes('turn')
					? 'turn'
					: type.includes('https')
						? 'https'
						: type.includes('http')
							? 'http'
							: 'socks5';
			if (type.startsWith('g')) enableSOCKS5globalProxy = true;
		} else if ((match = /\/(proxyip[.=]|pyip=|ip=)([^?#\s]+)/.exec(pathLower))) {
			const pathProxyValue = extractPathValue(match[2]);
			if (!parseProxyURL(pathProxyValue)) {
				setProxyIP(pathProxyValue);
				saveSnapshot();
				return proxyContext;
			}
		}
	}

	if (!mySOCKS5account) {
		enableSOCKS5proxy = null;
		saveSnapshot();
		return proxyContext;
	}

	try {
		parsedSocks5Address = await getSOCKS5Account(
			mySOCKS5account,
			getProxyDefaultPort(enableSOCKS5proxy)
		);
		if (searchParams.get('socks5')) enableSOCKS5proxy = 'socks5';
		else if (searchParams.get('http')) enableSOCKS5proxy = 'http';
		else if (searchParams.get('https')) enableSOCKS5proxy = 'https';
		else if (searchParams.get('turn')) enableSOCKS5proxy = 'turn';
		else if (searchParams.get('sstp')) enableSOCKS5proxy = 'sstp';
		else enableSOCKS5proxy = enableSOCKS5proxy || 'socks5';
	} catch (err) {
		console.error('parseSOCKS5address failed:', err.message);
		enableSOCKS5proxy = null;
	}
	saveSnapshot();
	return proxyContext;
}

export const proxyProtocolDefaultPorts = {
	socks5: 1080,
	http: 80,
	https: 443,
	turn: 3478,
	sstp: 443,
};

export function getProxyDefaultPort(type) {
	return proxyProtocolDefaultPorts[String(type || '').toLowerCase()] || 80;
}

export const SOCKS5accountBase64regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i,
	IPv6bracketRegex = /^\[.*\]$/;

export function getSOCKS5Account(address, defaultPort = 80) {
	address = String(address || '')
		.trim()
		.replace(/^(socks5|http|https|turn|sstp):\/\//i, '')
		.split('#')[0]
		.trim();
	const firstAt = address.lastIndexOf('@');
	if (firstAt !== -1) {
		let auth = address.slice(0, firstAt).replaceAll('%3D', '=');
		if (!auth.includes(':') && SOCKS5accountBase64regex.test(auth)) auth = atob(auth);
		address = `${auth}@${address.slice(firstAt + 1)}`;
	}

	const atIndex = address.lastIndexOf('@');
	const hostPart = (atIndex === -1 ? address : address.slice(atIndex + 1)).split('/')[0];
	const authPart = atIndex === -1 ? '' : address.slice(0, atIndex);
	const [username, password] = authPart ? authPart.split(':') : [];
	if (authPart && !password)
		throw new Error(
			'Invalid SOCKS address format：auth section must be "username:password" form of'
		);

	let hostname = hostPart,
		port = defaultPort;
	if (hostPart.includes(']:')) {
		const [ipv6Host, ipv6Port = ''] = hostPart.split(']:');
		hostname = ipv6Host + ']';
		port = Number(ipv6Port.replace(/[^\d]/g, ''));
	} else if (!hostPart.startsWith('[')) {
		const parts = hostPart.split(':');
		if (parts.length === 2) {
			hostname = parts[0];
			port = Number(parts[1].replace(/[^\d]/g, ''));
		}
	}

	if (isNaN(port)) throw new Error('Invalid SOCKS address format：Port must be a number');
	if (hostname.includes(':') && !IPv6bracketRegex.test(hostname))
		throw new Error(
			'Invalid SOCKS address format: IPv6 address must be enclosed in brackets, e.g. [2001:db8::1]'
		);
	return { username, password, hostname, port };
}
