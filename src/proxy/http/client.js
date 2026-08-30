/**
 * src/proxy/http/client.js
 * HTTP CONNECT chain-proxy clients (http + https) — split from src/core/proxy.js
 * (rewrite by Xray-core layout; matches proxy/http client semantics).
 */
import { concatByteData, getValidDataLength, log, safeCloseAll, toUint8Array } from '../../utils/helpers.js';
import { isIPHostname, stripIPv6Brackets } from '../../utils/network.js';
import { TlsClient } from '../../transport/internet/tls.js';

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
		safeCloseAll(writer, reader, socket);
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
			} catch {}
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
			} catch {}
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
					} catch {}
					settleClosed(resolveClosed);
				} catch (error) {
					try {
						controller.error(error);
					} catch {}
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
		} catch {}
		throw error;
	}
}

