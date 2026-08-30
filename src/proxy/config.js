/**
 * src/proxy/config.js
 * Chain-proxy config parsing (getProxyParams, ports, SOCKS5 account) —
 * split from src/core/proxy.js (rewrite by Xray-core layout).
 */
import { base64SecretDecode } from '../utils/crypto.js';
import { parseTrojanProxyAddress } from './trojan/encoding.js';

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
