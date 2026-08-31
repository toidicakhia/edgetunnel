/**
 * src/core/proxy.js
 * Auto-generated from _worker.js refactor
 * Original: edgetunnel 2.1 (2026-08-11)
 */
import { parseTrojanProxyAddress } from './protocol.js';

export function createRequestTCPConnector(request) {
	const requestObj = /** @type {any} */ (request);
	const fetcher = requestObj?.fetcher;
	if (!fetcher || typeof fetcher.connect !== 'function')
		throw new Error('request.fetcher.connect unavailable');
	return (options, init) =>
		init === undefined ? fetcher.connect(options) : fetcher.connect(options, init);
}
////////////////////////////////////////////TLSClient by: @Alexandre_Kojeve////////////////////////////////////////////////

export async function getProxyParams(url, _uuid, defaultProxyIP = '', defaultProxyFallback = true) {
	const { searchParams } = url;
	const pathname = decodeURIComponent(url.pathname);
	const pathLower = pathname.toLowerCase();
	let proxyIP = defaultProxyIP,
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
		proxyContext.proxyType = null;
		proxyContext.proxyAccount = '';
		proxyContext.proxyGlobal = false;
		proxyContext.proxyParams = {};
		proxyContext.proxyFallback = enableproxyFallback;
	};

	const setProxyIP = (value) => {
		proxyIP = value;
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
		setProxyIP(queryProxyIP);
		saveSnapshot();
		return proxyContext;
	}

	const pathProxyMatch = /\/(proxyip[.=]|pyip=|ip=)([^?#\s]+)/.exec(pathLower);
	if (pathProxyMatch) {
		setProxyIP(extractPathValue(pathProxyMatch[2]));
		saveSnapshot();
		return proxyContext;
	}

	saveSnapshot();
	return proxyContext;
}
