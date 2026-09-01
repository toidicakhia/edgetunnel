/**
 * src/utils/config.js
 * Auto-generated from _worker.js refactor
 * Original: edgetunnel 2.1 (2026-08-11)
 */
import { MD5MD5 } from './crypto.js';
import { getXHTTPPaddingIdentifiers } from '../handlers/xhttp.js';
import { log, parseToArray, randomPath, tryParseJSON } from './helpers.js';
import { generateVMessLink } from '../core/vmess.js';

export function getTransportProtocolConfig(config = {}) {
	const isGRPC = config.transportProtocol === 'grpc';
	const { head: localPaddingHeader, key: localPaddingKey } = getXHTTPPaddingIdentifiers(
		config.UUID
	);
	const xhttpObfsJSON = {
		xPaddingObfsMode: true,
		xPaddingMethod: 'tokenish',
		xPaddingPlacement: 'queryInHeader',
		xPaddingHeader: localPaddingHeader,
		xPaddingKey: localPaddingKey,
	};
	return {
		type: isGRPC
			? config.gRPCmode === 'multi'
				? 'grpc&mode=multi'
				: 'grpc&mode=gun'
			: config.transportProtocol === 'xhttp'
				? `xhttp&mode=stream-one&extra=${encodeURIComponent(JSON.stringify(xhttpObfsJSON))}`
				: 'ws',
		pathFieldName: isGRPC ? 'serviceName' : 'path',
		domainFieldName: isGRPC ? 'authority' : 'host',
	};
}

export function getTransportPathParamValue(
	config = {},
	nodePath = '/',
	asOptimalSubGenerator = false
) {
	const pathValue = asOptimalSubGenerator
		? '/'
		: config.randomPath
			? randomPath(nodePath)
			: nodePath;
	if (config.transportProtocol !== 'grpc') return pathValue;
	return pathValue.split('?')[0] || '/';
}

export {
	clashSubscriptionHotPatch,
	singboxSubscriptionHotPatch,
	surgeSubscriptionHotPatch,
} from '../subscription/generator.js';

export function maskSensitiveInfo(text, prefixlength = 3, suffixlength = 2) {
	if (!text || typeof text !== 'string') return text;
	if (text.length <= prefixlength + suffixlength) return text; // iflengthtooShort，return directly

	const prefix = text.slice(0, prefixlength);
	const suffix = text.slice(-suffixlength);
	const starCount = text.length - prefixlength - suffixlength;

	return `${prefix}${'*'.repeat(starCount)}${suffix}`;
}

export async function readConfigJSON(
	env,
	hostname,
	userID,
	UA = 'Mozilla/5.0',
	resetConfig = false
) {
	let config_JSON;
	const host = hostname,
		Ali_DoH = 'https://dns.alidns.com/dns-query',
		ECH_SNI = 'cloudflare-ech.com',
		initStartTime = performance.now(),
		defaultConfigJSON = {
			TIME: new Date().toISOString(),
			HOST: host,
			HOSTS: [hostname],
			UUID: userID,
			PATH: '/',
			protocolType: 'all',
			transportProtocol: 'ws',
			gRPCmode: 'gun',
			gRPCUserAgent: UA,
			skipCertVerify: false,
			enable0RTT: false,
			TLSFragment: null,
			randomPath: false,
			ECH: false,
			ECHConfig: {
				DNS: Ali_DoH,
				SNI: ECH_SNI,
			},
			SS: {
				cipherMethod: 'aes-128-gcm',
				TLS: true,
			},
			Fingerprint: 'chrome',
			optSubGenerator: {
				localIPDB: {
					specifiedPort: -1,
				},
				SUBNAME: 'edge' + 'tunnel',
				TOKEN: await MD5MD5(hostname + userID),
			},
			CF: {
				Email: null,
				GlobalAPIKey: null,
				AccountID: null,
				APIToken: null,
				UsageAPI: null,
				Usage: {
					success: false,
					pages: 0,
					workers: 0,
					total: 0,
					max: 100000,
				},
			},
		};

	const configJSON = await env.KV.get('config.json');
	if (!configJSON || resetConfig == true) {
		await env.KV.put('config.json', JSON.stringify(defaultConfigJSON, null, 2)).catch?.(
			() => {}
		);
		config_JSON = defaultConfigJSON;
	} else {
		config_JSON = tryParseJSON(configJSON, defaultConfigJSON);
	}

	if (!config_JSON.optSubGenerator) {
		config_JSON.optSubGenerator =
			config_JSON.optimalSubscriptionGeneration || defaultConfigJSON.optSubGenerator;
	}
	if (!config_JSON.CF) config_JSON.CF = defaultConfigJSON.CF;
	if (!config_JSON.gRPCUserAgent) config_JSON.gRPCUserAgent = UA;
	config_JSON.HOST = host;
	if (!config_JSON.HOSTS) config_JSON.HOSTS = [hostname];
	if (env.HOST)
		config_JSON.HOSTS = (await parseToArray(env.HOST)).map(
			(h) =>
				h
					.toLowerCase()
					.replace(/^https?:\/\//, '')
					.split('/')[0]
					.split(':')[0]
		);
	config_JSON.UUID = userID;
	if (!config_JSON.randomPath) config_JSON.randomPath = false;
	if (!config_JSON.enable0RTT) config_JSON.enable0RTT = false;

	if (env.PATH) config_JSON.PATH = env.PATH.startsWith('/') ? env.PATH : '/' + env.PATH;
	else if (!config_JSON.PATH) config_JSON.PATH = '/';

	if (!config_JSON.gRPCmode) config_JSON.gRPCmode = 'gun';
	if (!config_JSON.SS) config_JSON.SS = { cipherMethod: 'aes-128-gcm', TLS: false };

	config_JSON.PATH = config_JSON.PATH.replace('//', '/');
	const normalizedPath =
		config_JSON.PATH === '/'
			? ''
			: config_JSON.PATH.replace(/\/+(?=\?|$)/, '').replace(/\/+$/, '');
	const [pathPart, ...queryArray] = normalizedPath.split('?');
	const queryPart = queryArray.length ? '?' + queryArray.join('?') : '';
	config_JSON.fullNodePath =
		(pathPart || '/') +
		queryPart +
		(config_JSON.enable0RTT ? (queryPart ? '&' : '?') + 'ed=2560' : '');

	if (!config_JSON.TLSFragment && config_JSON.TLSFragment !== null)
		config_JSON.TLSFragment = null;
	const tlsFragmentParam =
		config_JSON.TLSFragment == 'Shadowrocket'
			? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}`
			: config_JSON.TLSFragment == 'Happ'
				? `&fragment=${encodeURIComponent('3,1,tlshello')}`
				: '';
	if (!config_JSON.Fingerprint) config_JSON.Fingerprint = 'chrome';
	if (!config_JSON.ECH) config_JSON.ECH = false;
	if (!config_JSON.ECHConfig) config_JSON.ECHConfig = { DNS: Ali_DoH, SNI: ECH_SNI };
	const echLinkParam = config_JSON.ECH
		? `&ech=${encodeURIComponent((config_JSON.ECHConfig.SNI ? config_JSON.ECHConfig.SNI + '+' : '') + config_JSON.ECHConfig.DNS)}`
		: '';
	const {
		type: transportProtocol,
		pathFieldName,
		domainFieldName,
	} = getTransportProtocolConfig(config_JSON);
	const transportPathParamValue = getTransportPathParamValue(
		config_JSON,
		config_JSON.fullNodePath
	);
	const generateSingleProtocolLink = (proto, suffix = '') => {
		const subName = config_JSON.optSubGenerator.SUBNAME + (suffix ? ` - ${suffix}` : '');
		if (proto === 'ss') {
			return `ss://${btoa(config_JSON.SS.cipherMethod + ':' + userID)}@${host}:${config_JSON.SS.TLS ? '443' : '80'}?plugin=v2${encodeURIComponent(`ray-plugin;mode=websocket;host=${host};path=${(config_JSON.fullNodePath.includes('?') ? config_JSON.fullNodePath.replace('?', '?enc=' + config_JSON.SS.cipherMethod + '&') : config_JSON.fullNodePath + '?enc=' + config_JSON.SS.cipherMethod) + (config_JSON.SS.TLS ? ';tls' : '')};mux=0`) + echLinkParam}#${encodeURIComponent(subName)}`;
		}
		if (proto === 'vmess') {
			return generateVMessLink({
				host,
				port: 443,
				uuid: userID,
				security: 'auto',
				net: transportProtocol.includes('grpc') ? 'grpc' : 'ws',
				path: transportPathParamValue,
				hostHeader: host,
				tls: 'tls',
				sni: host,
				fp: config_JSON.Fingerprint,
				ps: subName,
			});
		}
		if (proto === 'trojan') {
			return `trojan://${userID}@${host}:443?security=tls&type=${transportProtocol + echLinkParam}&${domainFieldName}=${host}&fp=${config_JSON.Fingerprint}&sni=${host}&${pathFieldName}=${encodeURIComponent(transportPathParamValue) + tlsFragmentParam}#${encodeURIComponent(subName)}`;
		}
		return `vless://${userID}@${host}:443?security=tls&type=${transportProtocol + echLinkParam}&${domainFieldName}=${host}&fp=${config_JSON.Fingerprint}&sni=${host}&${pathFieldName}=${encodeURIComponent(transportPathParamValue) + tlsFragmentParam}&encryption=none#${encodeURIComponent(subName)}`;
	};

	if (config_JSON.protocolType === 'all') {
		config_JSON.LINK = [
			generateSingleProtocolLink('vless', 'VLESS'),
			generateSingleProtocolLink('trojan', 'Trojan'),
			generateSingleProtocolLink('vmess', 'VMess'),
			generateSingleProtocolLink('ss', 'SS'),
		].join('\n');
	} else {
		config_JSON.LINK = generateSingleProtocolLink(config_JSON.protocolType || 'vless');
	}
	config_JSON.optSubGenerator.TOKEN = await MD5MD5(hostname + userID);

	const initCF_JSON = {
		Email: null,
		GlobalAPIKey: null,
		AccountID: null,
		APIToken: null,
		UsageAPI: null,
	};
	config_JSON.CF = {
		...initCF_JSON,
		Usage: { success: false, pages: 0, workers: 0, total: 0, max: 100000 },
	};
	const CF_TXT = await env.KV.get('cf.json');
	if (!CF_TXT) {
		await env.KV.put('cf.json', JSON.stringify(initCF_JSON, null, 2)).catch?.(() => {});
	} else {
		const CF_JSON = tryParseJSON(CF_TXT);
		if (CF_JSON?.UsageAPI) {
			const response = await fetch(CF_JSON.UsageAPI).catch?.(() => null);
			const Usage = await response?.json?.().catch?.(() => null);
			if (Usage) config_JSON.CF.Usage = Usage;
		} else if (CF_JSON) {
			config_JSON.CF.Email = CF_JSON.Email ? CF_JSON.Email : null;
			config_JSON.CF.GlobalAPIKey = CF_JSON.GlobalAPIKey
				? maskSensitiveInfo(CF_JSON.GlobalAPIKey)
				: null;
			config_JSON.CF.AccountID = CF_JSON.AccountID
				? maskSensitiveInfo(CF_JSON.AccountID)
				: null;
			config_JSON.CF.APIToken = CF_JSON.APIToken ? maskSensitiveInfo(CF_JSON.APIToken) : null;
			config_JSON.CF.UsageAPI = null;
			const Usage = await getCloudflareUsage(
				CF_JSON.Email,
				CF_JSON.GlobalAPIKey,
				CF_JSON.AccountID,
				CF_JSON.APIToken
			);
			config_JSON.CF.Usage = Usage;
		}
	}

	config_JSON.loadTime = (performance.now() - initStartTime).toFixed(2) + 'ms';

	if (config_JSON.optSubGenerator) {
		config_JSON.optSubGenerator.localIPDB = config_JSON.optSubGenerator.localIPDB || {
			specifiedPort: -1,
		};
	}

	return config_JSON;
}

export async function getCloudflareUsage(Email, GlobalAPIKey, AccountID, APIToken) {
	const API = 'https://api.cloudflare.com/client/v4';
	const sum = (a) => a?.reduce((t, i) => t + (i?.sum?.requests || 0), 0) || 0;
	const cfg = { 'Content-Type': 'application/json' };

	try {
		if (!AccountID && (!Email || !GlobalAPIKey))
			return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };

		if (!AccountID) {
			const r = await fetch(`${API}/accounts`, {
				method: 'GET',
				headers: { ...cfg, 'X-AUTH-EMAIL': Email, 'X-AUTH-KEY': GlobalAPIKey },
			});
			if (!r.ok) throw new Error(`account fetch failed: ${r.status}`);
			const d = await r.json();
			if (!d?.result?.length) throw new Error('account not found');
			const idx = d.result.findIndex((a) =>
				a.name?.toLowerCase().startsWith(Email.toLowerCase())
			);
			AccountID = d.result[idx >= 0 ? idx : 0]?.id;
		}

		const now = new Date();
		now.setUTCHours(0, 0, 0, 0);
		const hdr = APIToken
			? { ...cfg, Authorization: `Bearer ${APIToken}` }
			: { ...cfg, 'X-AUTH-EMAIL': Email, 'X-AUTH-KEY': GlobalAPIKey };

		const res = await fetch(`${API}/graphql`, {
			method: 'POST',
			headers: hdr,
			body: JSON.stringify({
				query: `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
					viewer { accounts(filter: {accountTag: $AccountID}) {
						pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } }
						workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } }
					} }
				}`,
				variables: {
					AccountID,
					filter: {
						datetime_geq: now.toISOString(),
						datetime_leq: new Date().toISOString(),
					},
				},
			}),
		});

		if (!res.ok) throw new Error(`query failed: ${res.status}`);
		const result = await res.json();
		if (result.errors?.length) throw new Error(result.errors[0].message);

		const acc = result?.data?.viewer?.accounts?.[0];
		if (!acc) throw new Error('account data not found');

		const pages = sum(acc.pagesFunctionsInvocationsAdaptiveGroups);
		const workers = sum(acc.workersInvocationsAdaptive);
		const total = pages + workers;
		const max = 100000;
		log(
			`statisticsresult - Pages: ${pages}, Workers: ${workers}, total: ${total}, upper limit: 100000`
		);
		return { success: true, pages, workers, total, max };
	} catch (error) {
		console.error('getUsageError:', error.message);
		return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };
	}
}
