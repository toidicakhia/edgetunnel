/**
 * src/utils/config.js
 * Auto-generated from _worker.js refactor
 * Original: edgetunnel 2.1 (2026-08-11)
 */
import { featureCodeDict } from '../constants.js';
import { socks5Whitelist } from '../state.js';
import { MD5MD5 } from './crypto.js';
import { getXHTTPPaddingIdentifiers } from '../handlers/xhttp.js';
import { log, parseToArray, randomPath } from './helpers.js';
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


export async function logRequest(
	env,
	request,
	accessIP,
	requestType = 'Get_SUB',
	config_JSON,
	writeKVLog = true
) {
	try {
		const currentTime = new Date();
		const logEntry = {
			TYPE: requestType,
			IP: accessIP,
			ASN: `AS${request.cf.asn || '0'} ${request.cf.asOrganization || 'Unknown'}`,
			CC: `${request.cf.country || 'N/A'} ${request.cf.city || 'N/A'}`,
			URL: request.url,
			UA: request.headers.get('User-Agent') || 'Unknown',
			TIME: currentTime.getTime(),
		};
		if (config_JSON.TG.enable) {
			try {
				const TG_TXT = await env.KV.get('tg.json');
				const TG_JSON = JSON.parse(TG_TXT);
				if (TG_JSON?.BotToken && TG_JSON?.ChatID) {
					const requestTime =
						new Date(logEntry.TIME).toISOString().replace('T', ' ').slice(0, 19) +
						' UTC';
					const requestURL = new URL(logEntry.URL);
					const msg =
						`<b>#${config_JSON.optSubGenerator.SUBNAME} Log Notification</b>\n\n` +
						`📌 <b>Type:</b> #${logEntry.TYPE}\n` +
						`🌐 <b>IP:</b> <code>${logEntry.IP}</code>\n` +
						`📍 <b>Location:</b> ${logEntry.CC}\n` +
						`🏢 <b>ASN:</b> ${logEntry.ASN}\n` +
						`🔗 <b>Domain:</b> <code>${requestURL.host}</code>\n` +
						`🔍 <b>Path:</b> <code>${requestURL.pathname + requestURL.search}</code>\n` +
						`🤖 <b>User-Agent:</b> <code>${logEntry.UA}</code>\n` +
						`📅 <b>Time:</b> ${requestTime}\n` +
						`${config_JSON.CF.Usage.success ? `📊 <b>Requests:</b> ${config_JSON.CF.Usage.total}/${config_JSON.CF.Usage.max} <b>${((config_JSON.CF.Usage.total / config_JSON.CF.Usage.max) * 100).toFixed(2)}%</b>\n` : ''}`;
					await fetch(
						`https://api.telegram.org/bot${TG_JSON.BotToken}/sendMessage?chat_id=${TG_JSON.ChatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`,
						{
							method: 'GET',
							headers: {
								Accept: 'text/html,application/xhtml+xml,application/xml;',
								'Accept-Encoding': 'gzip, deflate, br',
								'User-Agent': logEntry.UA || 'Unknown',
							},
						}
					);
				}
			} catch (error) {
				console.error(`readtg.jsonerror: ${error.message}`);
			}
		}
		writeKVLog = ['1', 'true'].includes(env.OFF_LOG) ? false : writeKVLog;
		if (!writeKVLog) return;
		let logArray = [];
		const existingLogs = await env.KV.get('log.json'),
			KVcapacityLimit = 4; //MB
		if (existingLogs) {
			try {
				logArray = JSON.parse(existingLogs);
				if (!Array.isArray(logArray)) {
					logArray = [logEntry];
				} else if (requestType !== 'Get_SUB') {
					const thirtyMinAgoTimestamp = currentTime.getTime() - 30 * 60 * 1000;
					if (
						logArray.some(
							(log) =>
								log.TYPE !== 'Get_SUB' &&
								log.IP === accessIP &&
								log.URL === request.url &&
								log.UA === (request.headers.get('User-Agent') || 'Unknown') &&
								log.TIME >= thirtyMinAgoTimestamp
						)
					)
						return;
					logArray.push(logEntry);
					while (
						JSON.stringify(logArray, null, 2).length > KVcapacityLimit * 1024 * 1024 &&
						logArray.length > 0
					)
						logArray.shift();
				} else {
					logArray.push(logEntry);
					while (
						JSON.stringify(logArray, null, 2).length > KVcapacityLimit * 1024 * 1024 &&
						logArray.length > 0
					)
						logArray.shift();
				}
			} catch {
				logArray = [logEntry];
			}
		} else {
			logArray = [logEntry];
		}
		await env.KV.put('log.json', JSON.stringify(logArray, null, 2));
	} catch (error) {
		console.error(`log recording failed: ${error.message}`);
	}
}

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
	const _p = featureCodeDict[0];
	const host = hostname,
		Ali_DoH = 'https://dns.alidns.com/dns-query',
		ECH_SNI = 'cloudflare-ech.com',
		placeholder = '{{IP:PORT}}',
		initStartTime = performance.now(),
		defaultConfigJSON = {
			TIME: new Date().toISOString(),
			HOST: host,
			HOSTS: [hostname],
			UUID: userID,
			PATH: '/',
			protocolType: 'v' + 'le' + 'ss',
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
				local: true, // true: local-basedOptimalAddress  false: optimalSubscriptionGenerator
				localIPDB: {
					randomIP: true, // whenRandomIPIs true, enableRandomIPCount, otherwiseUseKVADD.txt
					randomCount: 16,
					specifiedPort: -1,
				},
				SUB: null,
				SUBNAME: 'edge' + 'tunnel',
				SUBUpdateTime: 3, // subscriptionUpdateTime（hours）
				TOKEN: await MD5MD5(hostname + userID),
			},
			subConverterConfig: {
				SUBAPI: `https://SUBAPI.${featureCodeDict[1]}ssss.net`,
				SUBCONFIG: `https://raw.githubusercontent.com/${featureCodeDict[1]}/ACL4SSR/refs/heads/main/Clash/config/ACL4SSR_Online_Mini_MultiMode_CF.ini`,
				SUBEMOJI: false,
				SUBLIST: false, //outputNodeInfoOnly
				UDP: false, // enableUDP
				XUDP: false, // enableXUDP
				TLS13: false, // enableTLS1.3
				APPEND_TYPE: false, // insertNodeType
				SORT: false, // basicNodeSorting
			},
			proxy: {
				[_p]: 'auto',
				SOCKS5: {
					enable: null,
					global: false,
					account: '',
					whitelist: socks5Whitelist,
				},
				pathTemplate: {
					[_p]: 'proxyip=' + placeholder,
					SOCKS5: {
						global: 'socks5://' + placeholder,
						standard: 'socks5=' + placeholder,
					},
					HTTP: {
						global: 'http://' + placeholder,
						standard: 'http=' + placeholder,
					},
					HTTPS: {
						global: 'https://' + placeholder,
						standard: 'https=' + placeholder,
					},
					TURN: {
						global: 'turn://' + placeholder,
						standard: 'turn=' + placeholder,
					},
					SSTP: {
						global: 'sstp://' + placeholder,
						standard: 'sstp=' + placeholder,
					},
				},
			},
			TG: {
				enable: false,
				BotToken: null,
				ChatID: null,
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

	try {
		const configJSON = await env.KV.get('config.json');
		if (!configJSON || resetConfig == true) {
			await env.KV.put('config.json', JSON.stringify(defaultConfigJSON, null, 2));
			config_JSON = defaultConfigJSON;
		} else {
			config_JSON = JSON.parse(configJSON);
		}
	} catch (error) {
		console.error(`readConfigJSONerror: ${error.message}`);
		config_JSON = defaultConfigJSON;
	}

	if (!config_JSON.optSubGenerator) {
		config_JSON.optSubGenerator =
			config_JSON.optimalSubscriptionGeneration || defaultConfigJSON.optSubGenerator;
	}
	if (!config_JSON.subConverterConfig) {
		config_JSON.subConverterConfig =
			config_JSON.subscriptionConversionconfig || defaultConfigJSON.subConverterConfig;
	}
	if (!config_JSON.proxy) config_JSON.proxy = defaultConfigJSON.proxy;
	if (!config_JSON.proxy.pathTemplate)
		config_JSON.proxy.pathTemplate = defaultConfigJSON.proxy.pathTemplate;
	if (!config_JSON.proxy.SOCKS5) config_JSON.proxy.SOCKS5 = defaultConfigJSON.proxy.SOCKS5;
	if (!config_JSON.TG) config_JSON.TG = defaultConfigJSON.TG;
	if (!config_JSON.CF) config_JSON.CF = defaultConfigJSON.CF;

	if (!config_JSON.subConverterConfig.SUBLIST) config_JSON.subConverterConfig.SUBLIST = false;
	if (!config_JSON.subConverterConfig.UDP) config_JSON.subConverterConfig.UDP = false;
	if (!config_JSON.subConverterConfig.XUDP) config_JSON.subConverterConfig.XUDP = false;
	if (!config_JSON.subConverterConfig.TLS13) config_JSON.subConverterConfig.TLS13 = false;
	if (!config_JSON.subConverterConfig.APPEND_TYPE)
		config_JSON.subConverterConfig.APPEND_TYPE = false;
	if (!config_JSON.subConverterConfig.SORT) config_JSON.subConverterConfig.SORT = false;
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

	if (!config_JSON.proxy.pathTemplate?.[_p]) {
		config_JSON.proxy.pathTemplate = {
			[_p]: 'proxyip=' + placeholder,
			SOCKS5: {
				global: 'socks5://' + placeholder,
				standard: 'socks5=' + placeholder,
			},
			HTTP: {
				global: 'http://' + placeholder,
				standard: 'http=' + placeholder,
			},
			HTTPS: {
				global: 'https://' + placeholder,
				standard: 'https=' + placeholder,
			},
			TURN: {
				global: 'turn://' + placeholder,
				standard: 'turn=' + placeholder,
			},
			SSTP: {
				global: 'sstp://' + placeholder,
				standard: 'sstp=' + placeholder,
			},
		};
	}
	if (!config_JSON.proxy.pathTemplate.HTTPS)
		config_JSON.proxy.pathTemplate.HTTPS = {
			global: 'https://' + placeholder,
			standard: 'https=' + placeholder,
		};
	if (!config_JSON.proxy.pathTemplate.TURN)
		config_JSON.proxy.pathTemplate.TURN = {
			global: 'turn://' + placeholder,
			standard: 'turn=' + placeholder,
		};
	if (!config_JSON.proxy.pathTemplate.SSTP)
		config_JSON.proxy.pathTemplate.SSTP = {
			global: 'sstp://' + placeholder,
			standard: 'sstp=' + placeholder,
		};

	const proxyConfig =
		config_JSON.proxy.pathTemplate[config_JSON.proxy.SOCKS5.enable?.toUpperCase()];

	let pathProxyParam = '';
	if (proxyConfig && config_JSON.proxy.SOCKS5.account)
		pathProxyParam = (
			config_JSON.proxy.SOCKS5.global ? proxyConfig.global : proxyConfig.standard
		).replace(placeholder, config_JSON.proxy.SOCKS5.account);
	else if (config_JSON.proxy[_p] !== 'auto')
		pathProxyParam = config_JSON.proxy.pathTemplate[_p].replace(
			placeholder,
			config_JSON.proxy[_p]
		);

	let proxyQueryParam = '';
	if (pathProxyParam.includes('?')) {
		const [proxyPathPart, proxyQueryPart] = pathProxyParam.split('?');
		pathProxyParam = proxyPathPart;
		proxyQueryParam = proxyQueryPart;
	}

	config_JSON.PATH = config_JSON.PATH.replace(pathProxyParam, '').replace('//', '/');
	const normalizedPath =
		config_JSON.PATH === '/'
			? ''
			: config_JSON.PATH.replace(/\/+(?=\?|$)/, '').replace(/\/+$/, '');
	const [pathPart, ...queryArray] = normalizedPath.split('?');
	const queryPart = queryArray.length ? '?' + queryArray.join('?') : '';
	const finalQueryPart = proxyQueryParam
		? queryPart
			? queryPart + '&' + proxyQueryParam
			: '?' + proxyQueryParam
		: queryPart;
	config_JSON.fullNodePath =
		(pathPart || '/') +
		(pathPart && pathProxyParam ? '/' : '') +
		pathProxyParam +
		finalQueryPart +
		(config_JSON.enable0RTT ? (finalQueryPart ? '&' : '?') + 'ed=2560' : '');

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
	config_JSON.LINK =
		config_JSON.protocolType === 'ss'
			? `${config_JSON.protocolType}://${btoa(config_JSON.SS.cipherMethod + ':' + userID)}@${host}:${config_JSON.SS.TLS ? '443' : '80'}?plugin=v2${encodeURIComponent(`ray-plugin;mode=websocket;host=${host};path=${(config_JSON.fullNodePath.includes('?') ? config_JSON.fullNodePath.replace('?', '?enc=' + config_JSON.SS.cipherMethod + '&') : config_JSON.fullNodePath + '?enc=' + config_JSON.SS.cipherMethod) + (config_JSON.SS.TLS ? ';tls' : '')};mux=0`) + echLinkParam}#${encodeURIComponent(config_JSON.optSubGenerator.SUBNAME)}`
			: config_JSON.protocolType === 'vmess'
				? generateVMessLink({
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
						ps: config_JSON.optSubGenerator.SUBNAME,
					})
				: `${config_JSON.protocolType}://${userID}@${host}:443?security=tls&type=${transportProtocol + echLinkParam}&${domainFieldName}=${host}&fp=${config_JSON.Fingerprint}&sni=${host}&${pathFieldName}=${encodeURIComponent(transportPathParamValue) + tlsFragmentParam}&encryption=none#${encodeURIComponent(config_JSON.optSubGenerator.SUBNAME)}`;
	config_JSON.optSubGenerator.TOKEN = await MD5MD5(hostname + userID);

	const initTG_JSON = { BotToken: null, ChatID: null };
	config_JSON.TG = {
		enable: config_JSON.TG.enable ? config_JSON.TG.enable : false,
		...initTG_JSON,
	};
	try {
		const TG_TXT = await env.KV.get('tg.json');
		if (!TG_TXT) {
			await env.KV.put('tg.json', JSON.stringify(initTG_JSON, null, 2));
		} else {
			const TG_JSON = JSON.parse(TG_TXT);
			config_JSON.TG.ChatID = TG_JSON.ChatID ? TG_JSON.ChatID : null;
			config_JSON.TG.BotToken = TG_JSON.BotToken ? maskSensitiveInfo(TG_JSON.BotToken) : null;
		}
	} catch (error) {
		console.error(`readtg.jsonerror: ${error.message}`);
	}

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
	try {
		const CF_TXT = await env.KV.get('cf.json');
		if (!CF_TXT) {
			await env.KV.put('cf.json', JSON.stringify(initCF_JSON, null, 2));
		} else {
			const CF_JSON = JSON.parse(CF_TXT);
			if (CF_JSON.UsageAPI) {
				try {
					const response = await fetch(CF_JSON.UsageAPI);
					const Usage = await response.json();
					config_JSON.CF.Usage = Usage;
				} catch (err) {
					console.error(`request CF_JSON.UsageAPI failed: ${err.message}`);
				}
			} else {
				config_JSON.CF.Email = CF_JSON.Email ? CF_JSON.Email : null;
				config_JSON.CF.GlobalAPIKey = CF_JSON.GlobalAPIKey
					? maskSensitiveInfo(CF_JSON.GlobalAPIKey)
					: null;
				config_JSON.CF.AccountID = CF_JSON.AccountID
					? maskSensitiveInfo(CF_JSON.AccountID)
					: null;
				config_JSON.CF.APIToken = CF_JSON.APIToken
					? maskSensitiveInfo(CF_JSON.APIToken)
					: null;
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
	} catch (error) {
		console.error(`readcf.jsonerror: ${error.message}`);
	}

	config_JSON.loadTime = (performance.now() - initStartTime).toFixed(2) + 'ms';

	if (config_JSON.optSubGenerator) {
		config_JSON.optSubGenerator.localIPDB = config_JSON.optSubGenerator.localIPDB || {
			randomIP: true,
			randomCount: 16,
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
