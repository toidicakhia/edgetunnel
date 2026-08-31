/**
 * src/router.js
 * Auto-generated from _worker.js refactor
 * Original: edgetunnel 2.1 (2026-08-11)
 */
import { Version, featureCodeDict } from './constants.js';
import {
	PROXY_CONCURRENT_DIAL_COUNT,
	TCP_CONCURRENT_DIAL_COUNT,
	config_JSON,
	debugLogging,
	preloadRaceDial,
	setConfigJSON,
	setDebugLogging,
	setPreloadRaceDial,
	setProxyConcurrentDialCount,
	setTCPConcurrentDialCount,
} from './state.js';
import { MD5MD5 } from './utils/crypto.js';
import {
	clashSubscriptionHotPatch,
	getCloudflareUsage,
	getTransportPathParamValue,
	getTransportProtocolConfig,
	logRequest,
	readConfigJSON,
	singboxSubscriptionHotPatch,
} from './utils/config.js';
import {
	log,
	parseToArray,
	randomPath,
	replaceWildcardWithRandomChars,
} from './utils/helpers.js';
import { getProxyParams } from './core/proxy.js';
import { fetchOptimalAPI, fetchOptimalSubGeneratorData, generateRandomIPs } from './utils/doh.js';
import { getXHTTPPaddingIdentifiers, handleXHTTPRequest } from './handlers/xhttp.js';
import { handleGRPCRequest } from './handlers/grpc.js';
import { handleWSRequest } from './handlers/ws.js';
import { generateVMessLink } from './core/vmess.js';
import { html1101, nginx } from './html/camouflage.js';
import { loginPage } from './html/login.js';
import { noAdminPage, noKVPage } from './html/errorPages.js';
import { adminPage } from './html/admin.js';
import { identifyISP } from './utils/network.js';

export default {
	async fetch(request, env, ctx) {
		let requestURLText = request.url.replace(/%5[Cc]/g, '').replace(/\\/g, '');
		const requestURLAnchorIndex = requestURLText.indexOf('#');
		const requestURLMainPart =
			requestURLAnchorIndex === -1
				? requestURLText
				: requestURLText.slice(0, requestURLAnchorIndex);
		if (!requestURLMainPart.includes('?') && /%3f/i.test(requestURLMainPart)) {
			const requestURLAnchorPart =
				requestURLAnchorIndex === -1 ? '' : requestURLText.slice(requestURLAnchorIndex);
			requestURLText = requestURLMainPart.replace(/%3f/i, '?') + requestURLAnchorPart;
		}
		const url = new URL(requestURLText);
		const UA = request.headers.get('User-Agent') || 'null';
		const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase(),
			contentType = (request.headers.get('content-type') || '').toLowerCase();
		const adminPassword =
			env.ADMIN ||
			env.admin ||
			env.PASSWORD ||
			env.password ||
			env.pswd ||
			env.TOKEN ||
			env.KEY ||
			env.UUID ||
			env.uuid;
		const encryptionSecret = env.KEY || 'Do not modify this default secret key';
		const userIDMD5 = await MD5MD5(adminPassword + encryptionSecret);
		const uuidRegex =
			/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
		const envUUID = env.UUID || env.uuid;
		const userID =
			envUUID && uuidRegex.test(envUUID)
				? envUUID.toLowerCase()
				: [
						userIDMD5.slice(0, 8),
						userIDMD5.slice(8, 12),
						'4' + userIDMD5.slice(13, 16),
						'8' + userIDMD5.slice(17, 20),
						userIDMD5.slice(20),
					].join('-');
		const hosts = env.HOST
			? (await parseToArray(env.HOST)).map(
					(h) =>
						h
							.toLowerCase()
							.replace(/^https?:\/\//, '')
							.split('/')[0]
							.split(':')[0]
				)
			: [url.hostname];
		const host = hosts[0];
		const accessPath = url.pathname.slice(1).toLowerCase();
		setDebugLogging(['1', 'true'].includes(env.DEBUG) || debugLogging);
		setPreloadRaceDial(['1', 'true'].includes(env.PRELOAD_RACE_DIAL) || preloadRaceDial);
		setProxyConcurrentDialCount(
			Math.max(1, Number(env.PROXY_CONCURRENT_DIAL) || PROXY_CONCURRENT_DIAL_COUNT)
		);
		setTCPConcurrentDialCount(
			Math.max(1, Number(env.TCP_CONCURRENT_DIAL) || TCP_CONCURRENT_DIAL_COUNT)
		);
		if (
			!env.TCP_CONCURRENT_DIAL &&
			TCP_CONCURRENT_DIAL_COUNT !== 1 &&
			identifyISP(request) === 'cmcc'
		)
			setTCPConcurrentDialCount(1);
		let defaultProxyIP =
				`${request.cf?.colo || 'sjc'}.${featureCodeDict[0]}.${featureCodeDict[1]}SsSs.nEt`.toLowerCase(),
			defaultProxyFallback = true;
		if (env.PROXYIP) {
			const proxyIPs = await parseToArray(env.PROXYIP);
			defaultProxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
			defaultProxyFallback = false;
		}
		const accessIP =
			request.headers.get('CF-Connecting-IP') ||
			request.headers.get('True-Client-IP') ||
			request.headers.get('X-Real-IP') ||
			request.headers.get('X-Forwarded-For') ||
			request.headers.get('Fly-Client-IP') ||
			request.headers.get('X-Appengine-Remote-Addr') ||
			request.headers.get('X-Cluster-Client-IP') ||
			'unknownIP';
		if (accessPath === 'version') {
			// versionAPI
			const requestUUID = (url.searchParams.get('uuid') || '').toLowerCase();
			if (uuidRegex.test(requestUUID)) {
				const targetUUID = String(userID).toLowerCase();
				let requestFirst8Sum = 0,
					targetFirst8Sum = 0;
				for (let i = 0; i < 8; i++) {
					const requestCode = requestUUID.charCodeAt(i);
					requestFirst8Sum += requestCode <= 57 ? requestCode - 48 : requestCode - 87;
					const targetCode = targetUUID.charCodeAt(i);
					targetFirst8Sum += targetCode <= 57 ? targetCode - 48 : targetCode - 87;
				}
				if (
					requestFirst8Sum === targetFirst8Sum &&
					requestUUID.slice(-12) === targetUUID.slice(-12)
				)
					return new Response(
						JSON.stringify({ Version: Number(String(Version).replace(/\D+/g, '')) }),
						{
							status: 200,
							headers: { 'Content-Type': 'application/json;charset=utf-8' },
						}
					);
			}
		} else if (adminPassword && upgradeHeader === 'websocket') {
			// WebSocketproxy
			const proxyContext = await getProxyParams(
				url,
				userID,
				defaultProxyIP,
				defaultProxyFallback
			);
			log(`[WebSocket] Matched request: ${url.pathname}${url.search}`);
			return await handleWSRequest(request, userID, url, proxyContext);
		} else if (
			adminPassword &&
			!accessPath.startsWith('admin/') &&
			accessPath !== 'login' &&
			request.method === 'POST'
		) {
			// gRPC/XHTTPproxy
			const proxyContext = await getProxyParams(
				url,
				userID,
				defaultProxyIP,
				defaultProxyFallback
			);
			const { head: localPaddingHeader, key: localPaddingKey } =
				getXHTTPPaddingIdentifiers(userID);
			const matchedXHTTPFeature =
				!!request.headers.get(localPaddingHeader) ||
				!!url.searchParams.get(localPaddingKey);
			if (!matchedXHTTPFeature && contentType.startsWith('application/grpc')) {
				log(`[gRPC] Matched request: ${url.pathname}${url.search}`);
				return await handleGRPCRequest(request, userID, proxyContext);
			}
			log(`[XHTTP] Matched request: ${url.pathname}${url.search}`);
			return await handleXHTTPRequest(request, userID, proxyContext);
		} else {
			if (url.protocol === 'http:')
				return Response.redirect(
					url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`),
					301
				);
			if (!adminPassword)
				return new Response(noAdminPage(), {
					status: 404,
					headers: {
						'Content-Type': 'text/html; charset=UTF-8',
						'Cache-Control': 'no-store, no-cache, must-revalidate',
					},
				});
			if (env.KV && typeof env.KV.get === 'function') {
				const caseSensitiveAccessPath = url.pathname.slice(1);
				if (
					caseSensitiveAccessPath === encryptionSecret &&
					encryptionSecret !== 'Do not modify this default secret key'
				) {
					//quickSubscription
					const params = new URLSearchParams(url.search);
					params.set('token', await MD5MD5(host + userID));
					return new Response('Redirecting...', {
						status: 302,
						headers: { Location: `/sub?${params.toString()}` },
					});
				} else if (accessPath === 'login') {
					//handleLoginPageAndLoginRequest
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies
						.split(';')
						.find((c) => c.trim().startsWith('auth='))
						?.split('=')[1];
					if (authCookie == (await MD5MD5(UA + encryptionSecret + adminPassword)))
						return new Response('Redirecting...', {
							status: 302,
							headers: { Location: '/admin' },
						});
					if (request.method === 'POST') {
						const formData = await request.text();
						const params = new URLSearchParams(formData);
						const inputPassword = params.get('password');
						if (
							inputPassword ===
							(typeof adminPassword === 'string'
								? adminPassword.replace(/[\r\n]/g, '')
								: adminPassword)
						) {
							// password correct, set cookie and return success
							const response = new Response(JSON.stringify({ success: true }), {
								status: 200,
								headers: { 'Content-Type': 'application/json;charset=utf-8' },
							});
							response.headers.set(
								'Set-Cookie',
								`auth=${await MD5MD5(UA + encryptionSecret + adminPassword)}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Lax`
							);
							return response;
						}
						return new Response(
							JSON.stringify({ success: false, error: 'Invalid password' }),
							{
								status: 401,
								headers: { 'Content-Type': 'application/json;charset=utf-8' },
							}
						);
					}
					return new Response(loginPage(), {
						status: 200,
						headers: {
							'Content-Type': 'text/html; charset=UTF-8',
							'Cache-Control': 'no-store, no-cache, must-revalidate',
						},
					});
				} else if (accessPath === 'admin' || accessPath.startsWith('admin/')) {
					//validatecookiethenRespondAdminPage
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies
						.split(';')
						.find((c) => c.trim().startsWith('auth='))
						?.split('=')[1];
					// no cookie or cookie error，redirect to/loginpage
					if (
						!authCookie ||
						authCookie !== (await MD5MD5(UA + encryptionSecret + adminPassword))
					)
						return new Response('Redirecting...', {
							status: 302,
							headers: { Location: '/login' },
						});
					if (accessPath === 'admin/log.json') {
						// logContent
						const logContent = (await env.KV.get('log.json')) || '[]';
						return new Response(logContent, {
							status: 200,
							headers: { 'Content-Type': 'application/json;charset=utf-8' },
						});
					} else if (caseSensitiveAccessPath === 'admin/getCloudflareUsage') {
						// queryUsage
						try {
							const Usage_JSON = await getCloudflareUsage(
								url.searchParams.get('Email'),
								url.searchParams.get('GlobalAPIKey'),
								url.searchParams.get('AccountID'),
								url.searchParams.get('APIToken')
							);
							return new Response(JSON.stringify(Usage_JSON, null, 2), {
								status: 200,
								headers: { 'Content-Type': 'application/json' },
							});
						} catch (err) {
							const errorResponse = {
								msg: 'Failed to query usage: ' + err.message,
								error: err.message,
							};
							return new Response(JSON.stringify(errorResponse, null, 2), {
								status: 500,
								headers: { 'Content-Type': 'application/json;charset=utf-8' },
							});
						}
					} else if (caseSensitiveAccessPath === 'admin/getADDAPI') {
						// validateOptimalAPI
						if (url.searchParams.get('url')) {
							const pendingVerifyOptimalURL = url.searchParams.get('url');
							try {
								new URL(pendingVerifyOptimalURL);
								const fetchOptimalAPIResult = await fetchOptimalAPI(
									[pendingVerifyOptimalURL],
									url.searchParams.get('port') || '443'
								);
								let optimalAPIIPs =
									fetchOptimalAPIResult[0].length > 0
										? fetchOptimalAPIResult[0]
										: fetchOptimalAPIResult[1];
								optimalAPIIPs = optimalAPIIPs.map((item) =>
									item.replace(
										/#(.+)$/,
										(_, remark) => '#' + decodeURIComponent(remark)
									)
								);
								return new Response(
									JSON.stringify({ success: true, data: optimalAPIIPs }, null, 2),
									{
										status: 200,
										headers: {
											'Content-Type': 'application/json;charset=utf-8',
										},
									}
								);
							} catch (err) {
								const errorResponse = {
									msg: 'validateOptimalAPI failed: ' + err.message,
									error: err.message,
								};
								return new Response(JSON.stringify(errorResponse, null, 2), {
									status: 500,
									headers: { 'Content-Type': 'application/json;charset=utf-8' },
								});
							}
						}
						return new Response(JSON.stringify({ success: false, data: [] }, null, 2), {
							status: 403,
							headers: { 'Content-Type': 'application/json;charset=utf-8' },
						});
					}
					setConfigJSON(await readConfigJSON(env, host, userID, UA));

					if (accessPath === 'admin/init') {
						try {
							setConfigJSON(await readConfigJSON(env, host, userID, UA, true));
							ctx.waitUntil(
								logRequest(env, request, accessIP, 'Init_Config', config_JSON)
							);
							config_JSON.init = 'Config reset to defaults';
							return new Response(JSON.stringify(config_JSON, null, 2), {
								status: 200,
								headers: { 'Content-Type': 'application/json;charset=utf-8' },
							});
						} catch (err) {
							const errorResponse = {
								msg: 'Config reset failed，failure reason：' + err.message,
								error: err.message,
							};
							return new Response(JSON.stringify(errorResponse, null, 2), {
								status: 500,
								headers: { 'Content-Type': 'application/json;charset=utf-8' },
							});
						}
					} else if (request.method === 'POST') {
						// processKVOperation（POSTRequest）
						if (accessPath === 'admin/config.json') {
							// saveconfig.jsonconfig
							try {
								const newConfig = await request.json();
								// validateConfigIntegrity
								if (!newConfig.UUID || !newConfig.HOST)
									return new Response(
										JSON.stringify({ error: 'Config incomplete' }),
										{
											status: 400,
											headers: {
												'Content-Type': 'application/json;charset=utf-8',
											},
										}
									);

								// save to KV
								await env.KV.put('config.json', JSON.stringify(newConfig, null, 2));
								ctx.waitUntil(
									logRequest(env, request, accessIP, 'Save_Config', config_JSON)
								);
								return new Response(
									JSON.stringify({ success: true, message: 'Config saved' }),
									{
										status: 200,
										headers: {
											'Content-Type': 'application/json;charset=utf-8',
										},
									}
								);
							} catch (error) {
								console.error('Failed to save config:', error);
								return new Response(
									JSON.stringify({
										error: 'Failed to save config: ' + error.message,
									}),
									{
										status: 500,
										headers: {
											'Content-Type': 'application/json;charset=utf-8',
										},
									}
								);
							}
						} else if (accessPath === 'admin/cf.json') {
							// savecf.jsonconfig
							try {
								const newConfig = await request.json();
								const CF_JSON = {
									Email: null,
									GlobalAPIKey: null,
									AccountID: null,
									APIToken: null,
									UsageAPI: null,
								};
								if (!newConfig.init || newConfig.init !== true) {
									if (newConfig.Email && newConfig.GlobalAPIKey) {
										CF_JSON.Email = newConfig.Email;
										CF_JSON.GlobalAPIKey = newConfig.GlobalAPIKey;
									} else if (newConfig.AccountID && newConfig.APIToken) {
										CF_JSON.AccountID = newConfig.AccountID;
										CF_JSON.APIToken = newConfig.APIToken;
									} else if (newConfig.UsageAPI) {
										CF_JSON.UsageAPI = newConfig.UsageAPI;
									} else {
										return new Response(
											JSON.stringify({ error: 'Config incomplete' }),
											{
												status: 400,
												headers: {
													'Content-Type':
														'application/json;charset=utf-8',
												},
											}
										);
									}
								}

								// save to KV
								await env.KV.put('cf.json', JSON.stringify(CF_JSON, null, 2));
								ctx.waitUntil(
									logRequest(env, request, accessIP, 'Save_Config', config_JSON)
								);
								return new Response(
									JSON.stringify({ success: true, message: 'Config saved' }),
									{
										status: 200,
										headers: {
											'Content-Type': 'application/json;charset=utf-8',
										},
									}
								);
							} catch (error) {
								console.error('Failed to save config:', error);
								return new Response(
									JSON.stringify({
										error: 'Failed to save config: ' + error.message,
									}),
									{
										status: 500,
										headers: {
											'Content-Type': 'application/json;charset=utf-8',
										},
									}
								);
							}
						} else if (caseSensitiveAccessPath === 'admin/ADD.txt') {
							// saveCustomoptimalIP
							try {
								const customIPs = await request.text();
								await env.KV.put('ADD.txt', customIPs); // saveToKV
								ctx.waitUntil(
									logRequest(
										env,
										request,
										accessIP,
										'Save_Custom_IPs',
										config_JSON
									)
								);
								return new Response(
									JSON.stringify({ success: true, message: 'Custom IPs saved' }),
									{
										status: 200,
										headers: {
											'Content-Type': 'application/json;charset=utf-8',
										},
									}
								);
							} catch (error) {
								console.error('save customIPfailed:', error);
								return new Response(
									JSON.stringify({
										error: 'save customIPfailed: ' + error.message,
									}),
									{
										status: 500,
										headers: {
											'Content-Type': 'application/json;charset=utf-8',
										},
									}
								);
							}
						} else
							return new Response(
								JSON.stringify({ error: 'Unsupported POST path' }),
								{
									status: 404,
									headers: { 'Content-Type': 'application/json;charset=utf-8' },
								}
							);
					} else if (accessPath === 'admin/config.json') {
						// processAdmin/config.jsonRequest，returnJSON
						return new Response(JSON.stringify(config_JSON, null, 2), {
							status: 200,
							headers: { 'Content-Type': 'application/json' },
						});
					} else if (caseSensitiveAccessPath === 'admin/ADD.txt') {
						// processAdmin/ADD.txtRequest，returnlocalOptimalIP
						let localOptimalIP = (await env.KV.get('ADD.txt')) || 'null';
						if (localOptimalIP == 'null')
							localOptimalIP = (
								await generateRandomIPs(
									request,
									config_JSON.optSubGenerator.localIPDB.randomCount,
									config_JSON.optSubGenerator.localIPDB.specifiedPort
								)
							)[1];
						return new Response(localOptimalIP, {
							status: 200,
							headers: {
								'Content-Type': 'text/plain;charset=utf-8',
								asn: request.cf?.asn || '0',
							},
						});
					} else if (accessPath === 'admin/cf.json') {
						// CFconfigfile
						return new Response(JSON.stringify(request.cf || {}, null, 2), {
							status: 200,
							headers: { 'Content-Type': 'application/json;charset=utf-8' },
						});
					}

					ctx.waitUntil(logRequest(env, request, accessIP, 'Admin_Login', config_JSON));
					return new Response(adminPage(), {
						status: 200,
						headers: {
							'Content-Type': 'text/html; charset=UTF-8',
							'Cache-Control': 'no-store, no-cache, must-revalidate',
						},
					});
				} else if (accessPath === 'logout' || uuidRegex.test(accessPath)) {
					//clearcookieandRedirectToLoginPage
					const response = new Response('Redirecting...', {
						status: 302,
						headers: { Location: '/login' },
					});
					response.headers.set('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly');
					return response;
				} else if (accessPath === 'sub') {
					//handleSubscriptionRequest
					const subscriptionTOKEN = await MD5MD5(host + userID),
						asOptimalSubGenerator =
							['1', 'true'].includes(env.BEST_SUB) &&
							url.searchParams.get('host') === 'example.com' &&
							url.searchParams.get('uuid') ===
								'00000000-0000-4000-8000-000000000000' &&
							UA.toLowerCase().includes(
								'tunnel (https://github.com/' + featureCodeDict[1] + '/edge'
							);
					const requestTOKEN = url.searchParams.get('token');
					const userClientRequestingSub = requestTOKEN === subscriptionTOKEN;
					if (userClientRequestingSub || asOptimalSubGenerator) {
						setConfigJSON(await readConfigJSON(env, host, userID, UA));
						if (asOptimalSubGenerator)
							ctx.waitUntil(
								logRequest(
									env,
									request,
									accessIP,
									'Get_Best_SUB',
									config_JSON,
									false
								)
							);
						else
							ctx.waitUntil(
								logRequest(env, request, accessIP, 'Get_SUB', config_JSON)
							);
						const ua = UA.toLowerCase();
						const responseHeaders = {
							'content-type': 'text/plain; charset=utf-8',
							'Profile-Update-Interval': config_JSON.optSubGenerator.SUBUpdateTime,
							'Profile-web-page-url': url.protocol + '//' + url.host + '/admin',
							'Cache-Control': 'no-store',
						};
						if (config_JSON.CF.Usage.success) {
							const pagesSum = config_JSON.CF.Usage.pages;
							const workersSum = config_JSON.CF.Usage.workers;
							const total = Number.isFinite(config_JSON.CF.Usage.max)
								? (config_JSON.CF.Usage.max / 1000) * 1024
								: 1024 * 100;
							responseHeaders['Subscription-Userinfo'] =
								`upload=${pagesSum}; download=${workersSum}; total=${total}; expire=4102329600`; // 2099-12-31ExpiryTime
						}
						const subscriptionType = url.searchParams.has('target')
								? url.searchParams.get('target')
								: url.searchParams.has('clash') ||
									  ua.includes('clash') ||
									  ua.includes('meta') ||
									  ua.includes('mihomo')
									? 'clash'
									: url.searchParams.has('sb') ||
										  url.searchParams.has('singbox') ||
										  ua.includes('singbox') ||
										  ua.includes('sing-box')
										? 'singbox'
										: url.searchParams.has('surge') || ua.includes('surge')
											? 'surge&ver=4'
											: url.searchParams.has('quanx') ||
												  ua.includes('quantumult')
												? 'quanx'
												: url.searchParams.has('loon') ||
													  ua.includes('loon')
													? 'loon'
													: 'mixed';

						if (!ua.includes('mozilla'))
							responseHeaders['Content-Disposition'] =
								`attachment; filename*=utf-8''${encodeURIComponent(config_JSON.optSubGenerator.SUBNAME)}`;
						const protocolType =
							(url.searchParams.has('surge') || ua.includes('surge')) &&
							config_JSON.protocolType !== 'ss' &&
							config_JSON.protocolType !== 'vmess'
								? 'tro' + 'jan'
								: config_JSON.protocolType;
						let subscriptionContent = '';
						if (subscriptionType === 'mixed') {
							const tlsFragmentParam =
								config_JSON.TLSFragment == 'Shadowrocket'
									? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}`
									: config_JSON.TLSFragment == 'Happ'
										? `&fragment=${encodeURIComponent('3,1,tlshello')}`
										: '';
							let fullOptimalIPs = [],
								otherNodesLINK = '',
								proxyIPPool = [];

							if (!url.searchParams.has('sub') && config_JSON.optSubGenerator.local) {
								// localSubscriptionGeneration
								const fullOptimalList = config_JSON.optSubGenerator.localIPDB
									.randomIP
									? (
											await generateRandomIPs(
												request,
												config_JSON.optSubGenerator.localIPDB.randomCount,
												config_JSON.optSubGenerator.localIPDB.specifiedPort
											)
										)[0]
									: (await env.KV.get('ADD.txt'))
										? await parseToArray(await env.KV.get('ADD.txt'))
										: (
												await generateRandomIPs(
													request,
													config_JSON.optSubGenerator.localIPDB
														.randomCount,
													config_JSON.optSubGenerator.localIPDB
														.specifiedPort
												)
											)[0];
								const optimalAPI = [],
									optimalIP = [],
									otherNodes = [];
								for (const element of fullOptimalList) {
									if (element.toLowerCase().startsWith('sub://')) {
										optimalAPI.push(element);
									} else {
										const remarkPosition = element.indexOf('#');
										const addressPart =
											remarkPosition > -1
												? element.slice(0, remarkPosition)
												: element;
										const remarkPart =
											remarkPosition > -1
												? element.slice(remarkPosition)
												: '';
										const subMatch = element.match(/sub\s*=\s*([^\s&#]+)/i);
										if (subMatch && subMatch[1].trim().includes('.')) {
											const optimalIPAsProxyIP = element
												.toLowerCase()
												.includes('proxyip=true');
											if (optimalIPAsProxyIP)
												optimalAPI.push(
													'sub://' +
														subMatch[1].trim() +
														'?proxyip=true' +
														(element.includes('#')
															? '#' + element.split('#')[1]
															: '')
												);
											else
												optimalAPI.push(
													'sub://' +
														subMatch[1].trim() +
														(element.includes('#')
															? '#' + element.split('#')[1]
															: '')
												);
										} else if (
											addressPart.toLowerCase().startsWith('https://')
										) {
											optimalAPI.push(element);
										} else if (addressPart.toLowerCase().includes('://')) {
											if (element.includes('#')) {
												const addressRemarkSplit = element.split('#');
												otherNodes.push(
													addressRemarkSplit[0] +
														'#' +
														encodeURIComponent(
															decodeURIComponent(
																addressRemarkSplit[1]
															)
														)
												);
											} else otherNodes.push(element);
										} else {
											if (addressPart.includes('*')) {
												optimalIP.push(
													replaceWildcardWithRandomChars(addressPart) +
														remarkPart
												);
											} else optimalIP.push(element);
										}
									}
								}
								const fetchOptimalAPIResult = await fetchOptimalAPI(
									optimalAPI,
									'443'
								);
								const mergedOtherNodeArray = [
									...new Set(otherNodes.concat(fetchOptimalAPIResult[1])),
								];
								otherNodesLINK =
									mergedOtherNodeArray.length > 0
										? mergedOtherNodeArray.join('\n') + '\n'
										: '';
								const optimalAPIIPs = fetchOptimalAPIResult[0];
								proxyIPPool = fetchOptimalAPIResult[2] || [];
								fullOptimalIPs = [...new Set(optimalIP.concat(optimalAPIIPs))];
							} else {
								// optimalSubscriptionGenerator
								const optSubGeneratorHOST =
									url.searchParams.get('sub') || config_JSON.optSubGenerator.SUB;
								const [optGeneratorIPArray, optGeneratorOtherNodes] =
									await fetchOptimalSubGeneratorData(optSubGeneratorHOST);
								fullOptimalIPs = fullOptimalIPs.concat(optGeneratorIPArray);
								otherNodesLINK += optGeneratorOtherNodes;
							}
							const echLinkParam = config_JSON.ECH
								? `&ech=${encodeURIComponent((config_JSON.ECHConfig.SNI ? config_JSON.ECHConfig.SNI + '+' : '') + config_JSON.ECHConfig.DNS)}`
								: '';
							const isLoonOrSurge = ua.includes('loon') || ua.includes('surge');
							const {
								type: transportProtocol,
								pathFieldName,
								domainFieldName,
							} = getTransportProtocolConfig(config_JSON);
							subscriptionContent =
								otherNodesLINK +
								fullOptimalIPs
									.map((rawAddress) => {
										// unified regex: match domain/IPv4/IPv6address + optional port + optionalremark
										// example:
										//   - domain: hj.xmm1993.top:2096#remark or example.com
										//   - IPv4: 166.0.188.128:443#Los Angeles or 166.0.188.128
										//   - IPv6: [2606:4700::]:443#CMCC or [2606:4700::]
										const regex =
											/^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
										const match = rawAddress.match(regex);

										let nodeAddress,
											nodePort = '443',
											nodeRemark;

										if (match) {
											nodeAddress = match[1]; // IPaddressOrDomain(mayHaveBrackets)
											nodePort = match[2] ? match[2] : '443'; // portDefault443，SSNoTLSmappedWhenGeneratingLink
											nodeRemark = match[3] || nodeAddress; // remark,default toAddressItself
										} else {
											// invalid format，skip processing returnnull
											console.warn(
												`[subscriptionContent] Invalid IP format ignored: ${rawAddress}`
											);
											return null;
										}

										let fullNodePath = config_JSON.fullNodePath;

										if (proxyIPPool.length > 0) {
										} else if (proxyIPPool.length > 0) {
											const matchedProxyIP = proxyIPPool.find((p) =>
												p.includes(nodeAddress)
											);
											if (matchedProxyIP)
												fullNodePath =
													`${config_JSON.PATH}/proxyip=${matchedProxyIP}`.replace(
														/\/\//g,
														'/'
													) + (config_JSON.enable0RTT ? '?ed=2560' : '');
										}
										if (isLoonOrSurge)
											fullNodePath = fullNodePath.replace(/,/g, '%2C');

										if (protocolType === 'vmess' && !asOptimalSubGenerator) {
											// VMess link: vmess://<base64(json)>
											const transportPathParamValue =
												getTransportPathParamValue(
													config_JSON,
													fullNodePath,
													asOptimalSubGenerator
												);
											// Map internal transport to VMess net field
											let vmessNet = 'ws';
											let vmessPath = transportPathParamValue;
											let vmessHost = 'example.com';
											if (config_JSON.transportProtocol === 'grpc') {
												vmessNet = 'grpc';
												vmessPath = transportPathParamValue;
												vmessHost = 'example.com';
											} else if (config_JSON.transportProtocol === 'xhttp') {
												// XHTTP not standard for VMess, fallback to ws with xhttp path
												vmessNet = 'ws';
												vmessPath = transportPathParamValue;
											}
											// Determine TLS based on port
											const tlsPorts = [443, 2053, 2083, 2087, 2096, 8443];
											const isNodeTLS = tlsPorts.includes(Number(nodePort));
											const vmessTLS = isNodeTLS ? 'tls' : '';
											const vmessSNI = isNodeTLS ? 'example.com' : '';
											const vmessFP = isNodeTLS ? (config_JSON.Fingerprint || 'chrome') : '';
											const vmessLink = generateVMessLink({
												host: nodeAddress,
												port: nodePort,
												uuid: '00000000-0000-4000-8000-000000000000',
												security: 'auto',
												net: vmessNet,
												path: vmessPath,
												hostHeader: vmessHost,
												tls: vmessTLS,
												sni: vmessSNI,
												fp: vmessFP,
												ps: nodeRemark,
											});
											// For VMess, we need to add ECH and fragment as well? VMess json doesn't support them directly,
											// but we can append as extra params in the JSON's path if needed. For now, handle ECH via vmess link's sni.
											return vmessLink;
										} else if (
											protocolType === 'ss' &&
											!asOptimalSubGenerator
										) {
											if (!config_JSON.SS.TLS) {
												const tlsPorts = [
													443, 2053, 2083, 2087, 2096, 8443,
												];
												const nonTLSPorts = [
													80, 2052, 2082, 2086, 2095, 8080,
												];
												nodePort = String(
													nonTLSPorts[
														tlsPorts.indexOf(Number(nodePort))
													] ?? nodePort
												);
											}
											fullNodePath = (
												fullNodePath.includes('?')
													? fullNodePath.replace(
															'?',
															'?enc=' +
																config_JSON.SS.cipherMethod +
																'&'
														)
													: fullNodePath +
														'?enc=' +
														config_JSON.SS.cipherMethod
										).replace(/([=,])/g, '\\$1');
										fullNodePath = fullNodePath + ';mux=0';
										return `${protocolType}://${btoa(config_JSON.SS.cipherMethod + ':00000000-0000-4000-8000-000000000000')}@${nodeAddress}:${nodePort}?plugin=v2${encodeURIComponent('ray-plugin;mode=websocket;host=example.com;path=' + (config_JSON.randomPath ? randomPath(fullNodePath) : fullNodePath) + (config_JSON.SS.TLS ? ';tls' : '')) + echLinkParam + tlsFragmentParam}#${encodeURIComponent(nodeRemark)}`;
										} else {
											const transportPathParamValue =
												getTransportPathParamValue(
													config_JSON,
													fullNodePath,
													asOptimalSubGenerator
												);
											return `${protocolType}://00000000-0000-4000-8000-000000000000@${nodeAddress}:${nodePort}?security=tls&type=${transportProtocol + echLinkParam}&${domainFieldName}=example.com&fp=${config_JSON.Fingerprint}&sni=example.com&${pathFieldName}=${encodeURIComponent(transportPathParamValue) + tlsFragmentParam}&encryption=none#${encodeURIComponent(nodeRemark)}`;
										}
									})
									.filter((item) => item !== null)
									.join('\n');
						}

						if (userClientRequestingSub) {
							const shuffledHOSTS = [...config_JSON.HOSTS].sort(
								() => Math.random() - 0.5
							);
							let replaceHostCount = 0,
								currentRandomHost = null;
							subscriptionContent = subscriptionContent
								.replace(/00000000-0000-4000-8000-000000000000/g, config_JSON.UUID)
								.replace(
									/MDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAw/g,
									btoa(config_JSON.UUID)
								)
								.replace(/example\.com/g, () => {
									if (replaceHostCount % 2 === 0) {
										const originalHost =
											shuffledHOSTS[
												Math.floor(replaceHostCount / 2) %
													shuffledHOSTS.length
											];
										currentRandomHost =
											replaceWildcardWithRandomChars(originalHost);
									}
									replaceHostCount++;
									return currentRandomHost;
								});
							// Handle VMess links where id/host/sni are inside base64 JSON
							if (
								protocolType === 'vmess' &&
								subscriptionContent.includes('vmess://')
							) {
								// For VMess, each link's JSON contains id, host, sni, path etc. The previous replaces didn't affect base64.
								// We need to decode each vmess:// line, replace, and re-encode.
								// Use a separate counter for VMess hosts to keep rotation consistent with VLESS
								let vmessHostIdx = 0;
								subscriptionContent = subscriptionContent
									.split('\n')
									.map((line) => {
										if (!line.startsWith('vmess://')) return line;
										try {
											const b64 = line.slice(8).trim();
											const jsonStr = atob(b64);
											const vmess = JSON.parse(jsonStr);
											// Replace id
											if (vmess.id === '00000000-0000-4000-8000-000000000000')
												vmess.id = config_JSON.UUID;
											// Replace host/sni/add if they are example.com (or contain it)
											// For VMess, add is the optimal IP, not example.com, so we only replace host/sni
											// But to keep host rotation consistent, we pick a host for this VMess node
											const originalHost =
												shuffledHOSTS[vmessHostIdx % shuffledHOSTS.length];
											const currentHost =
												replaceWildcardWithRandomChars(originalHost);
											vmessHostIdx++;
											if (vmess.host === 'example.com')
												vmess.host = currentHost;
											if (vmess.sni === 'example.com')
												vmess.sni = vmess.tls === 'tls' ? currentHost : '';
											// Also handle ps if needed? No, ps is remark
											// Re-encode
											return 'vmess://' + btoa(JSON.stringify(vmess));
										} catch {
											return line;
										}
									})
									.join('\n');
							}
						}

						if (
							subscriptionType === 'mixed' &&
							(!ua.includes('mozilla') ||
								url.searchParams.has('b64') ||
								url.searchParams.has('base64'))
						)
							subscriptionContent = btoa(subscriptionContent);

						if (subscriptionType === 'singbox') {
							subscriptionContent = await singboxSubscriptionHotPatch(
								subscriptionContent,
								config_JSON
							);
							responseHeaders['content-type'] = 'application/json; charset=utf-8';
						} else if (subscriptionType === 'clash') {
							subscriptionContent = clashSubscriptionHotPatch(
								subscriptionContent,
								config_JSON
							);
							responseHeaders['content-type'] = 'application/x-yaml; charset=utf-8';
						}
						return new Response(subscriptionContent, {
							status: 200,
							headers: responseHeaders,
						});
					}
				} else if (accessPath === 'locations') {
					//proxylocationslist
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies
						.split(';')
						.find((c) => c.trim().startsWith('auth='))
						?.split('=')[1];
					if (
						authCookie &&
						authCookie == (await MD5MD5(UA + encryptionSecret + adminPassword))
					)
						return fetch(
							new Request('https://speed.cloudflare.com/locations', {
								headers: { Referer: 'https://speed.cloudflare.com/' },
							})
						);
				} else if (accessPath === 'robots.txt')
					return new Response('User-agent: *\nDisallow: /', {
						status: 200,
						headers: { 'Content-Type': 'text/plain; charset=UTF-8' },
					});
			} else if (!envUUID)
				return new Response(noKVPage(), {
					status: 404,
					headers: {
						'Content-Type': 'text/html; charset=UTF-8',
						'Cache-Control': 'no-store, no-cache, must-revalidate',
					},
				});
		}

		let camouflagePageURL = env.URL || 'nginx';
		if (camouflagePageURL && camouflagePageURL !== 'nginx' && camouflagePageURL !== '1101') {
			camouflagePageURL = camouflagePageURL.trim().replace(/\/$/, '');
			if (!camouflagePageURL.match(/^https?:\/\//i))
				camouflagePageURL = 'https://' + camouflagePageURL;
			if (camouflagePageURL.toLowerCase().startsWith('http://'))
				camouflagePageURL = 'https://' + camouflagePageURL.substring(7);
			try {
				const u = new URL(camouflagePageURL);
				camouflagePageURL = u.protocol + '//' + u.host;
			} catch {
				camouflagePageURL = 'nginx';
			}
		}
		if (camouflagePageURL === '1101')
			return new Response(await html1101(url.host, accessIP), {
				status: 200,
				headers: { 'Content-Type': 'text/html; charset=UTF-8' },
			});
		try {
			const proxyURL = new URL(camouflagePageURL),
				newRequestHeaders = new Headers(request.headers);
			newRequestHeaders.set('Host', proxyURL.host);
			newRequestHeaders.set('Referer', proxyURL.origin);
			newRequestHeaders.set('Origin', proxyURL.origin);
			if (!newRequestHeaders.has('User-Agent') && UA && UA !== 'null')
				newRequestHeaders.set('User-Agent', UA);
			const proxyResponse = await fetch(proxyURL.origin + url.pathname + url.search, {
				method: request.method,
				headers: newRequestHeaders,
				body: request.body,
				cf: request.cf,
			});
			const contentType = proxyResponse.headers.get('content-type') || '';
			// text onlytyperesponse of
			if (/text|javascript|json|xml/.test(contentType)) {
				const responseContent = (await proxyResponse.text()).replaceAll(
					proxyURL.host,
					url.host
				);
				return new Response(responseContent, {
					status: proxyResponse.status,
					headers: {
						...Object.fromEntries(proxyResponse.headers),
						'Cache-Control': 'no-store',
					},
				});
			}
			return proxyResponse;
		} catch {}
		return new Response(await nginx(), {
			status: 200,
			headers: { 'Content-Type': 'text/html; charset=UTF-8' },
		});
	},
};
///////////////////////////////////////////////////////////////////////XHTTP transport data///////////////////////////////////////////////
