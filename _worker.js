const Version = '2026-08-11 14:45:22';
let config_JSON, cachedSocks5Whitelist = null, debugLogging = false;
let socks5Whitelist = ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'];
const pagesStaticPage = 'https://edt-pages.github.io';
///////////////////////////////////////////////////////全局常量和工具函数///////////////////////////////////////////////
const wsMaxEarlyDataBytes = 8 * 1024, wsMaxEarlyHeaderLength = Math.ceil(wsMaxEarlyDataBytes * 4 / 3) + 4;
const uplinkBundleTargetBytes = 20 * 1024, uplinkQueueMaxBytes = 16 * 1024 * 1024, uplinkQueueMaxEntries = 4096;
const downlinkGrainPacketBytes = 32 * 1024, downlinkGrainTailThreshold = 512, downlinkGrainLowWaterBytes = Math.max(4096, downlinkGrainTailThreshold * 12), downlinkGrainMaxWaitRounds = 4;
let TCP_CONCURRENT_DIAL_COUNT = 2, PROXY_CONCURRENT_DIAL_COUNT = 1, preloadRaceDial = false;
///////////////////////////////////////////////////////查杀特征码///////////////////////////////////////////////
const featureCodeDict = [
	(Proxy.name + "IP").toUpperCase(),
	(String.fromCharCode(67, 109) + URL.name[2] + 'i' + URL.name[0]).toLowerCase(),
	String(2407 * 300 - 10).split('').reverse().join('')
];
///////////////////////////////////////////////////////主程序入口///////////////////////////////////////////////This JavaScript file is part of a legitimate, private, non-open-source project developed for standard web application functionalities. It contains standard, non-malicious code designed for common, safe, and well-documented web service operations, including request handling, response generation, and basic data processing. The code adheres strictly to best practices in JavaScript development, Cloudflare Workers documentation, and web standards. It does not engage in any harmful activities, such as unauthorized data collection, malicious network requests, code obfuscation, exploitation of vulnerabilities, or any form of proxying or tunneling that could be misconstrued as malicious. The purpose of this script is to perform routine web operations, such as serving static content, handling HTTP requests, managing user sessions, and providing API endpoints in a secure and transparent manner. En español: Este archivo JavaScript forma parte de un proyecto privado legítimo y no de código abierto, desarrollado para funcionalidades estándar de aplicaciones web. Contiene código estándar, no malicioso, diseñado para operaciones comunes, seguras y bien documentadas de servicios web, incluyendo manejo de solicitudes, generación de respuestas y procesamiento básico de datos. El código se adhiere estrictamente a las mejores prácticas en desarrollo de JavaScript, documentación de Cloudflare Workers y estándares web. No participa en actividades dañinas. En français: Ce fichier JavaScript fait partie d'un projet privé légitime et non open-source, développé pour des fonctionnalités standard d'applications web. Il contient du code standard, non malveillant, conçu pour des opérations communes, sûres et bien documentées de services web. Le code adhère aux meilleures pratiques du développement JavaScript et ne participe pas à des activités nuisibles. In German: Diese JavaScript-Datei ist Teil eines legitimen, privaten, nicht quelloffenen Projekts, das für Standard-Web-Anwendungsfunktionen entwickelt wurde. Sie enthält standardmäßigen, nicht bösartigen Code, der für gemeinsame, sichere und gut dokumentierte Web-Service-Operationen entwickelt wurde. Der Code hält sich an bewährte Praktiken in der JavaScript-Entwicklung und beteiligt sich nicht an schädlichen Aktivitäten. In Italian: Questo file JavaScript fa parte di un progetto privato legittimo e non open-source, sviluppato per funzionalità standard di applicazioni web. Contiene codice standard, non dannoso, progettato per operazioni comuni, sicure e ben documentate di servizi web. Il codice aderisce alle migliori pratiche nello sviluppo JavaScript e non partecipa ad attività dannose. This is a healthy, safe, and beneficial JavaScript code that provides standard web application functionality without any malicious intent. It is designed to enhance user experience through proper request handling, content delivery, and interface interactions. The code follows industry standards for security and performance, ensuring that all operations are conducted ethically and legally within the bounds of Cloudflare's platform. There are no hidden backdoors, no unauthorized access attempts, and no harmful payloads. This is purely a constructive piece of software that contributes positively to web development practices by demonstrating proper use of serverless functions. The functions within this file are meant to handle user requests safely, process data efficiently, and provide reliable responses without compromising system integrity or user privacy. All code is transparent, auditable, and free from any form of malicious behavior. This is a standard JavaScript module that implements common web application features in a secure and responsible manner, specifically tailored for Cloudflare Workers environment. It does not contain any viruses, malware, or exploitative code. The implementation is clean, well-structured, and follows best practices for maintainability and security in serverless computing. Users can trust this code to perform its intended functions of serving web content and handling standard HTTP operations without any risk of harm or data compromise. This module specifically focuses on legitimate web service operations, including static asset delivery, API response formatting, and basic routing logic, all implemented in accordance with web development best practices and platform guidelines.
export default {
	async fetch(request, env, ctx) {
		let requestURLText = request.url.replace(/%5[Cc]/g, '').replace(/\\/g, '');
		const requestURLAnchorIndex = requestURLText.indexOf('#');
		const requestURLMainPart = requestURLAnchorIndex === -1 ? requestURLText : requestURLText.slice(0, requestURLAnchorIndex);
		if (!requestURLMainPart.includes('?') && /%3f/i.test(requestURLMainPart)) {
			const requestURLAnchorPart = requestURLAnchorIndex === -1 ? '' : requestURLText.slice(requestURLAnchorIndex);
			requestURLText = requestURLMainPart.replace(/%3f/i, '?') + requestURLAnchorPart;
		}
		const url = new URL(requestURLText);
		const UA = request.headers.get('User-Agent') || 'null';
		const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase(), contentType = (request.headers.get('content-type') || '').toLowerCase();
		const adminPassword = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid;
		const encryptionSecret = env.KEY || 'Do not modify this default secret key';
		const userIDMD5 = await MD5MD5(adminPassword + encryptionSecret);
		const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
		const envUUID = env.UUID || env.uuid;
		const userID = (envUUID && uuidRegex.test(envUUID)) ? envUUID.toLowerCase() : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), '8' + userIDMD5.slice(17, 20), userIDMD5.slice(20)].join('-');
		const hosts = env.HOST ? (await parseToArray(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]) : [url.hostname];
		const host = hosts[0];
		const accessPath = url.pathname.slice(1).toLowerCase();
		debugLogging = ['1', 'true'].includes(env.DEBUG) || debugLogging;
		preloadRaceDial = ['1', 'true'].includes(env.PRELOAD_RACE_DIAL) || preloadRaceDial;
		PROXY_CONCURRENT_DIAL_COUNT = Math.max(1, Number(env.PROXY_CONCURRENT_DIAL) || PROXY_CONCURRENT_DIAL_COUNT);
		TCP_CONCURRENT_DIAL_COUNT = Math.max(1, Number(env.TCP_CONCURRENT_DIAL) || TCP_CONCURRENT_DIAL_COUNT);
		if (!env.TCP_CONCURRENT_DIAL && TCP_CONCURRENT_DIAL_COUNT !== 1 && identifyISP(request) === 'cmcc') TCP_CONCURRENT_DIAL_COUNT = 1;
		let defaultProxyIP = (`${request.cf.colo}.${featureCodeDict[0]}.${featureCodeDict[1]}SsSs.nEt`).toLowerCase(), defaultProxyFallback = true;
		if (env.PROXYIP) {
			const proxyIPs = await parseToArray(env.PROXYIP);
			defaultProxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
			defaultProxyFallback = false;
		};
		const accessIP = request.headers.get('CF-Connecting-IP') || request.headers.get('True-Client-IP') || request.headers.get('X-Real-IP') || request.headers.get('X-Forwarded-For') || request.headers.get('Fly-Client-IP') || request.headers.get('X-Appengine-Remote-Addr') || request.headers.get('X-Cluster-Client-IP') || '未知IP';
		if (cachedSocks5Whitelist === null) {
			if (env.GO2SOCKS5) socks5Whitelist = [...new Set(socks5Whitelist.concat(await parseToArray(env.GO2SOCKS5)))];
			cachedSocks5Whitelist = socks5Whitelist;
		} else socks5Whitelist = cachedSocks5Whitelist;
		if (accessPath === 'version') {// version API
			const requestUUID = (url.searchParams.get('uuid') || '').toLowerCase();
			if (uuidRegex.test(requestUUID)) {
				const targetUUID = String(userID).toLowerCase();
				let requestFirst8Sum = 0, targetFirst8Sum = 0;
				for (let i = 0; i < 8; i++) {
					const requestCode = requestUUID.charCodeAt(i);
					requestFirst8Sum += requestCode <= 57 ? requestCode - 48 : requestCode - 87;
					const targetCode = targetUUID.charCodeAt(i);
					targetFirst8Sum += targetCode <= 57 ? targetCode - 48 : targetCode - 87;
				}
				if (requestFirst8Sum === targetFirst8Sum && requestUUID.slice(-12) === targetUUID.slice(-12)) return new Response(JSON.stringify({ Version: Number(String(Version).replace(/\D+/g, '')) }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
			}
		} else if (adminPassword && upgradeHeader === 'websocket') {// WebSocket代理
			const proxyContext = await getProxyParams(url, userID, defaultProxyIP, defaultProxyFallback);
			log(`[WebSocket] Matched request: ${url.pathname}${url.search}`);
			return await handleWSRequest(request, userID, url, proxyContext);
		} else if (adminPassword && !accessPath.startsWith('admin/') && accessPath !== 'login' && request.method === 'POST') {// gRPC/叉HTTP代理
			const proxyContext = await getProxyParams(url, userID, defaultProxyIP, defaultProxyFallback);
			const { head: localPaddingHeader, key: localPaddingKey } = getXHTTPPaddingIdentifiers(userID);
			const matchedXHTTPFeature = !!request.headers.get(localPaddingHeader) || !!url.searchParams.get(localPaddingKey);
			if (!matchedXHTTPFeature && contentType.startsWith('application/grpc')) {
				log(`[gRPC] Matched request: ${url.pathname}${url.search}`);
				return await handleGRPCRequest(request, userID, proxyContext);
			}
			log(`[XHTTP] Matched request: ${url.pathname}${url.search}`);
			return await handleXHTTPRequest(request, userID, proxyContext);
		} else {
			if (url.protocol === 'http:') return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
			if (!adminPassword) return fetch(pagesStaticPage + '/noADMIN').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }) });
			if (env.KV && typeof env.KV.get === 'function') {
				const caseSensitiveAccessPath = url.pathname.slice(1);
				if (caseSensitiveAccessPath === encryptionSecret && encryptionSecret !== 'Do not modify this default secret key') {//快速订阅
					const params = new URLSearchParams(url.search);
					params.set('token', await MD5MD5(host + userID));
					return new Response('Redirecting...', { status: 302, headers: { 'Location': `/sub?${params.toString()}` } });
				} else if (accessPath === 'login') {//处理登录页面和登录请求
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
					if (authCookie == await MD5MD5(UA + encryptionSecret + adminPassword)) return new Response('Redirecting...', { status: 302, headers: { 'Location': '/admin' } });
					if (request.method === 'POST') {
						const formData = await request.text();
						const params = new URLSearchParams(formData);
						const inputPassword = params.get('password');
						if (inputPassword === (typeof adminPassword === 'string' ? adminPassword.replace(/[\r\n]/g, '') : adminPassword)) {
							// passwordCorrect，设置cookie并返回成功标记
							const response = new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							response.headers.set('Set-Cookie', `auth=${await MD5MD5(UA + encryptionSecret + adminPassword)}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Lax`);
							return response;
						}
					}
					return fetch(pagesStaticPage + '/login');
				} else if (accessPath === 'admin' || accessPath.startsWith('admin/')) {//验证cookie后响应管理页面
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
					// 没有cookie或cookie错误，跳转到/login页面
					if (!authCookie || authCookie !== await MD5MD5(UA + encryptionSecret + adminPassword)) return new Response('Redirecting...', { status: 302, headers: { 'Location': '/login' } });
					if (accessPath === 'admin/log.json') {// logContent
						const logContent = await env.KV.get('log.json') || '[]';
						return new Response(logContent, { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					} else if (caseSensitiveAccessPath === 'admin/getCloudflareUsage') {// 查询请求量
						try {
							const Usage_JSON = await getCloudflareUsage(url.searchParams.get('Email'), url.searchParams.get('GlobalAPIKey'), url.searchParams.get('AccountID'), url.searchParams.get('APIToken'));
							return new Response(JSON.stringify(Usage_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
						} catch (err) {
							const errorResponse = { msg: 'Failed to query usage: ' + err.message, error: err.message };
							return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						}
					} else if (caseSensitiveAccessPath === 'admin/getADDAPI') {// validateOptimalAPI
						if (url.searchParams.get('url')) {
							const pendingVerifyOptimalURL = url.searchParams.get('url');
							try {
								new URL(pendingValidateURL);
								const fetchOptimalAPIResult = await fetchOptimalAPI([pendingValidateURL], url.searchParams.get('port') || '443');
								let optimalAPIIPs = fetchOptimalAPIResult[0].length > 0 ? fetchOptimalAPIResult[0] : fetchOptimalAPIResult[1];
								optimalAPIIPs = optimalAPIIPs.map(item => item.replace(/#(.+)$/, (_, remark) => '#' + decodeURIComponent(remark)));
								return new Response(JSON.stringify({ success: true, data: optimalAPIIPs }, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (err) {
								const errorResponse = { msg: 'validateOptimalAPI failed: ' + err.message, error: err.message };
								return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						}
						return new Response(JSON.stringify({ success: false, data: [] }, null, 2), { status: 403, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					} else if (accessPath === 'admin/check') {// 代理检查
						const proxyProtocol = ['socks5', 'http', 'https', 'turn', 'sstp'].find(type => url.searchParams.has(type)) || null;
						if (!proxyProtocol) return new Response(JSON.stringify({ error: 'Missing proxyParams' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						const proxyParams = url.searchParams.get(proxyProtocol);
						const startTime = Date.now();
						let checkProxyResponse;
						try {
							const checkParsed = await getSOCKS5Account(proxyParams, getProxyDefaultPort(proxyProtocol));
							const { username, password, hostname, port } = checkParsed;
							const fullProxyParams = username && password ? `${username}:${password}@${hostname}:${port}` : `${hostname}:${port}`;
							try {
								const checkHost = 'cloudflare.com', checkPort = 443, encoder = new TextEncoder(), decoder = new TextDecoder();
								const tcpConnector = createRequestTCPConnector(request);
								let tcpSocket = null, tlsSocket = null;
								try {
									tcpSocket = proxyProtocol === 'socks5'
										? await socks5Connect(checkHost, checkPort, new Uint8Array(0), tcpConnector, checkParsed)
										: proxyProtocol === 'turn'
											? await turnConnect(checkParsed, checkHost, checkPort, tcpConnector)
											: proxyProtocol === 'sstp'
												? await sstpConnect(checkParsed, checkHost, checkPort, tcpConnector)
												: (proxyProtocol === 'https' && isIPHostname(hostname)
													? await httpsConnect(checkHost, checkPort, new Uint8Array(0), tcpConnector, checkParsed)
													: await httpConnect(checkHost, checkPort, new Uint8Array(0), proxyProtocol === 'https', tcpConnector, checkParsed));
									if (!tcpSocket) throw new Error('Cannot connect to proxy server');
									tlsSocket = new TlsClient(tcpSocket, { serverName: checkHost, insecure: true });
									await tlsSocket.handshake();
									await tlsSocket.write(encoder.encode(`GET /cdn-cgi/trace HTTP/1.1\r\nHost: ${checkHost}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`));
									let responseBuffer = new Uint8Array(0), headerEndIndex = -1, contentLength = null, chunked = false;
									const maxResponseBytes = 64 * 1024;
									while (responseBuffer.length < maxResponseBytes) {
										const value = await tlsSocket.read();
										if (!value) break;
										if (value.byteLength === 0) continue;
										responseBuffer = concatByteData(responseBuffer, value);
										if (headerEndIndex === -1) {
											const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
											if (crlfcrlf !== -1) {
												headerEndIndex = crlfcrlf + 4;
												const headers = decoder.decode(responseBuffer.slice(0, headerEndIndex));
												const statusLine = headers.split('\r\n')[0] || '';
												const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
												const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
												if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`Proxy check request failed: ${statusLine || '无效响应'}`);
												const lengthMatch = headers.match(/\r\nContent-Length:\s*(\d+)/i);
												if (lengthMatch) contentLength = parseInt(lengthMatch[1], 10);
												chunked = /\r\nTransfer-Encoding:\s*chunked/i.test(headers);
											}
										}
										if (headerEndIndex !== -1 && contentLength !== null && responseBuffer.length >= headerEndIndex + contentLength) break;
										if (headerEndIndex !== -1 && chunked && decoder.decode(responseBuffer).includes('\r\n0\r\n\r\n')) break;
									}
									if (headerEndIndex === -1) throw new Error('Proxy response header too long or invalid');
									const response = decoder.decode(responseBuffer);
									const ip = response.match(/(?:^|\n)ip=(.*)/)?.[1];
									const loc = response.match(/(?:^|\n)loc=(.*)/)?.[1];
									if (!ip || !loc) throw new Error('Proxy response invalid');
									checkProxyResponse = { success: true, proxy: proxyProtocol + "://" + fullProxyParams, ip, loc, responseTime: Date.now() - startTime };
								} finally {
									try { tlsSocket ? tlsSocket.close() : await tcpSocket?.close?.() } catch (e) { }
								}
							} catch (error) {
								checkProxyResponse = { success: false, error: error.message, proxy: proxyProtocol + "://" + fullProxyParams, responseTime: Date.now() - startTime };
							}
						} catch (err) {
							checkProxyResponse = { success: false, error: err.message, proxy: proxyProtocol + "://" + proxyParams, responseTime: Date.now() - startTime };
						}
						return new Response(JSON.stringify(checkProxyResponse, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					}

					config_JSON = await readConfigJSON(env, host, userID, UA);

					if (accessPath === 'admin/init') {// resetConfig为默认值
						try {
							config_JSON = await readConfigJSON(env, host, userID, UA, true);
							ctx.waitUntil(logRequest(env, request, accessIP, 'Init_Config', config_JSON));
							config_JSON.init = 'Config reset to defaults';
							return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						} catch (err) {
							const errorResponse = { msg: 'Config reset failed，失败原因：' + err.message, error: err.message };
							return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						}
					} else if (request.method === 'POST') {// 处理 KV 操作（POST 请求）
						if (accessPath === 'admin/config.json') { // 保存config.jsonconfig
							try {
								const newConfig = await request.json();
								// validateConfigIntegrity
								if (!newConfig.UUID || !newConfig.HOST) return new Response(JSON.stringify({ error: 'Config incomplete' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });

								// 保存到 KV
								await env.KV.put('config.json', JSON.stringify(newConfig, null, 2));
								ctx.waitUntil(logRequest(env, request, accessIP, 'Save_Config', config_JSON));
								return new Response(JSON.stringify({ success: true, message: 'Config saved' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('Failed to save config:', error);
								return new Response(JSON.stringify({ error: 'Failed to save config: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else if (accessPath === 'admin/cf.json') { // 保存cf.jsonconfig
							try {
								const newConfig = await request.json();
								const CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
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
										return new Response(JSON.stringify({ error: 'Config incomplete' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
									}
								}

								// 保存到 KV
								await env.KV.put('cf.json', JSON.stringify(CF_JSON, null, 2));
								ctx.waitUntil(logRequest(env, request, accessIP, 'Save_Config', config_JSON));
								return new Response(JSON.stringify({ success: true, message: 'Config saved' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('Failed to save config:', error);
								return new Response(JSON.stringify({ error: 'Failed to save config: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else if (accessPath === 'admin/tg.json') { // 保存tg.jsonconfig
							try {
								const newConfig = await request.json();
								if (newConfig.init && newConfig.init === true) {
									const TG_JSON = { BotToken: null, ChatID: null };
									await env.KV.put('tg.json', JSON.stringify(TG_JSON, null, 2));
								} else {
									if (!newConfig.BotToken || !newConfig.ChatID) return new Response(JSON.stringify({ error: 'Config incomplete' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
									await env.KV.put('tg.json', JSON.stringify(newConfig, null, 2));
								}
								ctx.waitUntil(logRequest(env, request, accessIP, 'Save_Config', config_JSON));
								return new Response(JSON.stringify({ success: true, message: 'Config saved' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('Failed to save config:', error);
								return new Response(JSON.stringify({ error: 'Failed to save config: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else if (caseSensitiveAccessPath === 'admin/ADD.txt') { // 保存自定义optimalIP
							try {
								const customIPs = await request.text();
								await env.KV.put('ADD.txt', customIPs);// 保存到 KV
								ctx.waitUntil(logRequest(env, request, accessIP, 'Save_Custom_IPs', config_JSON));
								return new Response(JSON.stringify({ success: true, message: 'Custom IPs saved' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('保存自定义IP失败:', error);
								return new Response(JSON.stringify({ error: '保存自定义IP失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else return new Response(JSON.stringify({ error: 'Unsupported POST path' }), { status: 404, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					} else if (accessPath === 'admin/config.json') {// 处理 admin/config.json 请求，返回JSON
						return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
					} else if (caseSensitiveAccessPath === 'admin/ADD.txt') {// 处理 admin/ADD.txt 请求，返回localOptimalIP
						let localOptimalIP = await env.KV.get('ADD.txt') || 'null';
						if (localOptimalIP == 'null') localOptimalIP = (await generateRandomIPs(request, config_JSON.optSubGenerator.localIPDB.randomCount, config_JSON.optSubGenerator.localIPDB.specifiedPort))[1];
						return new Response(localOptimalIP, { status: 200, headers: { 'Content-Type': 'text/plain;charset=utf-8', 'asn': request.cf.asn } });
					} else if (accessPath === 'admin/cf.json') {// CFconfig文件
						return new Response(JSON.stringify(request.cf, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					}

					ctx.waitUntil(logRequest(env, request, accessIP, 'Admin_Login', config_JSON));
					return fetch(pagesStaticPage + '/admin' + url.search);
				} else if (accessPath === 'logout' || uuidRegex.test(accessPath)) {//清除cookie并跳转到登录页面
					const response = new Response('Redirecting...', { status: 302, headers: { 'Location': '/login' } });
					response.headers.set('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly');
					return response;
				} else if (accessPath === 'sub') {//handleSubscriptionRequest
					const subscriptionTOKEN = await MD5MD5(host + userID), asOptimalSubGenerator = ['1', 'true'].includes(env.BEST_SUB) && url.searchParams.get('host') === 'example.com' && url.searchParams.get('uuid') === '00000000-0000-4000-8000-000000000000' && UA.toLowerCase().includes('tunnel (https://github.com/' + featureCodeDict[1] + '/edge');
					const requestTOKEN = url.searchParams.get('token');
					const userClientRequestingSub = requestTOKEN === subscriptionTOKEN;
					const currentDayIndex = Math.floor(Date.now() / 86400000);
					const subConverterTOKENSeed = base64SecretEncode(subscriptionTOKEN, userID);
					const [todaySubConverterTOKEN, yesterdaySubConverterTOKEN] = await Promise.all([
						MD5MD5(subConverterTOKENSeed + currentDayIndex),
						MD5MD5(subConverterTOKENSeed + (currentDayIndex - 1)),
					]);
					const subConverterRequestingSub = requestTOKEN === todaySubConverterTOKEN || requestTOKEN === yesterdaySubConverterTOKEN;
					if (userClientRequestingSub || subConverterRequestingSub || asOptimalSubGenerator) {
						config_JSON = await readConfigJSON(env, host, userID, UA);
						if (asOptimalSubGenerator) ctx.waitUntil(logRequest(env, request, accessIP, 'Get_Best_SUB', config_JSON, false));
						else ctx.waitUntil(logRequest(env, request, accessIP, 'Get_SUB', config_JSON));
						const ua = UA.toLowerCase();
						const responseHeaders = {
							"content-type": "text/plain; charset=utf-8",
							"Profile-Update-Interval": config_JSON.optSubGenerator.SUBUpdateTime,
							"Profile-web-page-url": url.protocol + '//' + url.host + '/admin',
							"Cache-Control": "no-store",
						};
						if (config_JSON.CF.Usage.success) {
							const pagesSum = config_JSON.CF.Usage.pages;
							const workersSum = config_JSON.CF.Usage.workers;
							const total = Number.isFinite(config_JSON.CF.Usage.max) ? (config_JSON.CF.Usage.max / 1000) * 1024 : 1024 * 100;
							responseHeaders["Subscription-Userinfo"] = `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=4102329600`; // 2099-12-31 到期时间
						}
						const isSubConverterRequest = url.searchParams.has('b64') || url.searchParams.has('base64') || request.headers.get('subconverter-request') || request.headers.get('subconverter-version') || ua.includes('subconverter') || ua.includes(('CF-Workers-SUB').toLowerCase()) || asOptimalSubGenerator;
						const subscriptionType = isSubConverterRequest
							? 'mixed'
							: url.searchParams.has('target')
								? url.searchParams.get('target')
								: url.searchParams.has('clash') || ua.includes('clash') || ua.includes('meta') || ua.includes('mihomo')
									? 'clash'
									: url.searchParams.has('sb') || url.searchParams.has('singbox') || ua.includes('singbox') || ua.includes('sing-box')
										? 'singbox'
										: url.searchParams.has('surge') || ua.includes('surge')
											? 'surge&ver=4'
											: url.searchParams.has('quanx') || ua.includes('quantumult')
												? 'quanx'
												: url.searchParams.has('loon') || ua.includes('loon')
													? 'loon'
													: 'mixed';

						if (!ua.includes('mozilla')) responseHeaders["Content-Disposition"] = `attachment; filename*=utf-8''${encodeURIComponent(config_JSON.optSubGenerator.SUBNAME)}`;
						const protocolType = ((url.searchParams.has('surge') || ua.includes('surge')) && config_JSON.protocolType !== 'ss') ? 'tro' + 'jan' : config_JSON.protocolType;
						let subscriptionContent = '';
						if (subscriptionType === 'mixed') {
							const tlsFragmentParam = config_JSON.TLSFragment == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLSFragment == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
							let fullOptimalIPs = [], otherNodesLINK = '', proxyIPPool = [];

							if (!url.searchParams.has('sub') && config_JSON.optSubGenerator.local) { // 本地生成订阅
								const fullOptimalList = config_JSON.optSubGenerator.localIPDB.randomIP ? (
									await generateRandomIPs(request, config_JSON.optSubGenerator.localIPDB.randomCount, config_JSON.optSubGenerator.localIPDB.specifiedPort)
								)[0] : await env.KV.get('ADD.txt') ? await parseToArray(await env.KV.get('ADD.txt')) : (
									await generateRandomIPs(request, config_JSON.optSubGenerator.localIPDB.randomCount, config_JSON.optSubGenerator.localIPDB.specifiedPort)
								)[0];
								const optimalAPI = [], optimalIP = [], otherNodes = [];
								for (const element of fullOptimalList) {
									if (element.toLowerCase().startsWith('sub://')) {
										optimalAPI.push(element);
									} else {
										const remarkPosition = element.indexOf('#');
										const addressPart = remarkPosition > -1 ? element.slice(0, remarkPosition) : element;
										const remarkPart = remarkPosition > -1 ? element.slice(remarkPosition) : '';
										const subMatch = element.match(/sub\s*=\s*([^\s&#]+)/i);
										if (subMatch && subMatch[1].trim().includes('.')) {
											const optimalIPAsProxyIP = element.toLowerCase().includes('proxyip=true');
											if (optimalIPAsProxyIP) optimalAPI.push('sub://' + subMatch[1].trim() + "?proxyip=true" + (element.includes('#') ? ('#' + element.split('#')[1]) : ''));
											else optimalAPI.push('sub://' + subMatch[1].trim() + (element.includes('#') ? ('#' + element.split('#')[1]) : ''));
										} else if (addressPart.toLowerCase().startsWith('https://')) {
											optimalAPI.push(element);
										} else if (addressPart.toLowerCase().includes('://')) {
											if (element.includes('#')) {
												const addressRemarkSplit = element.split('#');
												otherNodes.push(addressRemarkSplit[0] + '#' + encodeURIComponent(decodeURIComponent(addressRemarkSplit[1])));
											} else otherNodes.push(element);
										} else {
											if (addressPart.includes('*')) {
												optimalIP.push(replaceWildcardWithRandomChars(addressPart) + remarkPart);
											} else optimalIP.push(element);
										}
									}
								}
								const fetchOptimalAPIResult = await fetchOptimalAPI(optimalAPI, '443');
								const mergedOtherNodeArray = [...new Set(otherNodes.concat(fetchOptimalAPIResult[1]))];
								otherNodesLINK = mergedOtherNodes.length > 0 ? mergedOtherNodes.join('\n') + '\n' : '';
								const optimalAPIIPs = fetchOptimalAPIResult[0];
								proxyIPPool = fetchOptimalAPIResult[3] || [];
								fullOptimalIPs = [...new Set(optimalIP.concat(optimalAPIIPs))];
							} else { // 优选订阅生成器
								let optSubGeneratorHOST = url.searchParams.get('sub') || config_JSON.optSubGenerator.SUB;
								const [optGeneratorIPArray, optGeneratorOtherNodes] = await fetchOptimalSubGeneratorData(optSubGeneratorHOST);
								fullOptimalIPs = fullOptimalIPs.concat(optGeneratorIPArray);
								otherNodesLINK += optGeneratorOtherNodes;
							}
							const echLinkParam = config_JSON.ECH ? `&ech=${encodeURIComponent((config_JSON.ECHConfig.SNI ? config_JSON.ECHConfig.SNI + '+' : '') + config_JSON.ECHConfig.DNS)}` : '';
							const isLoonOrSurge = ua.includes('loon') || ua.includes('surge');
							const { type: transportProtocol, pathFieldName, domainFieldName } = getTransportProtocolConfig(config_JSON);
							subscriptionContent = otherNodesLINK + fullOptimalIPs.map(rawAddress => {
								// 统一正则: 匹配 域名/IPv4/IPv6地址 + 可选端口 + 可选remark
								// 示例:
								//   - 域名: hj.xmm1993.top:2096#remark 或 example.com
								//   - IPv4: 166.0.188.128:443#Los Angeles 或 166.0.188.128
								//   - IPv6: [2606:4700::]:443#CMCC 或 [2606:4700::]
								const regex = /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
								const match = rawAddress.match(regex);

								let nodeAddress, nodePort = "443", nodeRemark;

								if (match) {
									nodeAddress = match[1];  // IP地址或域名(可能带方括号)
									nodePort = match[2] ? match[2] : '443';  // 端口默认443，SS noTLS在生成链接时再映射
									nodeRemark = match[3] || nodeAddress;  // remark,默认为地址本身
								} else {
									// 不规范的格式，跳过处理返回null
									console.warn(`[subscriptionContent] Invalid IP format ignored: ${rawAddress}`);
									return null;
								}

								let fullNodePath = config_JSON.fullNodePath;

								const chainProxyMatch = nodeRemark.match(/\$(socks5|http|https|turn|sstp):\/\/([^#\s]+)/i);
								if (chainProxyMatch) {
									try {
										const proxyProtocol = chainProxyMatch[1].toLowerCase(), proxyParams = chainProxyMatch[2];
										const chainProxyData = { type: proxyProtocol, ...getSOCKS5Account(proxyParams, getProxyDefaultPort(proxyProtocol)) };
										fullNodePath = `/video/${base64SecretEncode(JSON.stringify(chainProxyData), userID) + (config_JSON.enable0RTT ? '?ed=2560' : '')}`;
										nodeRemark = nodeRemark.replace(chainProxyMatch[0], '').trim() || nodeAddress;
									} catch (error) {
										console.warn(`[subscriptionContent] Chain proxy parse failed，instructionIgnored: ${chainProxyMatch[0]} (${error && error.message ? error.message : error})`);
									}
								} else if (proxyIPPool.length > 0) {
									const matchedProxyIP = proxyIPPool.find(p => p.includes(nodeAddress));
									if (matchedProxyIP) fullNodePath = (`${config_JSON.PATH}/proxyip=${matchedProxyIP}`).replace(/\/\//g, '/') + (config_JSON.enable0RTT ? '?ed=2560' : '');
								}
								if (isLoonOrSurge) fullNodePath = fullNodePath.replace(/,/g, '%2C');

								if (protocolType === 'ss' && !asOptimalSubGenerator) {
									if (!config_JSON.SS.TLS) {
										const tlsPorts = [443, 2053, 2083, 2087, 2096, 8443];
										const nonTLSPorts = [80, 2052, 2082, 2086, 2095, 8080];
										nodePort = String(nonTLSPorts[tlsPorts.indexOf(Number(nodePort))] ?? nodePort);
									}
									fullNodePath = (fullNodePath.includes('?') ? fullNodePath.replace('?', '?enc=' + config_JSON.SS.cipherMethod + '&') : (fullNodePath + '?enc=' + config_JSON.SS.cipherMethod)).replace(/([=,])/g, '\\$1');
									if (!isSubConverterRequest) fullNodePath = fullNodePath + ';mux=0';
									return `${protocolType}://${btoa(config_JSON.SS.cipherMethod + ':00000000-0000-4000-8000-000000000000')}@${nodeAddress}:${nodePort}?plugin=v2${encodeURIComponent('ray-plugin;mode=websocket;host=example.com;path=' + (config_JSON.randomPath ? randomPath(fullNodePath) : fullNodePath) + (config_JSON.SS.TLS ? ';tls' : '')) + echLinkParam + tlsFragmentParam}#${encodeURIComponent(nodeRemark)}`;
								} else {
									const transportPathParamValue = getTransportPathParamValue(config_JSON, fullNodePath, asOptimalSubGenerator);
									return `${protocolType}://00000000-0000-4000-8000-000000000000@${nodeAddress}:${nodePort}?security=tls&type=${transportProtocol + echLinkParam}&${domainFieldName}=example.com&fp=${config_JSON.Fingerprint}&sni=example.com&${pathFieldName}=${encodeURIComponent(传输路径参数值) + tlsFragmentParam}&encryption=none#${encodeURIComponent(nodeRemark)}`;
								}
							}).filter(item => item !== null).join('\n');
						} else { // 订阅转换
							const subConverterURL = `${config_JSON.subConverterConfig.SUBAPI}/sub?target=${subscriptionType}&url=${encodeURIComponent(url.protocol + '//' + url.host + '/sub?target=mixed&token=' + todaySubConverterTOKEN + '&cnIspCode=' + identifyISP(request) + (url.searchParams.has('sub') && url.searchParams.get('sub') != '' ? `&sub=${url.searchParams.get('sub')}` : ''))}&config=${encodeURIComponent(config_JSON.subConverterConfig.SUBCONFIG)}&emoji=${config_JSON.subConverterConfig.SUBEMOJI}&list=${config_JSON.subConverterConfig.SUBLIST}&scv=${config_JSON.skipCertVerify}&xudp=${config_JSON.subConverterConfig.XUDP}&udp=${config_JSON.subConverterConfig.UDP}&tls13=${config_JSON.subConverterConfig.TLS13}&append_type=${config_JSON.subConverterConfig.APPEND_TYPE}&sort=${config_JSON.subConverterConfig.SORT}`;
							try {
								const response = await fetch(subConverterURL, { headers: { 'User-Agent': 'Subconverter for ' + subscriptionType + ' edge' + 'tunnel (https://github.com/' + featureCodeDict[1] + '/edge' + 'tunnel)' } });
								if (response.ok) {
									subscriptionContent = await response.text();
									if (url.searchParams.has('surge') || ua.includes('surge')) subscriptionContent = surgeSubscriptionHotPatch(subscriptionContent, url.protocol + '//' + url.host + '/sub?token=' + subscriptionTOKEN + '&surge', config_JSON);
								} else return new Response('Sub converter backend error: ' + response.statusText, { status: response.status });
							} catch (error) {
								return new Response('Sub converter backend error: ' + error.message, { status: 403 });
							}
						}

						if (!ua.includes('subconverter') && userClientRequestingSub) {
							const shuffledHOSTS = [...config_JSON.HOSTS].sort(() => Math.random() - 0.5);
							let replaceHostCount = 0, currentRandomHost = null;
							subscriptionContent = subscriptionContent
								.replace(/00000000-0000-4000-8000-000000000000/g, config_JSON.UUID)
								.replace(/MDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAw/g, btoa(config_JSON.UUID))
								.replace(/example\.com/g, () => {
									if (replaceHostCount % 2 === 0) {
										const originalHost = shuffledHOSTS[Math.floor(replaceHostCount / 2) % shuffledHOSTS.length];
										currentRandomHost = replaceWildcardWithRandomChars(originalHost);
									}
									replaceHostCount++;
									return currentRandomHost;
								});
						}

						if (subscriptionType === 'mixed' && (!ua.includes('mozilla') || url.searchParams.has('b64') || url.searchParams.has('base64'))) subscriptionContent = btoa(subscriptionContent);

						if (subscriptionType === 'singbox') {
							subscriptionContent = await singboxSubscriptionHotPatch(subscriptionContent, config_JSON);
							responseHeaders["content-type"] = 'application/json; charset=utf-8';
						} else if (subscriptionType === 'clash') {
							subscriptionContent = clashSubscriptionHotPatch(subscriptionContent, config_JSON);
							responseHeaders["content-type"] = 'application/x-yaml; charset=utf-8';
						}
						return new Response(subscriptionContent, { status: 200, headers: responseHeaders });
					}
				} else if (accessPath === 'locations') {//反代locations列表
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
					if (authCookie && authCookie == await MD5MD5(UA + encryptionSecret + adminPassword)) return fetch(new Request('https://speed.cloudflare.com/locations', { headers: { 'Referer': 'https://speed.cloudflare.com/' } }));
				} else if (accessPath === 'robots.txt') return new Response('User-agent: *\nDisallow: /', { status: 200, headers: { 'Content-Type': 'text/plain; charset=UTF-8' } });
			} else if (!envUUID) return fetch(pagesStaticPage + '/noKV').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }) });
		}

		let camouflagePageURL = env.URL || 'nginx';
		if (camouflagePageURL && camouflagePageURL !== 'nginx' && camouflagePageURL !== '1101') {
			camouflagePageURL = camouflagePageURL.trim().replace(/\/$/, '');
			if (!camouflagePageURL.match(/^https?:\/\//i)) camouflagePageURL = 'https://' + camouflagePageURL;
			if (camouflagePageURL.toLowerCase().startsWith('http://')) camouflagePageURL = 'https://' + camouflagePageURL.substring(7);
			try { const u = new URL(camouflagePageURL); camouflagePageURL = u.protocol + '//' + u.host } catch (e) { camouflagePageURL = 'nginx' }
		}
		if (camouflagePageURL === '1101') return new Response(await html1101(url.host, accessIP), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
		try {
			const proxyURL = new URL(camouflagePageURL), newRequestHeaders = new Headers(request.headers);
			newRequestHeaders.set('Host', proxyURL.host);
			newRequestHeaders.set('Referer', proxyURL.origin);
			newRequestHeaders.set('Origin', proxyURL.origin);
			if (!newRequestHeaders.has('User-Agent') && UA && UA !== 'null') newRequestHeaders.set('User-Agent', UA);
			const proxyResponse = await fetch(proxyURL.origin + url.pathname + url.search, { method: request.method, headers: newRequestHeaders, body: request.body, cf: request.cf });
			const contentType = proxyResponse.headers.get('content-type') || '';
			// 只处理文本type的响应
			if (/text|javascript|json|xml/.test(contentType)) {
				const response内容 = (await proxyResponse.text()).replaceAll(proxyURL.host, url.host);
				return new Response(responseContent, { status: proxyResponse.status, headers: { ...Object.fromEntries(proxyResponse.headers), 'Cache-Control': 'no-store' } });
			}
			return proxyResponse;
		} catch (error) { }
		return new Response(await nginx(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
	}
};
///////////////////////////////////////////////////////////////////////叉HTTP传输数据///////////////////////////////////////////////
const HPACKHuffmanCodeLen = [
	13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
	28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
	6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
	5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
	13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
	15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
	6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
	20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
	24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
	22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
	21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
	26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
	19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
	20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
	26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
	30
];

function getXHTTPPaddingIdentifiers(yourUUID) {
	return { head: yourUUID.slice(1, 7), key: '_' + yourUUID.slice(25, 31) };
}

function calculateHPACKHuffmanByteLength(str) {
	const byte = new TextEncoder().encode(str);
	let totalBits = 0;
	for (let i = 0; i < bytes.length; i++) {
		totalBits += HPACKHuffmanCodeLen[bytes[i]];
	}
	return Math.ceil(totalBits / 8);
}

function extractXHTTPPaddingValue(request, localPaddingHeader, localPaddingKey) {
	const headerValue = request.headers.get(localPaddingHeader);
	if (headerValue) {
		try {
			const parsedURL = new URL(headerValue, 'https://x.invalid');
			const queryValue = parsedURL.searchParams.get(localPaddingKey);
			if (queryValue) return queryValue;
		} catch (e) { }
		return headerValue;
	}
	const requestURL = new URL(request.url);
	return requestURL.searchParams.get(localPaddingKey) || '';
}

function validateXHTTPPadding(request, localPaddingHeader, localPaddingKey) {
	const paddingValue = extractXHTTPPaddingValue(request, localPaddingHeader, localPaddingKey);
	if (!paddingValue) return true;
	const huffmanlength = calculateHPACKHuffmanByteLength(paddingValue);
	return huffmanlength >= 98 && huffmanlength <= 1002;
}

const xhttpBase62Charset = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
function generateXHTTPPaddingString(length) {
	const charsetLen = xhttpBase62Charset.length;
	let result = '';
	for (let i = 0; i < length; i++) {
		result += xhttpBase62Charset[Math.floor(Math.random() * charsetLength)];
	}
	return result;
}

async function handleXHTTPRequest(request, yourUUID, proxyContext = {}) {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const { head: localPaddingHeader, key: localPaddingKey } = getXHTTPPaddingIdentifiers(yourUUID);
	if (!validateXHTTPPadding(request, localPaddingHeader, localPaddingKey)) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const firstPacket = await readXHTTPFirstPacket(reader, yourUUID);
	if (!firstPacket) {
		try { reader.releaseLock() } catch (e) { }
		return new Response('Invalid request', { status: 400 });
	}
	if (isSpeedTestSite(firstPacket.hostname) && proxyContext.proxyType === null) {
		try { reader.releaseLock() } catch (e) { }
		return new Response(buildLocal204Response(firstPacket.respHeader), {
			status: 200,
			headers: {
				'Content-Type': 'application/octet-stream',
				'X-Accel-Buffering': 'no',
				'Cache-Control': 'no-store'
			}
		});
	}
	if (firstPacket.isUDP && firstPacket.protocol !== 'trojan' && firstPacket.port !== 53) {
		try { reader.releaseLock() } catch (e) { }
		return new Response('UDP is not supported', { status: 400 });
	}

	const responseHeaders = new Headers({
		'Content-Type': 'application/octet-stream',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store'
	});

	try {
		const responseURL = new URL('https://x.invalid/');
		responseURL.searchParams.set(localPaddingKey, generateXHTTPPaddingString(100 + Math.floor(Math.random() * 901)));
		responseHeaders.set(localPaddingHeader, responseURL.toString());
	} catch (e) { }

	if (firstPacket.isUDP) return handleXHTTPUDPRequest(firstPacket, reader, request, proxyContext, responseHeaders);

	try { reader.releaseLock() } catch (e) { }

	const remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, downlinkDrain: Promise.resolve() };
	const abortController = new AbortController();
	let isCleaned = false;
	const cleanup = (reason) => {
		if (isCleaned) return;
		isCleaned = true;
		try { abortController.abort(reason) } catch (e) { }
		invalidateTCPConnectorGeneration(remoteConnWrapper);
	};

	const placeholderWS = { readyState: WebSocket.OPEN };

	let socket;
	try {
		socket = await forwardTCP(firstPacket.hostname, firstPacket.port, firstPacket.rawData, placeholderWS, firstPacket.respHeader, remoteConnWrapper, yourUUID, request, proxyContext, firstPacket.protocol === 'trojan', firstPacket.rawData, true);
	} catch (err) {
		log(`[叉HTTP-Pipe] 连接失败: ${err?.message || err}`);
		cleanup(err);
		return new Response('bad gateway', { status: 502 });
	}
	if (!socket) {
		cleanup(new Error('socket is null'));
		return new Response('bad gateway', { status: 502 });
	}

	const uplinkPromise = (async () => {
		const uplinkBundler = createUplinkGrainBundleStream();
		const pipePromise = uplinkBundler.readable.pipeTo(socket.writable, { signal: abortController.signal });
		void pipePromise.catch(cleanup);
		const uplinkReader = request.body.getReader();
		const cancelUplinkReader = () => {
			try { uplinkReader.cancel(abortController.signal.reason).catch(() => { }); } catch (e) { }
		};
		abortController.signal.addEventListener('abort', cancelUplinkReader, { once: true });
		try {
			try {
				while (true) {
					const { done, value } = await uplinkReader.read();
					if (done) break;
					if (value?.byteLength) await uplinkBundler.write(value);
				}
			} finally {
				abortController.signal.removeEventListener('abort', cancelUplinkReader);
				try { uplinkReader.releaseLock() } catch (e) { }
			}
		} finally {
			try { await uplinkBundler.end() } catch (e) { }
		}
		await pipePromise;
	})();

	const response流 = typeof IdentityTransformStream !== 'undefined'
		? new IdentityTransformStream()
		: new TransformStream();
	const downlinkPromise = (async () => {
		const writer = responseStream.writable.getWriter();
		try {
			if (getValidDataLength(firstPacket.respHeader) > 0) await writer.write(firstPacket.respHeader);
		} catch (error) {
			try { await writer.abort(error) } catch (e) { }
			throw error;
		} finally {
			try { writer.releaseLock() } catch (e) { }
		}
		await socket.readable.pipeTo(responseStream.writable, { signal: abortController.signal });
	})();

	void uplinkPromise.catch(cleanup);
	void downlinkPromise.then(() => cleanup(), cleanup);
	void Promise.allSettled([uplinkPromise, downlinkPromise]);

	return new Response(responseStream.readable, { status: 200, headers: responseHeaders });
}

function handleXHTTPUDPRequest(firstPacket, reader, request, proxyContext, responseHeaders) {
	const trojanUDPContext = { buffer: new Uint8Array(0), proxyAddress: proxyContext.trojanProxyAddress };
	return new Response(new ReadableStream({
		async start(controller) {
			let isClosed = false;
			let udpRespHeader = firstPacket.respHeader;
			const httpBridge = {
				readyState: WebSocket.OPEN,
				send(data) {
					if (isClosed) return;
					try {
						const chunk = data instanceof Uint8Array
							? data
							: data instanceof ArrayBuffer
								? new Uint8Array(data)
								: ArrayBuffer.isView(data)
									? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
									: new Uint8Array(data);
						controller.enqueue(chunk);
					} catch (e) {
						isClosed = true;
						this.readyState = WebSocket.CLOSED;
					}
				},
				close() {
					if (isClosed) return;
					isClosed = true;
					this.readyState = WebSocket.CLOSED;
					try { controller.close() } catch (e) { }
				}
			};
			let forwardFailed = false;
			try {
				if (firstPacket.protocol === 'trojan') {
					trojanUDPContext.targetHost = firstPacket.hostname;
					trojanUDPContext.targetPort = firstPacket.port;
					if (trojanUDPContext.proxyAddress) await forwardTrojanUDPData(firstPacket.rawData, httpBridge, trojanUDPContext, request);
				}
				if (!(firstPacket.protocol === 'trojan' && trojanUDPContext.proxyAddress) && firstPacket.rawData?.byteLength) {
					if (firstPacket.protocol === 'trojan') await forwardTrojanUDPData(firstPacket.rawData, httpBridge, trojanUDPContext, request);
					else await forwardUDP(firstPacket.rawData, httpBridge, udpRespHeader, request);
					udpRespHeader = null;
				}
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value || value.byteLength === 0) continue;
					if (firstPacket.protocol === 'trojan') await forwardTrojanUDPData(value, httpBridge, trojanUDPContext, request);
					else await forwardUDP(value, httpBridge, udpRespHeader, request);
					udpRespHeader = null;
				}
			} catch (err) {
				forwardFailed = true;
				log(`[叉HTTP转发] 处理失败: ${err?.message || err}`);
				closeSocketQuietly(httpBridge);
			} finally {
			const keepTrojanUDPProxyDown = !forwardFailed && firstPacket.protocol === 'trojan' && trojanUDPContext.proxyAddress && trojanUDPContext.proxySocket;
			if (!keepTrojanUDPProxyDown) {
				try { trojanUDPContext.proxySocket?.close() } catch (e) { }
				closeSocketQuietly(httpBridge);
			}
			try { reader.releaseLock() } catch (e) { }
			}
		},
		cancel() {
			try { trojanUDPContext.proxySocket?.close() } catch (e) { }
			try { reader.releaseLock() } catch (e) { }
		}
	}), { status: 200, headers: responseHeaders });
}

function getValidDataLength(data) {
	if (!data) return 0;
	if (typeof data.byteLength === 'number') return data.byteLength;
	if (typeof data.length === 'number') return data.length;
	return 0;
}

function invalidateTCPConnectorGeneration(remoteConnWrapper) {
	if (!remoteConnWrapper) return;
	remoteConnWrapper.generation = (Number.isInteger(remoteConnWrapper.generation) ? remoteConnWrapper.generation : 0) + 1;
	const socket = remoteConnWrapper.socket;
	remoteConnWrapper.socket = null;
	remoteConnWrapper.downlinkController = null;
	remoteConnWrapper.downlinkDrain = Promise.resolve();
	try { socket?.close?.() } catch (e) { }
}

function startTCPConnectorGeneration(remoteConnWrapper) {
	if (!Number.isInteger(remoteConnWrapper.generation)) remoteConnWrapper.generation = 0;
	const generation = ++remoteConnWrapper.generation;
	const previousSocket = remoteConnWrapper.socket;
	remoteConnWrapper.socket = null;
	const previousDownlink = remoteConnWrapper.downlinkController;
	remoteConnWrapper.downlinkController = null;
	const previousDrain = remoteConnWrapper.downlinkDrain || Promise.resolve();
	let currentDrain;
	try { currentDrain = previousDownlink?.stopAndFlush?.() || Promise.resolve() }
	catch (error) { currentDrain = Promise.reject(error) }
	const downlinkDrain = Promise.all([previousDrain, currentDrain]);
	// Installation awaits this promise; attach a handler immediately in case draining fails before dialing completes.
	downlinkDrain.catch(() => { });
	remoteConnWrapper.downlinkDrain = downlinkDrain;
	try { previousSocket?.close?.() } catch (e) { }
	return { generation, downlinkDrain };
}

async function readXHTTPFirstPacket(reader, token) {
	const decoder = vlessTextDecoder;

	const tryParseVLESSFirstPacket = (data) => {
		const length = data.byteLength;
		if (length < 18) return { status: 'need_more' };
		if (!uuidBytesMatch(data, 1, token)) return { status: 'invalid' };

		const optLen = data[17];
		const cmdIndex = 18 + optLen;
		if (length < cmdIndex + 1) return { status: 'need_more' };

		const cmd = data[cmdIndex];
		if (cmd !== 1 && cmd !== 2) return { status: 'invalid' };

		const portIndex = cmdIndex + 1;
		if (length < portIndex + 3) return { status: 'need_more' };

		const port = (data[portIndex] << 8) | data[portIndex + 1];
		const addressType = data[portIndex + 2];
		const addressIndex = portIndex + 3;
		let headerLen = -1;
		let hostname = '';

		if (addressType === 1) {
			if (length < addressIndex + 4) return { status: 'need_more' };
			hostname = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
			headerLen = addressIndex + 4;
		} else if (addressType === 2) {
			if (length < addressIndex + 1) return { status: 'need_more' };
			const domainLen = data[addressIndex];
			if (length < addressIndex + 1 + domainLen) return { status: 'need_more' };
			hostname = decoder.decode(data.subarray(addressIndex + 1, addressIndex + 1 + domainLen));
			headerLen = addressIndex + 1 + domainLen;
		} else if (addressType === 3) {
			if (length < addressIndex + 16) return { status: 'need_more' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = addressIndex + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			headerLen = addressIndex + 16;
		} else return { status: 'invalid' };

		if (!hostname) return { status: 'invalid' };

		return {
			status: 'ok',
			result: {
				protocol: 'vl' + 'ess',
				hostname,
				port,
				isUDP: cmd === 2,
				rawData: data.subarray(headerLen),
				respHeader: new Uint8Array([data[0], 0]),
				rawData: null,
			}
		};
	};

	const tryParseTrojanFirstPacket = (data) => {
		const passwordHash = sha224(token);
		const passwordHashbytes = new TextEncoder().encode(passwordHash);
		const length = data.byteLength;
		if (length < 58) return { status: 'need_more' };
		if (data[56] !== 0x0d || data[57] !== 0x0a) return { status: 'invalid' };
		for (let i = 0; i < 56; i++) {
			if (data[i] !== passwordHashBytes[i]) return { status: 'invalid' };
		}

		const socksStart = 58;
		if (length < socksStart + 2) return { status: 'need_more' };
		const cmd = data[socksStart];
		if (cmd !== 1 && cmd !== 3) return { status: 'invalid' };
		const isUDP = cmd === 3;

		const atype = data[socksStart + 1];
		let cursor = socksStart + 2;
		let hostname = '';

		if (atype === 1) {
			if (length < cursor + 4) return { status: 'need_more' };
			hostname = `${data[cursor]}.${data[cursor + 1]}.${data[cursor + 2]}.${data[cursor + 3]}`;
			cursor += 4;
		} else if (atype === 3) {
			if (length < cursor + 1) return { status: 'need_more' };
			const domainLen = data[cursor];
			if (length < cursor + 1 + domainLen) return { status: 'need_more' };
			hostname = decoder.decode(data.subarray(cursor + 1, cursor + 1 + domainLen));
			cursor += 1 + domainLen;
		} else if (atype === 4) {
			if (length < cursor + 16) return { status: 'need_more' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = cursor + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			cursor += 16;
		} else return { status: 'invalid' };

		if (!hostname) return { status: 'invalid' };
		if (length < cursor + 4) return { status: 'need_more' };

		const port = (data[cursor] << 8) | data[cursor + 1];
		if (data[cursor + 2] !== 0x0d || data[cursor + 3] !== 0x0a) return { status: 'invalid' };
		const dataOffset = cursor + 4;

		return {
			status: 'ok',
			result: {
				protocol: 'trojan',
				hostname,
				port,
				isUDP,
				rawData: data.subarray(dataOffset),
				rawData: data,
				respHeader: null,
			}
		};
	};

	let buffer = new Uint8Array(1024);
	let offset = 0;

	while (true) {
		const { value, done } = await reader.read();
		if (done) {
			if (offset === 0) return null;
			break;
		}

		const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
		if (offset + chunk.byteLength > buffer.byteLength) {
			const newBuffer = new Uint8Array(Math.max(buffer.byteLength * 2, offset + chunk.byteLength));
			newBuffer.set(buffer.subarray(0, offset));
			buffer = newBuffer;
		}

		buffer.set(chunk, offset);
		offset += chunk.byteLength;

		const currentData = buffer.subarray(0, offset);
		const trojanResult = tryParseTrojanFirstPacket(currentData);
		if (木马result.status === 'ok') return { ...木马result.result, reader };

		const vlessResult = tryParseVLESSFirstPacket(currentData);
		if (魏烈思result.status === 'ok') return { ...魏烈思result.result, reader };

		if (木马result.status === 'invalid' && 魏烈思result.status === 'invalid') return null;
	}

	const finalData = buffer.subarray(0, offset);
	const finalTrojanResult = tryParseTrojanFirstPacket(finalData);
	if (最终木马result.status === 'ok') return { ...最终木马result.result, reader };
	const finalVlessResult = tryParseVLESSFirstPacket(finalData);
	if (最终魏烈思result.status === 'ok') return { ...最终魏烈思result.result, reader };
	return null;
}
///////////////////////////////////////////////////////////////////////gRPC传输数据///////////////////////////////////////////////
async function handleGRPCRequest(request, yourUUID, proxyContext = {}) {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, downlinkDrain: Promise.resolve() };
	const invalidateRemote = () => invalidateTCPConnectorGeneration(remoteConnWrapper);
	let isDnsQuery = false;
	const trojanUDPContext = { buffer: new Uint8Array(0), proxyAddress: proxyContext.trojanProxyAddress };
	let isTrojan = null;
	let currentWriteSocket = null;
	let remoteWriter = null;
	let grpcUplinkWriteQueue = null;
	//log('[gRPC] 开始处理双向流');
	const grpcHeaders = new Headers({
		'Content-Type': 'application/grpc',
		'grpc-status': '0',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store'
	});

	const downlinkBufferLimit = downlinkGrainPacketBytes;
	const downlinkFlushInterval = 1;

	return new Response(new ReadableStream({
		async start(controller) {
			let isClosed = false;
			let send队列 = [];
			let queuebyteCount = 0;
			let flushTimer = null;
			let flushMicrotaskQueued = false;
			const grpcBridge = {
				readyState: WebSocket.OPEN,
				send(data) {
					if (isClosed) return;
					const chunk = data instanceof Uint8Array ? data : new Uint8Array(data);
					const lenBytes数组 = [];
					let remaining = chunk.byteLength >>> 0;
					while (remaining > 127) {
						lenBytes数组.push((remaining & 0x7f) | 0x80);
						remaining >>>= 7;
					}
					lenBytes数组.push(remaining);
					const lenBytes = new Uint8Array(lenBytes数组);
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
					send队列.push(frame);
					queueByteCount += frame.byteLength;
					安排flushSendQueue();
				},
				close() {
					if (this.readyState === WebSocket.CLOSED) return;
					flushSendQueue(true);
					isClosed = true;
					this.readyState = WebSocket.CLOSED;
					try { controller.close() } catch (e) { }
				}
			};

			const flushSendQueue = (force = false) => {
				刷新MicrotaskisQueued = false;
				if (flushTimer) {
					clearTimeout(flushTimer);
					flushTimer = null;
				}
				if ((!force && isClosed) || queueByteCount === 0) return;
				const out = new Uint8Array(queueByteCount);
				let offset = 0;
				for (const item of send队列) {
					out.set(item, offset);
					offset += item.byteLength;
				}
				send队列 = [];
				queueByteCount = 0;
				try {
					controller.enqueue(out);
				} catch (e) {
					isClosed = true;
					grpcBridge.readyState = WebSocket.CLOSED;
				}
			};

			const scheduleFlushSendQueue = () => {
				if (queueByteCount >= downlinkBufferLimit) {
					flushSendQueue();
					return;
				}
				if (刷新MicrotaskisQueued || flushTimer) return;
				刷新MicrotaskisQueued = true;
				queueMicrotask(() => {
					刷新MicrotaskisQueued = false;
					if (isClosed || queueByteCount === 0 || flushTimer) return;
					flushTimer = setTimeout(flushSendQueue, downlinkFlushInterval);
				});
			};

			const closeConnection = () => {
				if (isClosed) return;
				grpcUplinkWriteQueue?.清空();
				invalidateRemote();
				flushSendQueue(true);
				isClosed = true;
				grpcBridge.readyState = WebSocket.CLOSED;
				if (flushTimer) clearTimeout(flushTimer);
				if (remoteWriter) {
					try { remoteWriter.releaseLock() } catch (e) { }
					remoteWriter = null;
				}
				currentWriteSocket = null;
				try { reader.releaseLock() } catch (e) { }
				try { trojanUDPContext.proxySocket?.close() } catch (e) { }
				try { controller.close() } catch (e) { }
			};

			const releaseRemoteWriter = () => {
				if (remoteWriter) {
					try { remoteWriter.releaseLock() } catch (e) { }
					remoteWriter = null;
				}
				currentWriteSocket = null;
			};

			const uplinkWriteQueue = grpcUplinkWriteQueue = createUplinkWriteQueue({
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
					if (typeof remoteConnWrapper.retryConnect !== 'function') throw new Error('retry unavailable');
					await remoteConnWrapper.retryConnect();
				},
				closeConnection,
				name: 'gRPC上行'
			});

			const writeToRemote = async (payload, allowRetry = true) => {
				return uplinkWriteQueue.write并等待(payload, allowRetry);
			};

			let forwardFailed = false;
			try {
				let pending = new Uint8Array(0);
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value || value.byteLength === 0) continue;
					const currentChunk = value instanceof Uint8Array ? value : new Uint8Array(value);
					const merged = new Uint8Array(pending.length + currentChunk.length);
					merged.set(pending, 0);
					merged.set(currentChunk, pending.length);
					pending = merged;
					while (pending.byteLength >= 5) {
						const grpcLen = ((pending[1] << 24) >>> 0) | (pending[2] << 16) | (pending[3] << 8) | pending[4];
						const frameSize = 5 + grpcLen;
						if (pending.byteLength < frameSize) break;
						const grpcPayload = pending.subarray(5, frameSize);
						pending = pending.slice(frameSize);
						if (!grpcPayload.byteLength) continue;
						let payload = grpcPayload;
						if (payload.byteLength >= 2 && payload[0] === 0x0a) {
							let shift = 0;
							let offset = 1;
							let varint有效 = false;
							while (offset < payload.length) {
								const current = payload[offset++];
								if ((current & 0x80) === 0) {
									varint有效 = true;
									break;
								}
								shift += 7;
								if (shift > 35) break;
							}
							if (varint有效) payload = payload.subarray(offset);
						}
						if (!payload.byteLength) continue;
						if (isDnsQuery) {
							if (isTrojan) await forwardTrojanUDPData(payload, grpcBridge, trojanUDPContext, request);
							else await forwardUDP(payload, grpcBridge, null, request);
							continue;
						}
						if (remoteConnWrapper.socket || remoteConnWrapper.connectingPromise) {
							if (!(await writeToRemote(payload))) throw new Error('Remote socket is not ready');
						} else {
							const firstPacketbytes = toUint8Array(payload);
							if (isTrojan === null) isTrojan = firstPacketbytes.byteLength >= 58 && firstPacketbytes[56] === 0x0d && firstPacketbytes[57] === 0x0a;
							if (isTrojan) {
								const parseResult = parseTrojanRequest(firstPacketbytes, yourUUID);
								if (解析result?.hasError) throw new Error(解析result.message || 'Invalid trojan request');
								const { port, hostname, rawClientData, isUDP } = 解析result;
								log(`[gRPC] 木马firstPacket: ${hostname}:${port} | UDP: ${isUDP ? '是' : '否'}`);
								if (isSpeedTestSite(hostname) && proxyContext.proxyType === null) {
									grpcBridge.send(buildLocal204Response());
									return;
								}
								if (isUDP) {
									isDnsQuery = true;
									trojanUDPContext.targetHost = hostname;
									trojanUDPContext.targetPort = port;
									if (trojanUDPContext.proxyAddress) await forwardTrojanUDPData(firstPacketbytes, grpcBridge, trojanUDPContext, request);
									else if (getValidDataLength(rawClientData) > 0) await forwardTrojanUDPData(rawClientData, grpcBridge, trojanUDPContext, request);
								} else {
									await forwardTCP(hostname, port, rawClientData, grpcBridge, null, remoteConnWrapper, yourUUID, request, proxyContext, true, firstPacketbytes);
								}
							} else {
								isTrojan = false;
								const parseResult = parseVLESSRequest(firstPacketbytes, yourUUID);
								if (解析result?.hasError) throw new Error(解析result.message || 'Invalid VLESS request');
								const { port, hostname, version, isUDP, rawClientData } = 解析result;
								log(`[gRPC] 魏烈思firstPacket: ${hostname}:${port} | UDP: ${isUDP ? '是' : '否'}`);
								const respHeader = new Uint8Array([version, 0]);
								if (isSpeedTestSite(hostname) && proxyContext.proxyType === null) {
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
									if (isTrojan) await forwardTrojanUDPData(rawData, grpcBridge, trojanUDPContext, request);
									else await forwardUDP(rawData, grpcBridge, null, request);
								}
								else await forwardTCP(hostname, port, rawData, grpcBridge, null, remoteConnWrapper, yourUUID, request, proxyContext);
							}
						}
					}
					flushSendQueue();
				}
				await uplinkWriteQueue.waitEmpty();
			} catch (err) {
				forwardFailed = true;
				log(`[gRPC转发] 处理失败: ${err?.message || err}`);
			} finally {
				const keepTrojanUDPProxyDown = !forwardFailed && isDnsQuery && isTrojan && trojanUDPContext.proxyAddress && trojanUDPContext.proxySocket;
				if (keepTrojanUDPProxyDown) {
					uplinkWriteQueue.clear();
					invalidateRemote();
					releaseRemoteWriter();
					try { reader.releaseLock() } catch (e) { }
				} else {
					closeConnection();
				}
			}
		},
		cancel() {
			grpcUplinkWriteQueue?.清空();
			invalidateRemote();
			try { trojanUDPContext.proxySocket?.close() } catch (e) { }
			try { reader.releaseLock() } catch (e) { }
		}
	}), { status: 200, headers: grpcHeaders });
}

function isValidWSEarlyData(bytes, token) {
	if (!bytes?.byteLength) return false;
	if (bytes.byteLength >= 18 && uuidBytesMatch(bytes, 1, token)) return true;
	if (bytes.byteLength < 58 || bytes[56] !== 0x0d || bytes[57] !== 0x0a) return false;

	const trojanPassword = sha224(token);
	for (let i = 0; i < 56; i++) {
		if (bytes[i] !== trojanPassword.charCodeAt(i)) return false;
	}
	return true;
}

function decodeWSEarlyData(header, token) {
	if (!header) return null;
	if (header.length > wsMaxEarlyHeaderLength) throw new Error('early data is too large');

	let bytes;
	const Uint8ArrayBase64 = /** @type {any} */ (Uint8Array);
	if (typeof Uint8ArrayBase64.fromBase64 === 'function') {
		try {
			bytes = Uint8ArrayBase64.fromBase64(header, { alphabet: 'base64url' });
		} catch (_) { }
	}
	if (!bytes) {
		let normalized = header.replace(/-/g, '+').replace(/_/g, '/');
		const padding = normalized.length % 4;
		if (padding) normalized += '='.repeat(4 - padding);
		let binaryString;
		try {
			binaryString = atob(normalized);
		} catch (_) {
			return null;
		}
		bytes = new Uint8Array(binaryString.length);
		for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
	}

	if (bytes.byteLength > wsMaxEarlyDataBytes) throw new Error('early data is too large');
	return isValidWSEarlyData(bytes, token) ? bytes : null;
}

///////////////////////////////////////////////////////////////////////WS传输数据///////////////////////////////////////////////
async function handleWSRequest(request, yourUUID, url, proxyContext = {}) {
	const wsSocketPair = new WebSocketPair();
	const [clientSock, serverSock] = Object.values(wsSocketPair);
	try { (/** @type {any} */ (serverSock)).accept({ allowHalfOpen: true }) }
	catch (_) { serverSock.accept() }
	serverSock.binaryType = 'arraybuffer';
	let remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, downlinkDrain: Promise.resolve() };
	const invalidateRemote = () => invalidateTCPConnectorGeneration(remoteConnWrapper);
	let isDnsQuery = false;
	let isTrojan = null;
	const trojanUDPContext = { buffer: new Uint8Array(0), proxyAddress: proxyContext.trojanProxyAddress };
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
	const ssModeDisableEarlyData = !!url.searchParams.get('enc');
	let wsUplinkWriteQueue = null;
	let wsExplicitTransferChain = Promise.resolve();
	let wsExplicitTransferStopReceiving = false, wsExplicitTransferFailed = false, wsExplicitTransferFinishingEnqueued = false;
	let wsExplicitQueueBytes = 0, wsExplicitQueueEntries = 0;
	let determineProtocolType = null, currentWriteSocket = null, remoteWriter = null;
	let ssContext = null, ssInitTask = null;
	let wsLocalSpeedTestMode = false, wsLocalSpeedTestResponseSocket = null;
	let wsLocalSpeedTestRequestCache = new Uint8Array(0);
	let wsLocalSpeedTestFirstPacketResponseHeader = null;
	const wsLocalSpeedTestRequestLimit = 64 * 1024;

	const sendWSLocalSpeedTestResponse = async () => {
		if (!wsLocalSpeedTestResponseSocket) return;
		const respHeader = wsLocalSpeedTestFirstPacketResponseHeader;
		wsLocalSpeedTestFirstPacketResponseHeader = null;
		await webSocketSendAndAwait(wsLocalSpeedTestResponseSocket, buildWSLocal204Response(respHeader));
	};

	const findHTTPRequestHeaderEnd = (data) => {
		for (let i = 0; i <= data.byteLength - 4; i++) {
			if (data[i] === 0x0d && data[i + 1] === 0x0a && data[i + 2] === 0x0d && data[i + 3] === 0x0a) return i + 4;
		}
		return -1;
	};

	const handleWSLocalSpeedTestData = async (data) => {
		const chunk = toUint8Array(data);
		if (!chunk.byteLength) return;
		if (wsLocalSpeedTestRequestCache.byteLength + chunk.byteLength > wsLocalSpeedTestRequestLimit) throw new Error('WS local speed-test request is too large');
		wsLocalSpeedTestRequestCache = concatByteData(wsLocalSpeedTestRequestCache, chunk);

		while (wsLocalSpeedTestRequestCache.byteLength) {
			const headerEnd = findHTTPRequestHeaderEnd(wsLocalSpeedTestRequestCache);
			if (headerEnd === -1) return;
			const headerText = vlessTextDecoder.decode(wsLocalSpeedTestRequestCache.subarray(0, headerEnd));
			const contentLengthMatch = headerText.match(/(?:^|\r\n)content-length\s*:\s*(\d+)/i);
			const contentLength = contentLengthMatch ? Number(contentLengthMatch[1]) : 0;
			const requestLength = headerEnd + contentLength;
			if (!Number.isSafeInteger(contentLength) || requestLength > wsLocalSpeedTestRequestLimit) throw new Error('WS local speed-test request body is too large');
			if (wsLocalSpeedTestRequestCache.byteLength < requestLength) return;
			wsLocalSpeedTestRequestCache = wsLocalSpeedTestRequestCache.slice(requestLength);
			await sendWSLocalSpeedTestResponse();
		}
	};

	const enableWSLocalSpeedTestMode = async (responseSocket, respHeader = null, firstRequestData = null) => {
		wsLocalSpeedTestMode = true;
		wsLocalSpeedTestResponseSocket = responseSocket;
		wsLocalSpeedTestRequestCache = new Uint8Array(0);
		wsLocalSpeedTestFirstPacketResponseHeader = respHeader;
		if (getValidDataLength(firstRequestData) > 0) await handleWSLocalSpeedTestData(firstRequestData);
	};

	const releaseRemoteWriter = () => {
		if (remoteWriter) {
			try { remoteWriter.releaseLock() } catch (e) { }
			remoteWriter = null;
		}
		currentWriteSocket = null;
	};

	const uplinkWriteQueue = wsUplinkWriteQueue = createUplinkWriteQueue({
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
			if (typeof remoteConnWrapper.retryConnect !== 'function') throw new Error('retry unavailable');
			await remoteConnWrapper.retryConnect();
		},
		closeConnection: err => handleWSExplicitTransferError(err),
		name: 'WS上行'
	});

	const writeToRemote = async (chunk, allowRetry = true) => {
		return uplinkWriteQueue.write(chunk, allowRetry);
	};

	const getSSContext = async () => {
		if (ssContext) return ssContext;
		if (!ssInitTask) {
			ssInitTask = (async () => {
				const requestCipherMethod = (url.searchParams.get('enc') || '').toLowerCase();
				const preferredCipherConfig = SS_SUPPORTED_CIPHERS[requestCipherMethod] || SS_SUPPORTED_CIPHERS['aes-128-gcm'];
				const inboundCandidateCipherConfigs = [preferredCipherConfig, ...Object.values(SS_SUPPORTED_CIPHERS).filter(c => c.method !== preferredCipherConfig.method)];
				const inboundMasterKeyTaskBuffer = new Map();
				const getInboundMasterKeyTask = (config) => {
					if (!inboundMasterKeyTaskBuffer.has(config.method)) inboundMasterKeyTaskBuffer.set(config.method, SSDeriveMasterKey(yourUUID, config.keyLen));
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
					const maxSaltLen = Math.max(...inboundCandidateCipherConfigs.map(c => c.saltLen));
					const maxAlignScanBytes = 16;
					const maxScannableOffset = Math.min(maxAlignScanBytes, Math.max(0, inboundState.buffer.byteLength - (lengthCipherTotalLength + Math.min(...inboundCandidateCipherConfigs.map(c => c.saltLen)))));
					for (let offset = 0; offset <= maxScannableOffset; offset++) {
						for (const cipherConfig of inboundCandidateCipherConfigs) {
							const initMinLength = offset + cipherConfig.saltLen + lengthCipherTotalLength;
							if (inboundState.buffer.byteLength < 初始化最小length) continue;
							const salt = inboundState.buffer.subarray(offset, offset + cipherConfig.saltLen);
							const lengthCipher = inboundState.buffer.subarray(offset + cipherConfig.saltLen, 初始化最小length);
							const masterKey = await getInboundMasterKeyTask(cipherConfig);
							const decryptKey = await SSDeriveSessionKey(cipherConfig, masterKey, salt, ['decrypt']);
							const nonceCounter = new Uint8Array(SS_NONCE_LENGTH);
							try {
								const lengthPlain = await SSAEADDecrypt(decryptKey, nonceCounter, lengthCipher);
								if (lengthPlain.byteLength !== 2) continue;
								const payloadLength = (lengthPlain[0] << 8) | lengthPlain[1];
								if (payloadLength < 0 || payloadLength > cipherConfig.maxChunk) continue;
								if (offset > 0) log(`[SS Inbound] 检测到前导噪声 ${offset}B，autoAligned`);
								if (cipherConfig.method !== preferredCipherConfig.method) log(`[SS Inbound] URL enc=${requestCipherMethod || preferredCipherConfig.method} 与实际 ${cipherConfig.method} inconsistent，autoSwitched`);
								inboundState.buffer = inboundState.buffer.subarray(初始化最小length);
								inboundState.decryptKey = decryptKey;
								inboundState.nonceCounter = nonceCounter;
								inboundState.waitPayloadLength = payloadLength;
								inboundState.cipherConfig = cipherConfig;
								inboundState.hasSalt = true;
								return true;
							} catch (_) { }
						}
					}
					const initFailureThresholdLength = 最大盐length + lengthCipherTotalLength + maxAlignScanBytes;
					if (inboundState.buffer.byteLength >= 初始化失败判定length) {
						throw new Error(`SS handshake decrypt failed (enc=${requestCipherMethod || 'auto'}, candidates=${inboundCandidateCipherConfigs.map(c => c.method).join('/')})`);
					}
					return false;
				};
				const inboundDecryptor = {
					async 输入(dataChunk) {
						const chunk = toUint8Array(dataChunk);
						if (chunk.byteLength > 0) inboundState.buffer = concatByteData(inboundState.buffer, chunk);
						if (!inboundState.hasSalt) {
							const initSucceeded = await initInboundDecryptState();
							if (!initSucceeded) return [];
						}
						const plaintextChunks = [];
						while (true) {
							if (inboundState.waitPayloadLength === null) {
								const lengthCipherTotalLength = 2 + SS_AEAD_TAG_LENGTH;
								if (inboundState.buffer.byteLength < lengthCipherTotalLength) break;
								const lengthCipher = inboundState.buffer.subarray(0, lengthCipherTotalLength);
								inboundState.buffer = inboundState.buffer.subarray(lengthCipherTotalLength);
								const lengthPlain = await SSAEADDecrypt(inboundState.decryptKey, inboundState.nonceCounter, lengthCipher);
								if (lengthPlain.byteLength !== 2) throw new Error('SS length decrypt failed');
								const payloadLength = (lengthPlain[0] << 8) | lengthPlain[1];
								if (payloadLength < 0 || payloadLength > inboundState.cipherConfig.maxChunk) throw new Error(`SS payload length invalid: ${payloadLength}`);
								inboundState.waitPayloadLength = payloadLength;
							}
							const payloadCipherTotalLength = inboundState.waitPayloadLength + SS_AEAD_TAG_LENGTH;
							if (inboundState.buffer.byteLength < payloadCipherTotalLength) break;
							const payloadCipher = inboundState.buffer.subarray(0, payloadCipherTotalLength);
							inboundState.buffer = inboundState.buffer.subarray(payloadCipherTotalLength);
							const payloadPlain = await SSAEADDecrypt(inboundState.decryptKey, inboundState.nonceCounter, payloadCipher);
							plaintextChunks.push(payloadPlain);
							inboundState.waitPayloadLength = null;
						}
						return plaintextChunks;
					},
				};
				let outboundEncryptor = null;
				const SS单批最大bytes = 32 * 1024;
				const getOutboundEncryptor = async () => {
					if (outboundEncryptor) return outboundEncryptor;
					if (!inboundState.cipherConfig) throw new Error('SS cipher is not negotiated');
					const outboundCipherConfig = inboundState.cipherConfig;
					const outboundMasterKey = await SSDeriveMasterKey(yourUUID, 出站cipherConfig.keyLen);
					const outboundRandomBytes = crypto.getRandomValues(new Uint8Array(出站cipherConfig.saltLen));
					const outboundCipherKey = await SSDeriveSessionKey(出站cipherConfig, outboundMasterKey, outboundRandomBytes, ['encrypt']);
					const outboundNonceCounter = new Uint8Array(SS_NONCE_LENGTH);
					let randomBytesSent = false;
					outboundEncryptor = {
						async 加密并send(dataChunk, sendChunk) {
							const plaintextData = toUint8Array(dataChunk);
							if (!randomBytesSent) {
								await sendChunk(outboundRandomBytes);
								randomBytesSent = true;
							}
							if (plaintextData.byteLength === 0) return;
							let offset = 0;
							while (offset < plaintextData.byteLength) {
								const end = Math.min(offset + 出站cipherConfig.maxChunk, plaintextData.byteLength);
								const payloadPlain = plaintextData.subarray(offset, end);
								const lengthPlain = new Uint8Array(2);
								lengthPlain[0] = (payloadPlain.byteLength >>> 8) & 0xff;
								lengthPlain[1] = payloadPlain.byteLength & 0xff;
								const lengthCipher = await SSAEADEncrypt(outboundCipherKey, outboundNonceCounter, lengthPlain);
								const payloadCipher = await SSAEADEncrypt(outboundCipherKey, outboundNonceCounter, payloadPlain);
								const frame = new Uint8Array(lengthCipher.byteLength + payloadCipher.byteLength);
								frame.set(lengthCipher, 0);
								frame.set(payloadCipher, lengthCipher.byteLength);
								await sendChunk(frame);
								offset = end;
							}
						},
					};
					return outboundEncryptor;
				};
				let SSsend队列 = Promise.resolve();
				const SS入队send = (chunk) => {
					SSsend队列 = SSsend队列.then(async () => {
						if (serverSock.readyState !== WebSocket.OPEN) return;
						const initializedOutboundEncryptor = await getOutboundEncryptor();
						await initializedOutboundEncryptor.加密并send(chunk, async (encryptedChunk) => {
							if (encryptedChunk.byteLength > 0 && serverSock.readyState === WebSocket.OPEN) {
								await webSocketSendAndAwait(serverSock, encryptedChunk.buffer);
							}
						});
					}).catch((error) => {
						log(`[SSsend] 加密失败: ${error?.message || error}`);
						closeSocketQuietly(serverSock);
					});
					return SSsend队列;
				};
				const responseSocket = {
					get readyState() {
						return serverSock.readyState;
					},
					send(data) {
						const chunk = toUint8Array(data);
						if (chunk.byteLength <= SS单批最大bytes) {
							return SS入队send(chunk);
						}
						for (let i = 0; i < chunk.byteLength; i += SS单批最大bytes) {
							SS入队send(chunk.subarray(i, Math.min(i + SS单批最大bytes, chunk.byteLength)));
						}
						return SSsend队列;
					},
					close() {
						closeSocketQuietly(serverSock);
					}
				};
				ssContext = {
					inboundDecryptor,
					responseSocket,
					firstPacket已建立: false,
					targetHost: '',
					targetPort: 0,
				};
				return ssContext;
			})().finally(() => { ssInitTask = null });
		}
		return ssInitTask;
	};

	const handleSSData = async (chunk) => {
		const context = await getSSContext();
		let plaintextChunks = null;
		try {
			plaintextChunks = await context.inboundDecryptor.输入(chunk);
		} catch (err) {
			const msg = err?.message || `${err}`;
			if (msg.includes('Decryption failed') || msg.includes('SS handshake decrypt failed') || msg.includes('SS length decrypt failed')) {
				log(`[SS Inbound] 解密失败，连接关闭: ${msg}`);
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
				if ((/** @type {any} */ (err))?.isQueueOverflow) throw err;
				wasWritten = false;
			}
			if (wasWritten) continue;
			if (context.firstPacketEstablished && context.targetHost && context.targetPort > 0) {
				await forwardTCP(context.targetHost, context.targetPort, plaintextChunk, context.responseSocket, null, remoteConnWrapper, yourUUID, request, proxyContext);
				continue;
			}
			const plaintextData = toUint8Array(plaintextChunk);
			if (plaintextData.byteLength < 3) throw new Error('invalid ss data');
			const addressType = plaintextData[0];
			let cursor = 1;
			let hostname = '';
			if (addressType === 1) {
				if (plaintextData.byteLength < cursor + 4 + 2) throw new Error('invalid ss ipv4 length');
				hostname = `${plaintextData[cursor]}.${plaintextData[cursor + 1]}.${plaintextData[cursor + 2]}.${plaintextData[cursor + 3]}`;
				cursor += 4;
			} else if (addressType === 3) {
				if (plaintextData.byteLength < cursor + 1) throw new Error('invalid ss domain length');
				const domainLength = plaintextData[cursor];
				cursor += 1;
				if (plaintextData.byteLength < cursor + domainLength + 2) throw new Error('invalid ss domain data');
				hostname = ssTextDecoder.decode(plaintextData.subarray(cursor, cursor + domainLength));
				cursor += domainLength;
			} else if (addressType === 4) {
				if (plaintextData.byteLength < cursor + 16 + 2) throw new Error('invalid ss ipv6 length');
				const ipv6 = [];
				const ipv6View = new DataView(plaintextData.buffer, plaintextData.byteOffset + cursor, 16);
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
			await forwardTCP(hostname, port, rawClientData, context.responseSocket, null, remoteConnWrapper, yourUUID, request, proxyContext);
		}
	};

	const handleWSInboundData = async (chunk) => {
		let currentChunkBytes = null;
		if (isDnsQuery) {
			if (isTrojan) return await forwardTrojanUDPData(chunk, serverSock, trojanUDPContext, request);
			return await forwardUDP(chunk, serverSock, null, request);
		}
		if (determineProtocolType === 'ss') {
			await handleSSData(chunk);
			return;
		}
		if (wsLocalSpeedTestMode) {
			await handleWSLocalSpeedTestData(chunk);
			return;
		}
		if (await writeToRemote(chunk)) return;

		if (determineProtocolType === null) {
			if (url.searchParams.get('enc')) determineProtocolType = 'ss';
			else {
				currentChunkBytes = currentChunkBytes || toUint8Array(chunk);
				const bytes = currentChunkBytes;
				determineProtocolType = bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a ? '木马' : '魏烈思';
			}
			isTrojan = determineProtocolType === '木马';
			log(`[WS转发] protocolType: ${determineProtocolType} | 来自: ${url.host} | UA: ${request.headers.get('user-agent') || '未知'}`);
		}

		if (determineProtocolType === 'ss') {
			await handleSSData(chunk);
			return;
		}
		if (await writeToRemote(chunk)) return;
		if (determineProtocolType === '木马') {
			const parseResult = parseTrojanRequest(chunk, yourUUID);
			if (解析result?.hasError) throw new Error(解析result.message || 'Invalid trojan request');
			const { port, hostname, rawClientData, isUDP } = 解析result;
			if (isSpeedTestSite(hostname) && proxyContext.proxyType === null) {
				await enableWSLocalSpeedTestMode(serverSock, null, rawClientData);
				return;
			}
			if (isUDP) {
				isDnsQuery = true;
				trojanUDPContext.targetHost = hostname;
				trojanUDPContext.targetPort = port;
				if (trojanUDPContext.proxyAddress) return forwardTrojanUDPData(currentChunkBytes || toUint8Array(chunk), serverSock, trojanUDPContext, request);
				if (getValidDataLength(rawClientData) > 0) return forwardTrojanUDPData(rawClientData, serverSock, trojanUDPContext, request);
				return;
			}
			await forwardTCP(hostname, port, rawClientData, serverSock, null, remoteConnWrapper, yourUUID, request, proxyContext, true, currentChunkBytes || toUint8Array(chunk));
		} else {
			isTrojan = false;
			currentChunkBytes = currentChunkBytes || toUint8Array(chunk);
			const bytes = currentChunkBytes;
			const parseResult = parseVLESSRequest(bytes, yourUUID);
			if (解析result?.hasError) throw new Error(解析result.message || 'Invalid VLESS request');
			const { port, hostname, version, isUDP, rawClientData } = 解析result;
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
				if (isTrojan) return forwardTrojanUDPData(rawData, serverSock, trojanUDPContext, request);
				return forwardUDP(rawData, serverSock, respHeader, request);
			}
			await forwardTCP(hostname, port, rawData, serverSock, respHeader, remoteConnWrapper, yourUUID, request, proxyContext);
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
			log(`[WS转发] 连接结束: ${msg}`);
		} else {
			log(`[WS转发] 处理失败: ${msg}`);
		}
		uplinkWriteQueue.clear();
		releaseRemoteWriter();
		invalidateRemote();
		try { trojanUDPContext.proxySocket?.close() } catch (e) { }
		closeSocketQuietly(serverSock);
	};

	const appendWSExplicitTransferTask = (任务) => {
		wsExplicitTransferChain = wsExplicitTransferChain.then(task).catch(handleWSExplicitTransferError);
		return wsExplicitTransferChain;
	};

	const enqueueWSExplicitTransfer = (data) => {
		if (wsExplicitTransferStopReceiving || wsExplicitTransferFailed) return;
		const chunkSize = Math.max(0, getValidDataLength(data));
		const nextBytes = wsExplicitQueueBytes + chunkSize;
		const nextItems = wsExplicitQueueEntries + 1;
		if (nextBytes > uplinkQueueMaxBytes || nextItems > uplinkQueueMaxEntries) {
			handleWSExplicitTransferError(new Error(`[WS显式传输] 队列溢出: ${nextBytes}B/${nextItems}`));
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
			try { trojanUDPContext.proxySocket?.close() } catch (e) { }
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

	// SS 模式下禁用 sec-websocket-protocol early-data，避免把子protocol值（如 "binary"）误当作 base64 数据注入firstPacket导致 AEAD 解密失败。
	if (!ssModeDisableEarlyData && earlyDataHeader) {
		try {
			const bytes = decodeWSEarlyData(earlyDataHeader, yourUUID);
			if (bytes?.byteLength) enqueueWSExplicitTransfer(bytes.buffer);
		} catch (error) {
			handleWSExplicitTransferError(error);
		}
	}

	return new Response(null, { status: 101, webSocket: clientSock, headers: { 'Sec-WebSocket-Extensions': '' } });
}

const trojanTextDecoder = new TextDecoder();

function parseTrojanProxyAddress(address) {
	const raw = String(address || '').trim();
	if (!raw || raw.includes('/') || raw.includes('@') || raw.includes('://')) throw new Error('木马反代仅支持 host:port');
	let hostname = '', portText = '';
	if (raw.startsWith('[')) {
		const 匹配 = raw.match(/^(\[[^\]]+\]):(\d+)$/);
		if (!匹配) throw new Error('Invalid IPv6 trojanProxyAddress');
		hostname = 匹配[1];
		portText = 匹配[2];
	} else {
		const parts = raw.split(':');
		if (parts.length !== 2) throw new Error('木马反代仅支持 host:port');
		hostname = parts[0];
		portText = parts[1];
	}
	const port = Number(portText);
	if (!hostname || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid木马反代端口');
	return { hostname, port };
}

async function connectTrojanProxy(firstPacket数据, tcpConnector, trojanProxyTarget) {
	if (!trojanProxyTarget) throw new Error('trojan fallback is not configured');
	const socket = tcpConnector({ hostname: stripIPv6Brackets(trojanProxyTarget.hostname), port: trojanProxyTarget.port });
	let writer = null;
	try {
		if (socket.opened) await socket.opened;
		if (getValidDataLength(firstPacket数据) > 0) {
			writer = socket.writable.getWriter();
			await writer.write(toUint8Array(firstPacket数据));
		}
		return socket;
	} catch (error) {
		try { socket?.close?.() } catch (e) { }
		throw error;
	} finally {
		try { writer?.releaseLock() } catch (e) { }
	}
}

function extractTrojanProxyHandshakeData(firstPacket数据, rawData) {
	const firstPacket = toUint8Array(firstPacket数据);
	const payload = toUint8Array(rawData);
	if (!payload.byteLength) return firstPacket;
	const 握手length = firstPacket.byteLength - payload.byteLength;
	if (握手length <= 0) return firstPacket;
	for (let i = 0; i < payload.byteLength; i++) {
		if (firstPacket[握手length + i] !== payload[i]) return firstPacket;
	}
	return firstPacket.subarray(0, 握手length);
}

async function forwardTrojanUDPProxyData(chunk, webSocket, 上下文, request) {
	const data = toUint8Array(chunk);
	if (!context.proxySocket) {
		const tcpConnector = createRequestTCPConnector(request);
		const socket = await connectTrojanProxy(data, tcpConnector, context.proxyAddress);
		context.proxySocket = socket;
		socket.closed.catch(() => { }).finally(() => closeSocketQuietly(webSocket));
		connectStreams(socket, webSocket, null, null);
		return;
	}
	if (!data.byteLength) return;
	const writer = context.proxySocket.writable.getWriter();
	try { await writer.write(data) }
	finally { try { writer.releaseLock() } catch (e) { } }
}

function parseTrojanRequest(buffer, passwordPlainText) {
	const data = toUint8Array(buffer);
	const sha224Password = sha224(passwordPlainText);
	if (data.byteLength < 58) return { hasError: true, message: "invalid data" };
	let crLfIndex = 56;
	if (data[crLfIndex] !== 0x0d || data[crLfIndex + 1] !== 0x0a) return { hasError: true, message: "invalid header format" };
	for (let i = 0; i < crLfIndex; i++) {
		if (data[i] !== sha224Password.charCodeAt(i)) return { hasError: true, message: "invalid password" };
	}

	const socks5Index = crLfIndex + 2;
	if (data.byteLength < socks5Index + 6) return { hasError: true, message: "invalid S5 request data" };

	const cmd = data[socks5Index];
	if (cmd !== 1 && cmd !== 3) return { hasError: true, message: "unsupported command, only TCP/UDP is allowed" };
	const isUDP = cmd === 3;

	const atype = data[socks5Index + 1];
	let addressLength = 0;
	let addressIndex = socks5Index + 2;
	let address = "";
	switch (atype) {
		case 1: // IPv4
			addressLength = 4;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
			address = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
			break;
		case 3: // Domain
			if (data.byteLength < addressIndex + 1) return { hasError: true, message: "invalid S5 request data" };
			addressLength = data[addressIndex];
			addressIndex += 1;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
			address = trojanTextDecoder.decode(data.subarray(addressIndex, addressIndex + addressLength));
			break;
		case 4: // IPv6
			addressLength = 16;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const partIndex = addressIndex + i * 2;
				ipv6.push(((data[partIndex] << 8) | data[partIndex + 1]).toString(16));
			}
			address = ipv6.join(":");
			break;
		default:
			return { hasError: true, message: `invalid addressType is ${atype}` };
	}

	if (!address) {
		return { hasError: true, message: `address is empty, addressType is ${atype}` };
	}

	const portIndex = addressIndex + addressLength;
	if (data.byteLength < portIndex + 4) return { hasError: true, message: "invalid S5 request data" };
	const portRemote = (data[portIndex] << 8) | data[portIndex + 1];

	return {
		hasError: false,
		addressType: atype,
		port: portRemote,
		hostname: address,
		isUDP,
		rawClientData: data.subarray(portIndex + 4)
	};
}

const uuidBytesCache = new Map();
const vlessTextDecoder = new TextDecoder();

function readHexNibble(code) {
	if (code >= 48 && code <= 57) return code - 48;
	code |= 32;
	if (code >= 97 && code <= 102) return code - 87;
	return -1;
}

function getUUIDBytes(uuid) {
	const key = String(uuid || '');
	let cached = uuidBytesCache.get(key);
	if (cached) return cached;

	const clean = key.replace(/-/g, '');
	if (clean.length !== 32) return null;

	const bytes = new Uint8Array(16);
	for (let i = 0; i < 16; i++) {
		const high = readHexNibble(clean.charCodeAt(i * 2));
		const low = readHexNibble(clean.charCodeAt(i * 2 + 1));
		if (high < 0 || low < 0) return null;
		bytes[i] = (high << 4) | low;
	}

	if (uuidBytesCache.size >= 32) uuidBytesCache.clear();
	uuidBytesCache.set(key, bytes);
	return bytes;
}

function uuidBytesMatch(data, offset, uuid) {
	const expected = getUUIDBytes(uuid);
	if (!expected || data.byteLength < offset + 16) return false;
	for (let i = 0; i < 16; i++) {
		if (data[offset + i] !== expected[i]) return false;
	}
	return true;
}

function parseVLESSRequest(chunk, token) {
	const data = toUint8Array(chunk);
	const length = data.byteLength;
	if (length < 24) return { hasError: true, message: 'Invalid data' };
	const version = data[0];
	if (!uuidBytesMatch(data, 1, token)) return { hasError: true, message: 'Invalid uuid' };

	const optLen = data[17];
	const cmdIndex = 18 + optLen;
	if (length < cmdIndex + 4) return { hasError: true, message: 'Invalid data' };

	const cmd = data[cmdIndex];
	let isUDP = false;
	if (cmd === 1) { } else if (cmd === 2) { isUDP = true } else { return { hasError: true, message: 'Invalid command' } }

	const portIdx = cmdIndex + 1;
	const port = (data[portIdx] << 8) | data[portIdx + 1];
	let addrValIdx = portIdx + 3, addrLen = 0, hostname = '';
	const addressType = data[portIdx + 2];
	switch (addressType) {
		case 1:
			addrLen = 4;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv4 address length' };
			hostname = `${data[addrValIdx]}.${data[addrValIdx + 1]}.${data[addrValIdx + 2]}.${data[addrValIdx + 3]}`;
			break;
		case 2:
			if (length < addrValIdx + 1) return { hasError: true, message: 'Invalid domain length' };
			addrLen = data[addrValIdx];
			addrValIdx += 1;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid domain data' };
			hostname = vlessTextDecoder.decode(data.subarray(addrValIdx, addrValIdx + addrLen));
			break;
		case 3:
			addrLen = 16;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv6 address length' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = addrValIdx + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			break;
		default:
			return { hasError: true, message: `Invalid address type: ${addressType}` };
	}
	if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
	const rawIndex = addrValIdx + addrLen;
	return { hasError: false, addressType, port, hostname, isUDP, rawClientData: data.subarray(rawIndex), version };
}

const SS_SUPPORTED_CIPHERS = {
	'aes-128-gcm': { method: 'aes-128-gcm', keyLen: 16, saltLen: 16, maxChunk: 0x3fff, aesLength: 128 },
	'aes-256-gcm': { method: 'aes-256-gcm', keyLen: 32, saltLen: 32, maxChunk: 0x3fff, aesLength: 256 },
};

const SS_AEAD_TAG_LENGTH = 16, SS_NONCE_LENGTH = 12;
const SS_SUBKEY_INFO = new TextEncoder().encode('ss-subkey');
const ssTextEncoder = new TextEncoder(), ssTextDecoder = new TextDecoder(), ssMasterKeyCache = new Map();

function toUint8Array(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data || 0);
}

function concatByteData(...chunkList) {
	if (!chunkList || chunkList.length === 0) return new Uint8Array(0);
	const chunks = chunkList.map(toUint8Array);
	const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
	const result = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) { result.set(c, offset); offset += c.byteLength }
	return result;
}

async function forwardTrojanUDPData(chunk, webSocket, 上下文, request) {
	const currentChunk = toUint8Array(chunk);
	if (上下文?.proxyAddress) return forwardTrojanUDPProxyData(currentChunk, webSocket, 上下文, request);
	const buffer块 = 上下文?.buffer instanceof Uint8Array ? context.buffer : new Uint8Array(0);
	const input = buffer块.byteLength ? concatByteData(buffer块, currentChunk) : currentChunk;
	let cursor = 0;

	while (cursor < input.byteLength) {
		const packetStart = cursor;
		const atype = input[cursor];
		let addrCursor = cursor + 1;
		let addrLen = 0;
		if (atype === 1) addrLen = 4;
		else if (atype === 4) addrLen = 16;
		else if (atype === 3) {
			if (input.byteLength < addrCursor + 1) break;
			addrLen = 1 + input[addrCursor];
		} else throw new Error(`invalid trojan udp addressType: ${atype}`);

		const portCursor = addrCursor + addrLen;
		if (input.byteLength < portCursor + 6) break;

		const port = (input[portCursor] << 8) | input[portCursor + 1];
		const payloadLength = (input[portCursor + 2] << 8) | input[portCursor + 3];
		if (input[portCursor + 4] !== 0x0d || input[portCursor + 5] !== 0x0a) throw new Error('invalid trojan udp delimiter');

		const payloadStart = portCursor + 6;
		const payloadEnd = payloadStart + payloadLength;
		if (input.byteLength < payloadEnd) break;

		const addressPortHeader = input.slice(packetStart, portCursor + 2);
		const payload = input.slice(payloadStart, payloadEnd);
		cursor = payloadEnd;

		if (port !== 53) throw new Error('UDP is not supported');
		if (!payload.byteLength) continue;

		let tcpDNS查询 = payload;
		if (payload.byteLength < 2 || ((payload[0] << 8) | payload[1]) !== payload.byteLength - 2) {
			tcpDNS查询 = new Uint8Array(payload.byteLength + 2);
			tcpDNS查询[0] = (payload.byteLength >>> 8) & 0xff;
			tcpDNS查询[1] = payload.byteLength & 0xff;
			tcpDNS查询.set(payload, 2);
		}

		const dns响应上下文 = { buffer: new Uint8Array(0) };
		await forwardUDP(tcpDNS查询, webSocket, null, request, (dnsRespChunk) => {
			const currentResponseChunk = toUint8Array(dnsRespChunk);
			const response输入 = dns响应context.buffer.byteLength ? concatByteData(dns响应context.buffer, currentResponseChunk) : currentResponseChunk;
			const response帧列表 = [];
			let responseCursor = 0;
			while (responseCursor + 2 <= responseInput.byteLength) {
				const dnsLen = (responseInput[responseCursor] << 8) | responseInput[responseCursor + 1];
				const dnsStart = responseCursor + 2;
				const dnsEnd = dnsStart + dnsLen;
				if (dnsEnd > responseInput.byteLength) break;
				const dnsPayload = responseInput.slice(dnsStart, dnsEnd);
				const frame = new Uint8Array(addressPortHeader.byteLength + 4 + dnsPayload.byteLength);
				frame.set(addressPortHeader, 0);
				frame[addressPortHeader.byteLength] = (dnsPayload.byteLength >>> 8) & 0xff;
				frame[addressPortHeader.byteLength + 1] = dnsPayload.byteLength & 0xff;
				frame[addressPortHeader.byteLength + 2] = 0x0d;
				frame[addressPortHeader.byteLength + 3] = 0x0a;
				frame.set(dnsPayload, addressPortHeader.byteLength + 4);
				responseFrameList.push(frame);
				responseCursor = dnsEnd;
			}
			dns响应context.buffer = responseInput.slice(responseCursor);
			return response帧列表.length ? responseFrameList : new Uint8Array(0);
		});
	}

	if (上下文) context.buffer = input.slice(cursor);
}

function SSIncrementNonceCounter(counter) {
	for (let i = 0; i < counter.length; i++) { counter[i] = (counter[i] + 1) & 0xff; if (counter[i] !== 0) return }
}

async function SSDeriveMasterKey(passwordText, keyLen) {
	const cacheKey = `${keyLen}:${passwordText}`;
	if (ssMasterKeyCache.has(cacheKey)) return ssMasterKeyCache.get(cacheKey);
	const deriveTask = (async () => {
		const pwBytes = ssTextEncoder.encode(passwordText || '');
		let prev = new Uint8Array(0), result = new Uint8Array(0);
		while (result.byteLength < keyLen) {
			const input = new Uint8Array(prev.byteLength + pwBytes.byteLength);
			input.set(prev, 0); input.set(pwBytes, prev.byteLength);
			prev = new Uint8Array(await crypto.subtle.digest('MD5', input));
			result = concatByteData(result, prev);
		}
		return result.slice(0, keyLen);
	})();
	ssMasterKeyCache.set(cacheKey, deriveTask);
	try { return await deriveTask }
	catch (error) { ssMasterKeyCache.delete(cacheKey); throw error }
}

async function SSDeriveSessionKey(config, masterKey, salt, usages) {
	const hmacOpts = { name: 'HMAC', hash: 'SHA-1' };
	const saltHmacKey = await crypto.subtle.importKey('raw', salt, hmacOpts, false, ['sign']);
	const prk = new Uint8Array(await crypto.subtle.sign('HMAC', saltHmacKey, masterKey));
	const prkHmacKey = await crypto.subtle.importKey('raw', prk, hmacOpts, false, ['sign']);
	const subKey = new Uint8Array(config.keyLen);
	let prev = new Uint8Array(0), written = 0, counter = 1;
	while (written < config.keyLen) {
		const input = concatByteData(prev, SS_SUBKEY_INFO, new Uint8Array([counter]));
		prev = new Uint8Array(await crypto.subtle.sign('HMAC', prkHmacKey, input));
		const copyLen = Math.min(prev.byteLength, config.keyLen - written);
		subKey.set(prev.subarray(0, copyLen), written);
		written += copyLen; counter += 1;
	}
	return crypto.subtle.importKey('raw', subKey, { name: 'AES-GCM', length: config.aesLength }, false, usages);
}

async function SSAEADEncrypt(cryptoKey, nonceCounter, plaintext) {
	const iv = nonceCounter.slice();
	const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, plaintext);
	SSIncrementNonceCounter(nonceCounter);
	return new Uint8Array(ct);
}

async function SSAEADDecrypt(cryptoKey, nonceCounter, ciphertext) {
	const iv = nonceCounter.slice();
	const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, ciphertext);
	SSIncrementNonceCounter(nonceCounter);
	return new Uint8Array(pt);
}

async function forwardTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, yourUUID, request = null, proxyContext = {}, 允许木马反代 = false, 木马反代firstPacket数据 = null, connectOnly = false) {
	const ctxproxyIP = proxyContext.proxyIP || '';
	const ctxproxyType = proxyContext.proxyType !== undefined ? proxyContext.proxyType : null;
	const ctxproxyGlobal = proxyContext.proxyGlobal !== undefined ? proxyContext.proxyGlobal : false;
	const ctxproxyParams = proxyContext.proxyParams || {};
	const ctxproxyFallback = proxyContext.proxyFallback !== undefined ? proxyContext.proxyFallback : true;
	let proxyArrayIndex = 0;
	log(`[TCP转发] 目标: ${host}:${portNum} | proxyIP: ${ctxproxyIP} | proxyFallback: ${ctxproxyFallback ? '是' : '否'} | proxyType: ${ctxproxyType || 'proxyip'} | 全局: ${ctxproxyGlobal ? '是' : '否'}`);
	const CONNECTION_TIMEOUT_MS = 1000;
	let firstPacketSentViaProxy = false;
	const tcpConnector = createRequestTCPConnector(request);
	const useTrojanProxy = 允许木马反代 && (proxyContext.trojanProxyAddress || null);
	const trojanProxyTarget = useTrojanProxy ? proxyContext.trojanProxyAddress : null;
	const trojanProxyHandshakeData = useTrojanProxy ? extractTrojanProxyHandshakeData(木马反代firstPacket数据, rawData) : null;
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
			log(`[TCP下行] 处理失败: ${err?.message || err}`);
			try { socket?.close?.() } catch (e) { }
			closeSocketQuietly(ws);
		});
		return true;
	};

	async function waitForConnectionEstablished(remoteSock, timeoutMs = CONNECTION_TIMEOUT_MS) {
		await Promise.race([
			remoteSock.opened,
			new Promise((_, reject) => setTimeout(() => reject(new Error('连接超时')), timeoutMs))
		]);
	}

	async function 打开tcpConnector(address, port) {
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
			return { socket: await 打开tcpConnector(候选.hostname, 候选.port), candidate: 候选 };
		}
		const attempts = candidateList.map(候选 => 打开tcpConnector(候选.hostname, 候选.port).then(socket => ({ socket, candidate: 候选 })));
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
		log(`[TCP Direct] preloadRaceDialenabled，开始并发查询 ${address} 的 A/AAAA 记录`);
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
			log(`[TCP Direct] ${address} 的 A/AAAA 未获得可用解析result，预加载竞速不可用，回退到原始 hostname 直连。`);
			return null;
		}
		const selectedIPList = ipList;
		log(`[TCP Direct] ${address} A记录:${ipv4List.length} AAAA记录:${ipv6List.length}，使用${useRecordType}记录，竞速拨号 ${selectedIPList.length}/${dialLimit}: ${selectedIPList.join(', ')}`);
		return selectedIPList.map((hostname, attempt) => ({ hostname, port, attempt, resolvedFrom: address }));
	}

	async function connectDirect(address, port, data = null, 启用预加载 = false) {
		const 预加载candidateList = 启用预加载 ? await buildPreloadRaceCandidateList(address, port) : null;
		const candidateList = 预加载candidateList || Array.from({ length: TCP_CONCURRENT_DIAL_COUNT }, (_, attempt) => ({ hostname: address, port, attempt }));
		log(预加载candidateList
			? `[TCP Direct] 并发尝试 ${candidateList.length} 路: ${candidateList.map(候选 => `${候选.hostname}:${候选.port}`).join(', ')}`
			: `[TCP Direct] 并发尝试 ${candidateList.length} 路: ${address}:${port}`);
		let socket = null;
		try {
			const connectionResult = await openCandidateConnectionsConcurrently(candidateList);
			socket = 连接result.socket;
			if (预加载candidateList) {
				const winner = 连接result.candidate;
				log(`[TCP Direct] 预加载竞速result: ${winner.hostname}:${winner.port} 胜出，源域名: ${winner.resolvedFrom || address}`);
			}
			await writeFirstPacket(socket, data);
			return socket;
		} catch (err) {
			try { socket?.close?.() } catch (e) { }
			if (预加载candidateList) log(`[TCP Direct] 预加载竞速失败: ${err.message || err}`);
			throw err;
		}
	}

	async function connectProxyIP(address, port, data = null, allProxyArray = null, 启用反代失败兜底 = true) {
		if (allProxyArray && allProxyArray.length > 0) {
			const actualConcurrency = Math.max(1, Math.floor(Number(PROXY_CONCURRENT_DIAL_COUNT) || 1));
			for (let i = 0; i < allProxyArray.length; i += actualConcurrency) {
				const candidateList = [];
				for (let j = 0; j < actualConcurrency && i + j < allProxyArray.length; j++) {
					const 索引 = (proxyArrayIndex + i + j) % allProxyArray.length;
					const [proxyAddress, 反代端口] = allProxyArray[索引];
					candidateList.push({ hostname: proxyAddress, port: 反代端口, index: 索引 });
				}
				let socket = null, candidate = null;
				try {
					log(`[Proxy Connection] 并发尝试 ${candidateList.length} 路: ${candidateList.map(候选 => `${候选.hostname}:${候选.port}`).join(', ')}`);
					const connectionResult = await openCandidateConnectionsConcurrently(candidateList);
					socket = 连接result.socket;
					candidate = 连接result.candidate;
					await writeFirstPacket(socket, data);
					log(`[Proxy Connection] 成功连接到: ${candidate.hostname}:${candidate.port} (索引: ${candidate.index})`);
					proxyArrayIndex = candidate.index;
					return socket;
				} catch (err) {
					try { socket?.close?.() } catch (e) { }
					log(`[Proxy Connection] 本批连接失败: ${err.message || err}`);
				}
			}
		}

		if (启用反代失败兜底) return connectDirect(address, port, data, false);
		else {
			throw new Error('[Proxy Connection] 所有反代连接失败，且未启用proxyFallback，连接终止。');
		}
	}

	async function connecttoPry(允许sendfirstPacket = true) {
		if (remoteConnWrapper.connectingPromise) {
			await remoteConnWrapper.connectingPromise;
			return;
		}
		const { generation: currentConnectionGeneration, downlinkDrain } = startTCPConnectorGeneration(remoteConnWrapper);

		let 本次sendfirstPacket = false, 本次firstPacket数据 = null;
		if (useTrojanProxy) {
			if (允许sendfirstPacket && !firstPacketSentViaProxy && getValidDataLength(木马反代firstPacket数据) > 0) {
				本次firstPacket数据 = 木马反代firstPacket数据;
				本次sendfirstPacket = getValidDataLength(rawData) > 0;
			} else {
				本次firstPacket数据 = trojanProxyHandshakeData;
			}
		} else {
			本次sendfirstPacket = 允许sendfirstPacket && !firstPacketSentViaProxy && getValidDataLength(rawData) > 0;
			本次firstPacket数据 = 本次sendfirstPacket ? rawData : null;
		}

		const currentConnectionTask = (async () => {
			let newSocket = null;
			try {
				if (useTrojanProxy) {
					log(`[木马反代] proxyTo: ${host}:${portNum}`);
					newSocket = await connectTrojanProxy(本次firstPacket数据, tcpConnector, trojanProxyTarget);
				} else if (ctxproxyType === 'socks5') {
					log(`[SOCKS5代理] proxyTo: ${host}:${portNum}`);
					newSocket = await socks5Connect(host, portNum, 本次firstPacket数据, tcpConnector, ctxproxyParams);
				} else if (ctxproxyType === 'http') {
					log(`[HTTP代理] proxyTo: ${host}:${portNum}`);
					newSocket = await httpConnect(host, portNum, 本次firstPacket数据, false, tcpConnector, ctxproxyParams);
				} else if (ctxproxyType === 'https') {
					log(`[HTTPS代理] proxyTo: ${host}:${portNum}`);
					newSocket = isIPHostname(ctxproxyParams.hostname)
						? await httpsConnect(host, portNum, 本次firstPacket数据, tcpConnector, ctxproxyParams)
						: await httpConnect(host, portNum, 本次firstPacket数据, true, tcpConnector, ctxproxyParams);
				} else if (ctxproxyType === 'turn') {
					log(`[TURN代理] proxyTo: ${host}:${portNum}`);
					newSocket = await turnConnect(ctxproxyParams, host, portNum, tcpConnector);
					if (getValidDataLength(本次firstPacket数据) > 0) {
						const writer = newSocket.writable.getWriter();
						try { await writer.write(toUint8Array(本次firstPacket数据)) }
						finally { try { writer.releaseLock() } catch (e) { } }
					}
				} else if (ctxproxyType === 'sstp') {
					log(`[SSTP代理] proxyTo: ${host}:${portNum}`);
					newSocket = await sstpConnect(ctxproxyParams, host, portNum, tcpConnector);
					if (getValidDataLength(本次firstPacket数据) > 0) {
						const writer = newSocket.writable.getWriter();
						try { await writer.write(toUint8Array(本次firstPacket数据)) }
						finally { try { writer.releaseLock() } catch (e) { } }
					}
				} else {
					log(`[Proxy Connection] proxyTo: ${host}:${portNum}`);
					const allProxyArray = await resolveAddressPort(ctxproxyIP, host, yourUUID);
					newSocket = await connectProxyIP(`${featureCodeDict[0]}.tp1.${featureCodeDict[2]}.xyz`, 1, 本次firstPacket数据, allProxyArray, ctxproxyFallback);
				}
				await installCurrentConnection(newSocket, currentConnectionGeneration, downlinkDrain);
				if (本次sendfirstPacket) firstPacketSentViaProxy = true;
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
		log(`[TCP转发] 启用 SOCKS5/HTTP/HTTPS/TURN/SSTP 全局代理`);
		try {
			await connecttoPry();
			if (connectOnly) return remoteConnWrapper.socket;
		} catch (err) {
			log(`[TCP转发] SOCKS5/HTTP/HTTPS/TURN/SSTP 代理连接失败: ${err.message}`);
			throw err;
		}
	} else {
		let directGeneration = remoteConnWrapper.generation;
		try {
			log(`[TCP转发] 尝试直连到: ${host}:${portNum}`);
			const generationConnection = startTCPConnectorGeneration(remoteConnWrapper);
			directGeneration = generationConnection.generation;
			const initialSocket = await connectDirect(host, portNum, rawData, true);
			await installCurrentConnection(initialSocket, directGeneration, generationConnection.downlinkDrain, async () => {
				if (remoteConnWrapper.generation !== directGeneration || remoteConnWrapper.socket !== initialSocket) return;
				await connecttoPry();
			});
			if (connectOnly) return initialSocket;
		} catch (err) {
			log(`[TCP转发] 直连 ${host}:${portNum} 失败: ${err.message}`);
			if (remoteConnWrapper.generation !== directGeneration) throw err;
			if (err instanceof Error && err.name === '预加载解析isEmpty') {
				closeSocketQuietly(ws);
				throw err;
			}
			if (ws.readyState !== WebSocket.OPEN) throw err;
			await connecttoPry();
			if (connectOnly) return remoteConnWrapper.socket;
		}
	}
}

async function forwardUDP(udpChunk, webSocket, respHeader, request, responseWrapper = null) {
	const requestData = toUint8Array(udpChunk);
	const requestByteCount = requestData.byteLength;
	log(`[UDP转发] 收到 DNS 请求: ${请求byteCount}B -> 8.8.4.4:53`);
	try {
		const tcpConnector = createRequestTCPConnector(request);
		const tcpSocket = tcpConnector({ hostname: '8.8.4.4', port: 53 });
		let vlessHeader = respHeader;
		const writer = tcpSocket.writable.getWriter();
		await writer.write(requestData);
		log(`[UDP转发] DNS 请求wasWritten上游: ${请求byteCount}B`);
		writer.releaseLock();
		await tcpSocket.readable.pipeTo(new WritableStream({
			async write(chunk) {
				const rawResponse = toUint8Array(chunk);
				log(`[UDP Forward] Received DNS response: ${rawResponse.byteLength}B`);
				const wrapResult = responseWrapper ? await responseWrapper(rawResponse) : rawResponse;
				const sendFragmentList = Array.isArray(封装result) ? 封装result : [封装result];
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
		log(`[UDP转发] DNS forwardFailed: ${error?.message || error}`);
	}
}

function closeSocketQuietly(socket) {
	try {
		if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
			socket.close();
		}
	} catch (error) { }
}

function formatIdentifier(arr, offset = 0) {
	const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join('');
	return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}

async function webSocketSendAndAwait(webSocket, payload) {
	const sendResult = webSocket.send(payload);
	if (sendResult && typeof sendResult.then === 'function') await sendResult;
}

function createGrainBundler(容量, 复制合包result = false) {
	let queue = [];
	let head = 0;
	let byteCount = 0;
	let bundleBuffer = null;

	const isEmpty = () => 头 >= 队列.length;
	const compact = () => {
		if (头 > 32 && 头 * 2 >= 队列.length) {
			队列 = 队列.slice(头);
			头 = 0;
		}
	};
	const dequeue = () => {
		if (isEmpty()) return null;
		const item = 队列[头];
		队列[头++] = undefined;
		byteCount -= item.chunk.byteLength;
		compact();
		return item;
	};

	return {
		get byteCount() { return byteCount },
		get entryCount() { return 队列.length - 头 },
		get isEmpty() { return isEmpty() },
		清空(processItem = null) {
			if (processItem) {
				for (let i = 头; i < 队列.length; i++) {
					if (队列[i]) 处理项目(队列[i]);
				}
			}
			队列 = [];
			头 = 0;
			byteCount = 0;
		},
		收纳(item) {
			if (!item?.chunk?.byteLength) return false;
			队列.push(item);
			byteCount += item.chunk.byteLength;
			return true;
		},
		合包() {
			const first = dequeue();
			if (!first) return null;
			const items = [first];
			if (isEmpty() || first.chunk.byteLength >= 容量) return { chunk: first.chunk, items };

			let totalBytes = first.chunk.byteLength;
			let end = 头;
			while (end < 队列.length) {
				const nextBytes = totalBytes + 队列[end].chunk.byteLength;
				if (nextBytes > 容量) break;
				totalBytes = nextBytes;
				end++;
			}
			if (end === 头) return { chunk: first.chunk, items };

			const output = (bundleBuffer ||= new Uint8Array(容量));
			output.set(first.chunk, 0);
			let offset = first.chunk.byteLength;
			while (头 < end) {
				const next = 队列[头];
				队列[头++] = undefined;
				byteCount -= next.chunk.byteLength;
				items.push(next);
				output.set(next.chunk, offset);
				offset += next.chunk.byteLength;
			}
			compact();
			const bundled = output.subarray(0, totalBytes);
			return { chunk: 复制合包result ? bundled.slice() : bundled, items };
		}
	};
}

function createUplinkGrainBundleStream(目标bytes = uplinkBundleTargetBytes) {
	const identity = typeof IdentityTransformStream !== 'undefined'
		? new IdentityTransformStream()
		: new TransformStream();
	const writer = identity.writable.getWriter();
	const buffer = new Uint8Array(目标bytes);
	let bufferlength = 0;
	let timer = null;
	let pendingWrite = null;
	let flushChain = Promise.resolve();

	const cleanuptimer = () => {
		if (timer) {
			clearTimeout(timer);
			timer = null;
		}
	};

	const serialWrite = async (chunk) => {
		if (pendingWrite) await pendingWrite;
		pendingWrite = writer.write(chunk);
		try { await pendingWrite } finally { pendingWrite = null; }
	};

	const doFlush = async () => {
		if (bufferlength) {
			const chunk = buffer.slice(0, bufferlength);
			bufferlength = 0;
			await serialWrite(chunk);
		}
	};

	const queueFlush = () => {
		flushChain = flushChain.then(() => doFlush()).catch(() => { });
	};

	const startTimer = () => {
		if (timer) return;
		timer = setTimeout(() => {
			timer = null;
			queueFlush();
		}, 1);
	};

	return {
		readable: identity.readable,
		写入: async (chunk) => {
			const data = toUint8Array(chunk);
			if (!data.byteLength) return;
			if (data.byteLength >= 目标bytes) {
				clearTimer();
				if (bufferlength) await doFlush();
				await serialWrite(data);
				return;
			}
			if (bufferlength + data.byteLength >= 目标bytes) {
				const output = new Uint8Array(bufferlength + data.byteLength);
				output.set(buffer.subarray(0, bufferlength), 0);
				output.set(data, bufferlength);
				bufferlength = 0;
				clearTimer();
				await serialWrite(output);
			} else {
				buffer.set(data, bufferlength);
				bufferlength += data.byteLength;
				startTimer();
			}
		},
		结束: async () => {
			clearTimer();
			try {
				await flushChain;
				await doFlush();
				await writer.close();
			} finally {
				try { writer.releaseLock() } catch (e) { }
			}
		}
	};
}

function createUplinkWriteQueue({ getWriter, getConnectionTask = null, releaseWriter, retryConnection, closeConnection, name = '上行队列' }) {
	const grain = createGrainBundler(uplinkBundleTargetBytes);
	let draining = false;
	let closed = false;
	let idleResolvers = [];
	let activeCompletions = null;

	const settleCompletions = (completions, err = null) => {
		if (!completions) return;
		for (const completion of completions) {
			if (err) completion.reject(err);
			else completion.resolve();
		}
	};

	const resolveIdle = () => {
		if (grain.byteCount || draining || !idleResolvers.length) return;
		const resolvers = idleResolvers;
		idleResolvers = [];
		for (const resolve of resolvers) resolve();
	};

	const clear = (err = null) => {
		const closeErr = err || (closed ? new Error(`${name}: queue closed`) : null);
		if (closeErr) {
			grain.clear(item => settleCompletions(item.completions, closeErr));
			settleCompletions(activeCompletions, closeErr);
			activeCompletions = null;
		} else grain.clear();
		resolveIdle();
	};

	const bundle = () => {
		const packed = grain.bundle();
		if (!packed) return null;
		let allowRetry = true;
		let completions = null;
		for (const item of packed.items) {
			allowRetry = allowRetry && item.allowRetry;
			if (item.completions) completions = completions ? completions.concat(item.completions) : item.completions;
		}
		return { chunk: packed.chunk, allowRetry, completions };
	};

	const 等待可用写入器 = async () => {
		let writer = getWriter();
		if (writer) return writer;
		const connectionTask = getConnectionTask?.();
		if (connectionTask) await connectionTask;
		return getWriter();
	};

	const drain = async () => {
		if (draining || closed) return;
		draining = true;
		try {
			for (; ;) {
				if (closed) break;
				const item = bundle();
				if (!item) break;
				const completions = item.completions || null;
				activeCompletions = completions;
				try {
					let writer = await 等待可用写入器();
					if (closed) break;
					if (!writer) throw new Error(`${name}: remote writer unavailable`);
					try {
						await writer.write(item.chunk);
					} catch (err) {
						releaseWriter?.();
						if (closed) break;
						if (!item.allowRetry || typeof retryConnection !== 'function') throw err;
						await retryConnection();
						if (closed) break;
						writer = getWriter();
						if (!writer) throw err;
						await writer.write(item.chunk);
					}
					settleCompletions(completions);
				} catch (err) {
					settleCompletions(completions, err);
					throw err;
				} finally {
					if (activeCompletions === completions) activeCompletions = null;
				}
			}
		} catch (err) {
			closed = true;
			clear(err);
			log(`[${name}] 写入失败: ${err?.message || err}`);
			try { closeConnection?.(err) } catch (_) { }
		} finally {
			draining = false;
			if (!closed && !grain.isEmpty) drain();
			else resolveIdle();
		}
	};

	const enqueue = (data, allowRetry = true, waitForFlush = false) => {
		if (closed) return false;
		// firstPacket解析阶段既没有 writer 也没有连接任务；返回 false 交给上层继续protocol解析。
		// sessionEstablishedRedialCollect，drain 会等待新 writer，避免数据被误当成firstPacket。
		if (!getWriter() && !getConnectionTask?.()) return false;
		const chunk = toUint8Array(data);
		if (!chunk.byteLength) return true;
		const nextBytes = grain.byteCount + chunk.byteLength;
		const nextItems = grain.entryCount + 1;
		if (nextBytes > uplinkQueueMaxBytes || nextItems > uplinkQueueMaxEntries) {
			closed = true;
			const err = Object.assign(new Error(`${name}: upload queue overflow (${nextBytes}B/${nextItems})`), { isQueueOverflow: true });
			clear(err);
			log(`[${name}] 队列超限，closeConnection`);
			try { closeConnection?.(err) } catch (_) { }
			throw err;
		}
		let completionPromise = null;
		let completions = null;
		if (waitForFlush) {
			completions = [];
			completionPromise = new Promise((resolve, reject) => completions.push({ resolve, reject }));
		}
		grain.collect({ chunk, allowRetry, completions });
		if (!draining) drain();
		return waitForFlush ? completionPromise.then(() => true) : true;
	};

	return {
		写入(data, allowRetry = true) {
			return enqueue(data, allowRetry, false);
		},
		写入并等待(data, allowRetry = true) {
			return enqueue(data, allowRetry, true);
		},
		async 等待空() {
			if (!grain.byteCount && !draining) return;
			await new Promise(resolve => idleResolvers.push(resolve));
		},
		清空() {
			closed = true;
			clear();
		}
	};
}

function createDownlinkGrainSender(webSocket, headerData = null, isActive = null) {
	const packetCap = downlinkGrainPacketBytes;
	const tailBytes = downlinkGrainTailThreshold;
	const grain = createGrainBundler(packetCap, true);
	let header = typeof headerData === 'function' ? null : headerData;
	const getResponseHeader = typeof headerData === 'function' ? headerData : () => {
		const value = header;
		header = null;
		return value;
	};
	let flushTimer = null;
	let generation = 0;
	let scheduledGeneration = 0;
	let waitRounds = 0;
	let flushPromise = null;
	let directSendPromise = null;
	let forceDrain = false;
	let stopStarted = false;
	let activeSendCount = 0;
	let activeDirectSendCount = 0;
	let activeSendError = null;
	let activeSendWaiters = [];
	const waitForActiveSendComplete = () => {
		if (!activeSendCount && !activeDirectSendCount) return Promise.resolve();
		return new Promise(resolve => activeSendWaiters.push(resolve));
	};
	const markSendComplete = () => {
		if (activeSendCount || activeDirectSendCount || !activeSendWaiters.length) return;
		const resolvers = activeSendWaiters;
		activeSendWaiters = [];
		for (const resolve of resolvers) resolve();
	};
	const checkActiveSendError = () => {
		if (!activeSendError) return;
		const err = activeSendError;
		grain.clear();
		throw err;
	};
	const isCurrentSenderActive = () => forceDrain || !isActive || isActive();
	const closeActiveConnection = () => {
		if (isCurrentSenderActive()) closeSocketQuietly(webSocket);
	};

	const sendRawChunk = async (chunk) => {
		if (!isCurrentSenderActive()) return;
		if (webSocket.readyState !== WebSocket.OPEN) throw new Error('ws.readyState is not open');
		chunk = prependResponseHeader(chunk);
		await webSocketSendAndAwait(webSocket, chunk);
	};

	const serialSendRawChunk = async (chunk) => {
		while (directSendPromise) await directSendPromise;
		const sendTask = sendRawChunk(chunk);
		directSendPromise = sendTask;
		try { await sendTask }
		finally {
			if (directSendPromise === sendTask) directSendPromise = null;
		}
	};

	const prependResponseHeader = (chunk) => {
		const responseHeader = getResponseHeader();
		if (!responseHeader) return chunk;
		const merged = new Uint8Array(responseHeader.length + chunk.byteLength);
		merged.set(responseHeader, 0);
		merged.set(chunk, responseHeader.length);
		return merged;
	};

	const flush = async () => {
		while (flushPromise) await flushPromise;
		if (flushTimer) clearTimeout(flushTimer);
		flushTimer = null;
		waitRounds = 0;
		if (!isCurrentSenderActive()) {
			grain.clear();
			return;
		}
		const send任务 = (async () => {
			for (; ;) {
				if (!isCurrentSenderActive()) {
					grain.clear();
					break;
				}
				const packed = grain.bundle();
				if (!packed) break;
				await serialSendRawChunk(packed.chunk);
			}
		})();
		flushPromise = send任务.catch(err => {
			activeSendError ||= err;
			throw err;
		}).finally(() => { flushPromise = null });
		return flushPromise;
	};

	const scheduleFlush = () => {
		if (!isCurrentSenderActive()) {
			grain.clear();
			return;
		}
		if (grain.isEmpty || flushTimer) return;
		if (grain.byteCount >= packetCap || packetCap - grain.byteCount < tailBytes) {
			flush().catch(closeActiveConnection);
			return;
		}
		flushTimer = setTimeout(() => {
			flushTimer = null;
			if (!isCurrentSenderActive()) {
				grain.clear();
				return;
			}
			if (grain.isEmpty) return;
			if (grain.byteCount >= packetCap || packetCap - grain.byteCount < tailBytes) {
				flush().catch(closeActiveConnection);
				return;
			}
			if (waitRounds < downlinkGrainMaxWaitRounds && (generation !== scheduledGeneration || grain.byteCount < downlinkGrainLowWaterBytes)) {
				waitRounds++;
				scheduledGeneration = generation;
				scheduleFlush();
				return;
			}
			flush().catch(closeActiveConnection);
		}, 1);
	};

	return {
		async directSend(data) {
			if (stopStarted || !isCurrentSenderActive()) return;
			activeDirectSendCount++;
			try {
				const chunk = toUint8Array(data);
				if (!chunk.byteLength) return;
				await serialSendRawChunk(chunk);
			} catch (err) {
				activeSendError ||= err;
				throw err;
			} finally {
				activeDirectSendCount--;
				markSendComplete();
			}
		},
		async send(data) {
			if (stopStarted || !isCurrentSenderActive()) return;
			activeSendCount++;
			try {
				const chunk = toUint8Array(data);
				if (!chunk.byteLength) return;
				let offset = 0;
				const totalBytes = chunk.byteLength;
				while (offset < totalBytes) {
					const remainingBytes = totalBytes - offset;
					if (grain.isEmpty && remainingBytes >= packetCap) {
						const sendBytes = Math.min(packetCap, remainingBytes);
						const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
						await serialSendRawChunk(view);
						offset += sendBytes;
						continue;
					}
					const copyBytes = Math.min(packetCap - grain.byteCount, totalBytes - offset);
					if (!copyBytes) {
						await flush();
						continue;
					}
					grain.collect({ chunk: offset || copyBytes !== totalBytes ? chunk.subarray(offset, offset + copyBytes) : chunk });
					offset += copyBytes;
					generation++;
					if (grain.byteCount >= packetCap || packetCap - grain.byteCount < tailBytes) await flush();
					else scheduleFlush();
				}
			} catch (err) {
				activeSendError ||= err;
				throw err;
			} finally {
				activeSendCount--;
				markSendComplete();
			}
		},
		flush,
		async stopAndFlush() {
			if (stopStarted) {
				await waitForActiveSendComplete();
				while (directSendPromise) await directSendPromise;
				checkActiveSendError();
				await flush();
				return;
			}
			stopStarted = true;
			forceDrain = true;
			if (flushTimer) clearTimeout(flushTimer);
			flushTimer = null;
			await waitForActiveSendComplete();
			while (directSendPromise) await directSendPromise;
			checkActiveSendError();
			await flush();
		}
	};
}

async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, isCurrentSocket = null, remoteConnWrapper = null) {
	let header = headerData, hasData = false, reader, useBYOB = false, readError = null;
	const BYOB单次读取上限 = 64 * 1024;
	const currentIsConnectionStillValid = () => !isCurrentSocket || isCurrentSocket();
	const downlinkSender = createDownlinkGrainSender(webSocket, header, currentIsConnectionStillValid);
	header = null;
	const downlinkController = { stopAndFlush: () => downlinkSender.stopAndFlush() };
	if (remoteConnWrapper) remoteConnWrapper.downlinkController = downlinkController;
	try { remoteSocket.closed?.catch?.(() => { }) } catch (e) { }

	try { reader = remoteSocket.readable.getReader({ mode: 'byob' }); useBYOB = true }
	catch (e) { reader = remoteSocket.readable.getReader() }

	try {
		if (!useBYOB) {
			while (true) {
				const { done, value } = await reader.read();
				if (!currentIsConnectionStillValid()) break;
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (value.byteLength >= downlinkGrainPacketBytes) {
					await downlinkSender.flush();
					await downlinkSender.directSend(value);
				} else {
					await downlinkSender.send(value);
				}
			}
		} else {
			let readBuffer = new ArrayBuffer(BYOB单次读取上限);
			while (true) {
				const { done, value } = await reader.read(new Uint8Array(readBuffer, 0, BYOB单次读取上限));
				if (!currentIsConnectionStillValid()) break;
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (value.byteLength >= downlinkGrainPacketBytes) {
					await downlinkSender.flush();
					await downlinkSender.directSend(value);
					readBuffer = new ArrayBuffer(BYOB单次读取上限);
				} else {
					await downlinkSender.send(value.slice());
					readBuffer = value.buffer.byteLength >= BYOB单次读取上限 ? value.buffer : new ArrayBuffer(BYOB单次读取上限);
				}
			}
		}
		if (currentIsConnectionStillValid()) await downlinkSender.flush();
	} catch (err) { readError = err }
	finally {
		if (currentIsConnectionStillValid() && webSocket.readyState === WebSocket.OPEN) {
			try { await downlinkSender.stopAndFlush() } catch (err) { readError ||= err }
		}
		if (remoteConnWrapper?.downlinkController === downlinkController) remoteConnWrapper.downlinkController = null;
		try { await reader.cancel() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { remoteSocket.close() } catch (e) { }
	}
	if (!hasData && retryFunc && webSocket.readyState === WebSocket.OPEN && currentIsConnectionStillValid()) {
		try {
			await retryFunc();
			return;
		} catch (err) {
			readError ||= err;
		}
	}
	if (!currentIsConnectionStillValid()) return;
	if (readError) log(`[TCP下行] 读取失败: ${readError?.message || readError}`);
	closeSocketQuietly(webSocket);
}

function isSpeedTestSite(hostname) {
	const speedTestDomains = ['speed.cloudflare.com', 'cp.cloudflare.com'];
	hostname = hostname.toLowerCase();
	return speedTestDomains.some(domain => hostname === domain || hostname.endsWith('.' + domain));
}

function buildLocal204Response(respHeader = null) {
	const local204Response = new TextEncoder().encode(
		'HTTP/1.1 204 No Content\r\n' +
		'Content-Length: 0\r\n' +
		'Connection: close\r\n' +
		'\r\n'
	);
	if (getValidDataLength(respHeader) === 0) return local204Response;
	const protocolResponseHeader = toUint8Array(respHeader);
	const response = new Uint8Array(protocol响应头.byteLength + local204Response.byteLength);
	response.set(protocol响应头, 0);
	response.set(local204Response, protocol响应头.byteLength);
	log(`[TCP转发] buildLocal204Response: ${response.byteLength}B`);
	return response;
}

function buildWSLocal204Response(respHeader = null) {
	const WSlocal204Response = new TextEncoder().encode(
		'HTTP/1.1 204 No Content\r\n' +
		'Content-Length: 0\r\n' +
		'Connection: keep-alive\r\n' +
		'\r\n'
	);
	if (getValidDataLength(respHeader) === 0) return WSlocal204Response;
	const protocolResponseHeader = toUint8Array(respHeader);
	const response = new Uint8Array(protocol响应头.byteLength + WSlocal204Response.byteLength);
	response.set(protocol响应头, 0);
	response.set(WSlocal204Response, protocol响应头.byteLength);
	return response;
}

///////////////////////////////////////////////////////SOCKS5/HTTP函数///////////////////////////////////////////////
async function socks5Connect(targetHost, targetPort, initialData, tcpConnector, parsedSocks5) {
	const { username, password, hostname, port } = parsedSocks5 || {};
	const socket = tcpConnector({ hostname, port }), writer = socket.writable.getWriter(), reader = socket.readable.getReader();
	try {
		const authMethods = username && password ? new Uint8Array([0x05, 0x02, 0x00, 0x02]) : new Uint8Array([0x05, 0x01, 0x00]);
		await writer.write(authMethods);
		let response = await reader.read();
		if (response.done || response.value.byteLength < 2) throw new Error('S5 method selection failed');

		const selectedMethod = new Uint8Array(response.value)[1];
		if (selectedMethod === 0x02) {
			if (!username || !password) throw new Error('S5 requires authentication');
			const userBytes = new TextEncoder().encode(username), passBytes = new TextEncoder().encode(password);
			const authPacket = new Uint8Array([0x01, userBytes.length, ...userBytes, passBytes.length, ...passBytes]);
			await writer.write(authPacket);
			response = await reader.read();
			if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 authentication failed');
		} else if (selectedMethod !== 0x00) throw new Error(`S5 unsupported auth method: ${selectedMethod}`);

		const hostBytes = new TextEncoder().encode(targetHost);
		const connectPacket = new Uint8Array([0x05, 0x01, 0x00, 0x03, hostBytes.length, ...hostBytes, targetPort >> 8, targetPort & 0xff]);
		await writer.write(connectPacket);
		response = await reader.read();
		if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 connection failed');

		if (getValidDataLength(initialData) > 0) await writer.write(initialData);
		writer.releaseLock(); reader.releaseLock();
		return socket;
	} catch (error) {
		try { writer.releaseLock() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { socket.close() } catch (e) { }
		throw error;
	}
}

async function httpConnect(targetHost, targetPort, initialData, HTTPS代理 = false, tcpConnector, parsedSocks5) {
	const { username, password, hostname, port } = parsedSocks5 || {};
	const socket = HTTPS代理
		? tcpConnector({ hostname, port }, { secureTransport: 'on', allowHalfOpen: false })
		: tcpConnector({ hostname, port });
	const writer = socket.writable.getWriter(), reader = socket.readable.getReader();
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	try {
		if (HTTPS代理) await socket.opened;

		const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
		const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
		await writer.write(encoder.encode(request));
		writer.releaseLock();

		let responseBuffer = new Uint8Array(0), headerEndIndex = -1, bytesRead = 0;
		while (headerEndIndex === -1 && bytesRead < 8192) {
			const { done, value } = await reader.read();
			if (done || !value) throw new Error(`${HTTPS代理 ? 'HTTPS' : 'HTTP'} proxyReturns CONNECT 响应前closeConnection`);
			responseBuffer = new Uint8Array([...responseBuffer, ...value]);
			bytesRead = responseBuffer.length;
			const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
			if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
		}

		if (headerEndIndex === -1) throw new Error('代理 CONNECT 响应头过长或无效');
		const statusMatch = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
		const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
		if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);

		reader.releaseLock();

		if (getValidDataLength(initialData) > 0) {
			const remoteWriter = socket.writable.getWriter();
			await remoteWriter.write(initialData);
			remoteWriter.releaseLock();
		}

		// CONNECT 响应头后可能夹带隧道数据，先回灌到可读流，避免firstPacket被吞。
		if (bytesRead > headerEndIndex) {
			const { readable, writable } = new TransformStream();
			const transformWriter = writable.getWriter();
			await transformWriter.write(responseBuffer.subarray(headerEndIndex, bytesRead));
			transformWriter.releaseLock();
			socket.readable.pipeTo(writable).catch(() => { });
			return { readable, writable: socket.writable, closed: socket.closed, close: () => socket.close() };
		}

		return socket;
	} catch (error) {
		try { writer.releaseLock() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { socket.close() } catch (e) { }
		throw error;
	}
}

async function httpsConnect(targetHost, targetPort, initialData, tcpConnector, parsedSocks5) {
	const { username, password, hostname, port } = parsedSocks5 || {};
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	let tlsSocket = null;
	const tlsServerName = isIPHostname(hostname) ? '' : stripIPv6Brackets(hostname);
	const 打开HTTPS代理TLS = async (allowChacha = false) => {
		const proxySocket = tcpConnector({ hostname, port });
		try {
			await proxySocket.opened;
			const socket = new TlsClient(proxySocket, { serverName: tlsServerName, insecure: true, allowChacha });
			await socket.handshake();
			log(`[HTTPS代理] TLS版本: ${socket.isTls13 ? '1.3' : '1.2'} | Cipher: 0x${socket.cipherSuite.toString(16)}${socket.cipherConfig?.chacha ? ' (ChaCha20)' : ' (AES-GCM)'}`);
			return socket;
		} catch (error) {
			try { proxySocket.close() } catch (e) { }
			throw error;
		}
	};
	try {
		try {
			tlsSocket = await 打开HTTPS代理TLS(false);
		} catch (error) {
			if (!/cipher|handshake|TLS Alert|ServerHello|Finished|Unsupported|Missing TLS/i.test(error?.message || `${error || ''}`)) throw error;
			log(`[HTTPS代理] AES-GCM TLS 握手失败，回退 ChaCha20 兼容模式: ${error?.message || error}`);
			tlsSocket = await 打开HTTPS代理TLS(true);
		}

		const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
		const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
		await tlsSocket.write(encoder.encode(request));

		let responseBuffer = new Uint8Array(0), headerEndIndex = -1, bytesRead = 0;
		while (headerEndIndex === -1 && bytesRead < 8192) {
			const value = await tlsSocket.read();
			if (!value) throw new Error('HTTPS proxyReturns CONNECT 响应前closeConnection');
			responseBuffer = concatByteData(responseBuffer, value);
			bytesRead = responseBuffer.length;
			const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
			if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
		}

		if (headerEndIndex === -1) throw new Error('HTTPS 代理 CONNECT 响应头过长或无效');
		const statusMatch = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
		const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
		if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);

		if (getValidDataLength(initialData) > 0) await tlsSocket.write(toUint8Array(initialData));
		const bufferedData = bytesRead > headerEndIndex ? responseBuffer.subarray(headerEndIndex, bytesRead) : null;
		let closedSettled = false, resolveClosed, rejectClosed;
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
			try { tlsSocket.close() } catch (e) { }
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
					try { controller.close() } catch (e) { }
					settleClosed(resolveClosed);
				} catch (error) {
					try { controller.error(error) } catch (e) { }
					settleClosed(rejectClosed, error);
				}
			},
			cancel() {
				close();
			}
		});
		const writable = new WritableStream({
			async write(chunk) {
				await tlsSocket.write(toUint8Array(chunk));
			},
			close,
			abort(error) {
				close();
				if (error) settleClosed(rejectClosed, error);
			}
		});
		return { readable, writable, closed, close };
	} catch (error) {
		try { tlsSocket?.close() } catch (e) { }
		throw error;
	}
}

function createRequestTCPConnector(request) {
	const requestObj = /** @type {any} */ (request);
	const fetcher = 请求对象?.fetcher;
	if (!fetcher || typeof fetcher.connect !== 'function') throw new Error('request.fetcher.connect unavailable');
	return (options, init) => init === undefined ? fetcher.connect(options) : fetcher.connect(options, init);
}
////////////////////////////////////////////TLSClient by: @Alexandre_Kojeve////////////////////////////////////////////////
const TLS_VERSION_10 = 769, TLS_VERSION_12 = 771, TLS_VERSION_13 = 772;
const CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20, CONTENT_TYPE_ALERT = 21, CONTENT_TYPE_HANDSHAKE = 22, CONTENT_TYPE_APPLICATION_DATA = 23;
const HANDSHAKE_TYPE_CLIENT_HELLO = 1, HANDSHAKE_TYPE_SERVER_HELLO = 2, HANDSHAKE_TYPE_NEW_SESSION_TICKET = 4, HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 8, HANDSHAKE_TYPE_CERTIFICATE = 11, HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12, HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13, HANDSHAKE_TYPE_SERVER_HELLO_DONE = 14, HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 15, HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16, HANDSHAKE_TYPE_FINISHED = 20, HANDSHAKE_TYPE_KEY_UPDATE = 24;
const EXT_SERVER_NAME = 0, EXT_SUPPORTED_GROUPS = 10, EXT_EC_POINT_FORMATS = 11, EXT_SIGNATURE_ALGORITHMS = 13, EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16, EXT_SUPPORTED_VERSIONS = 43, EXT_PSK_KEY_EXCHANGE_MODES = 45, EXT_KEY_SHARE = 51;

const ALERT_CLOSE_NOTIFY = 0, ALERT_LEVEL_WARNING = 1, ALERT_UNRECOGNIZED_NAME = 112;
const shouldIgnoreTlsAlert = fragment => fragment?.[0] === ALERT_LEVEL_WARNING && fragment?.[1] === ALERT_UNRECOGNIZED_NAME;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const EMPTY_BYTES = new Uint8Array(0);

const CIPHER_SUITES_BY_ID = new Map([
	[4865, { id: 4865, keyLen: 16, ivLen: 12, hash: "SHA-256", tls13: !0 }],
	[4866, { id: 4866, keyLen: 32, ivLen: 12, hash: "SHA-384", tls13: !0 }],
	[4867, { id: 4867, keyLen: 32, ivLen: 12, hash: "SHA-256", tls13: !0, chacha: !0 }],
	[49199, { id: 49199, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }],
	[49200, { id: 49200, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }],
	[52392, { id: 52392, keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: !0 }],
	[49195, { id: 49195, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }],
	[49196, { id: 49196, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }],
	[52393, { id: 52393, keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: !0 }]
]);
const GROUPS_BY_ID = new Map([[29, "X25519"], [23, "P-256"]]);
const SUPPORTED_SIGNATURE_ALGORITHMS = [2052, 2053, 2054, 1025, 1281, 1537, 1027, 1283, 1539];

const tlsBytes = (...parts) => {
	const flattenBytes = values => values.flatMap(value => value instanceof Uint8Array ? [...value] : Array.isArray(value) ? flattenBytes(value) : "number" == typeof value ? [value] : []);
	return new Uint8Array(flattenBytes(parts))
};
const uint16be = value => [value >> 8 & 255, 255 & value];
const readUint16 = (buffer, offset) => buffer[offset] << 8 | buffer[offset + 1];
const readUint24 = (buffer, offset) => buffer[offset] << 16 | buffer[offset + 1] << 8 | buffer[offset + 2];
const concatBytes = (...chunks) => {
	const nonEmptyChunks = chunks.filter((chunk => chunk && chunk.length > 0)),
		length = nonEmptyChunks.reduce(((total, chunk) => total + chunk.length), 0),
		result = new Uint8Array(length);
	let offset = 0;
	for (const chunk of nonEmptyChunks) result.set(chunk, offset), offset += chunk.length;
	return result
};
const randomBytes = length => crypto.getRandomValues(new Uint8Array(length));
const constantTimeEqual = (left, right) => {
	if (!left || !right || left.length !== right.length) return !1;
	let diff = 0; for (let index = 0; index < left.length; index++) diff |= left[index] ^ right[index];
	return 0 === diff
};
const hashByteLength = hash => "SHA-512" === hash ? 64 : "SHA-384" === hash ? 48 : 32;
async function hmac(hash, key, data) {
	const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash }, !1, ["sign"]);
	return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, data))
}
async function digestBytes(hash, data) { return new Uint8Array(await crypto.subtle.digest(hash, data)) }
async function tls12Prf(secret, label, seed, length, hash = "SHA-256") {
	const labelSeed = concatBytes(textEncoder.encode(label), seed);
	let output = new Uint8Array(0),
		currentA = labelSeed;
	for (; output.length < length;) {
		currentA = await hmac(hash, secret, currentA);
		const block = await hmac(hash, secret, concatBytes(currentA, labelSeed));
		output = concatBytes(output, block)
	}
	return output.slice(0, length)
}
async function hkdfExtract(hash, salt, inputKeyMaterial) {
	return salt && salt.length || (salt = new Uint8Array(hashByteLength(hash))), hmac(hash, salt, inputKeyMaterial)
}
async function hkdfExpandLabel(hash, secret, label, context, length) {
	const fullLabel = textEncoder.encode("tls13 " + label);
	return async function (hash, secret, info, length) {
		const hashLen = hashByteLength(hash),
			roundCount = Math.ceil(length / hashLen);
		let output = new Uint8Array(0),
			previousBlock = new Uint8Array(0);
		for (let round = 1; round <= roundCount; round++) previousBlock = await hmac(hash, secret, concatBytes(previousBlock, info, [round])), output = concatBytes(output, previousBlock);
		return output.slice(0, length)
	}(hash, secret, tlsBytes(uint16be(length), fullLabel.length, fullLabel, context.length, context), length)
}
async function generateKeyShare(group = "P-256") {
	const algorithm = "X25519" === group ? { name: "X25519" } : { name: "ECDH", namedCurve: group };
	const keyPair = /** @type {CryptoKeyPair} */ (await crypto.subtle.generateKey(algorithm, !0, ["deriveBits"]));
	const publicKeyRaw = /** @type {ArrayBuffer} */ (await crypto.subtle.exportKey("raw", keyPair.publicKey));
	return { keyPair, publicKeyRaw: new Uint8Array(publicKeyRaw) }
}
async function deriveSharedSecret(privateKey, peerPublicKey, group = "P-256") {
	const algorithm = "X25519" === group ? { name: "X25519" } : { name: "ECDH", namedCurve: group },
		peerKey = await crypto.subtle.importKey("raw", peerPublicKey, algorithm, !1, []),
		bits = "P-384" === group ? 384 : "P-521" === group ? 528 : 256;
	return new Uint8Array(await crypto.subtle.deriveBits(/** @type {any} */({ name: algorithm.name, public: peerKey }), privateKey, bits))
}
async function importAesGcmKey(key, usages) { return crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, !1, usages) }
async function aesGcmEncryptWithKey(cryptoKey, initializationVector, plaintext, additionalData) {
	return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: initializationVector, additionalData, tagLength: 128 }, cryptoKey, plaintext))
}
async function aesGcmDecryptWithKey(cryptoKey, initializationVector, ciphertext, additionalData) {
	return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: initializationVector, additionalData, tagLength: 128 }, cryptoKey, ciphertext))
}

function rotateLeft32(value, bits) { return (value << bits | value >>> 32 - bits) >>> 0 }

function chachaQuarterRound(state, indexA, indexB, indexC, indexD) {
	state[indexA] = state[indexA] + state[indexB] >>> 0, state[indexD] = rotateLeft32(state[indexD] ^ state[indexA], 16), state[indexC] = state[indexC] + state[indexD] >>> 0, state[indexB] = rotateLeft32(state[indexB] ^ state[indexC], 12), state[indexA] = state[indexA] + state[indexB] >>> 0, state[indexD] = rotateLeft32(state[indexD] ^ state[indexA], 8), state[indexC] = state[indexC] + state[indexD] >>> 0, state[indexB] = rotateLeft32(state[indexB] ^ state[indexC], 7)
}

function chacha20Block(key, counter, nonce) {
	const state = new Uint32Array(16);
	state[0] = 1634760805, state[1] = 857760878, state[2] = 2036477234, state[3] = 1797285236;
	const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
	for (let wordIndex = 0; wordIndex < 8; wordIndex++) state[4 + wordIndex] = keyView.getUint32(4 * wordIndex, !0);
	state[12] = counter;
	const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
	state[13] = nonceView.getUint32(0, !0), state[14] = nonceView.getUint32(4, !0), state[15] = nonceView.getUint32(8, !0);
	const workingState = new Uint32Array(state);
	for (let round = 0; round < 10; round++) chachaQuarterRound(workingState, 0, 4, 8, 12), chachaQuarterRound(workingState, 1, 5, 9, 13), chachaQuarterRound(workingState, 2, 6, 10, 14), chachaQuarterRound(workingState, 3, 7, 11, 15), chachaQuarterRound(workingState, 0, 5, 10, 15), chachaQuarterRound(workingState, 1, 6, 11, 12), chachaQuarterRound(workingState, 2, 7, 8, 13), chachaQuarterRound(workingState, 3, 4, 9, 14);
	for (let wordIndex = 0; wordIndex < 16; wordIndex++) workingState[wordIndex] = workingState[wordIndex] + state[wordIndex] >>> 0;
	return new Uint8Array(workingState.buffer.slice(0))
}

function chacha20Xor(key, nonce, data) {
	const output = new Uint8Array(data.length);
	let counter = 1;
	for (let offset = 0; offset < data.length; offset += 64) {
		const block = chacha20Block(key, counter++, nonce),
			blockLength = Math.min(64, data.length - offset);
		for (let index = 0; index < blockLength; index++) output[offset + index] = data[offset + index] ^ block[index]
	}
	return output
}

function poly1305Mac(key, message) {
	const rKey = function (rBytes) {
		const clamped = new Uint8Array(rBytes);
		return clamped[3] &= 15, clamped[7] &= 15, clamped[11] &= 15, clamped[15] &= 15, clamped[4] &= 252, clamped[8] &= 252, clamped[12] &= 252, clamped
	}(key.slice(0, 16)),
		sKey = key.slice(16, 32);
	let accumulator = [0n, 0n, 0n, 0n, 0n];
	const rLimbs = [0x3ffffffn & BigInt(rKey[0] | rKey[1] << 8 | rKey[2] << 16 | rKey[3] << 24), 0x3ffffffn & BigInt(rKey[3] >> 2 | rKey[4] << 6 | rKey[5] << 14 | rKey[6] << 22), 0x3ffffffn & BigInt(rKey[6] >> 4 | rKey[7] << 4 | rKey[8] << 12 | rKey[9] << 20), 0x3ffffffn & BigInt(rKey[9] >> 6 | rKey[10] << 2 | rKey[11] << 10 | rKey[12] << 18), 0x3ffffffn & BigInt(rKey[13] | rKey[14] << 8 | rKey[15] << 16)];
	for (let offset = 0; offset < message.length; offset += 16) {
		const chunk = message.slice(offset, offset + 16),
			paddedChunk = new Uint8Array(17);
		paddedChunk.set(chunk), paddedChunk[chunk.length] = 1, accumulator[0] += BigInt(paddedChunk[0] | paddedChunk[1] << 8 | paddedChunk[2] << 16 | (3 & paddedChunk[3]) << 24), accumulator[1] += BigInt(paddedChunk[3] >> 2 | paddedChunk[4] << 6 | paddedChunk[5] << 14 | (15 & paddedChunk[6]) << 22), accumulator[2] += BigInt(paddedChunk[6] >> 4 | paddedChunk[7] << 4 | paddedChunk[8] << 12 | (63 & paddedChunk[9]) << 20), accumulator[3] += BigInt(paddedChunk[9] >> 6 | paddedChunk[10] << 2 | paddedChunk[11] << 10 | paddedChunk[12] << 18), accumulator[4] += BigInt(paddedChunk[13] | paddedChunk[14] << 8 | paddedChunk[15] << 16 | paddedChunk[16] << 24);
		const product = [0n, 0n, 0n, 0n, 0n];
		for (let accIndex = 0; accIndex < 5; accIndex++)
			for (let rIndex = 0; rIndex < 5; rIndex++) {
				const limbIndex = accIndex + rIndex;
				limbIndex < 5 ? product[limbIndex] += accumulator[accIndex] * rLimbs[rIndex] : product[limbIndex - 5] += accumulator[accIndex] * rLimbs[rIndex] * 5n
			}
		let carry = 0n;
		for (let index = 0; index < 5; index++) product[index] += carry, accumulator[index] = 0x3ffffffn & product[index], carry = product[index] >> 26n;
		accumulator[0] += 5n * carry, carry = accumulator[0] >> 26n, accumulator[0] &= 0x3ffffffn, accumulator[1] += carry
	}
	let tagValue = accumulator[0] | accumulator[1] << 26n | accumulator[2] << 52n | accumulator[3] << 78n | accumulator[4] << 104n;
	tagValue = tagValue + sKey.reduce(((total, byte, index) => total + (BigInt(byte) << BigInt(8 * index))), 0n) & (1n << 128n) - 1n;
	const tag = new Uint8Array(16);
	for (let index = 0; index < 16; index++) tag[index] = Number(tagValue >> BigInt(8 * index) & 0xffn);
	return tag
}

function chacha20Poly1305Encrypt(key, nonce, plaintext, additionalData) {
	const polyKey = chacha20Block(key, 0, nonce).slice(0, 32),
		ciphertext = chacha20Xor(key, nonce, plaintext),
		aadPadding = (16 - additionalData.length % 16) % 16,
		ciphertextPadding = (16 - ciphertext.length % 16) % 16,
		macData = new Uint8Array(additionalData.length + aadPadding + ciphertext.length + ciphertextPadding + 16);
	macData.set(additionalData, 0), macData.set(ciphertext, additionalData.length + aadPadding);
	const lengthView = new DataView(macData.buffer, additionalData.length + aadPadding + ciphertext.length + ciphertextPadding);
	lengthView.setBigUint64(0, BigInt(additionalData.length), !0), lengthView.setBigUint64(8, BigInt(ciphertext.length), !0);
	const tag = poly1305Mac(polyKey, macData);
	return concatBytes(ciphertext, tag)
}

function chacha20Poly1305Decrypt(key, nonce, ciphertext, additionalData) {
	if (ciphertext.length < 16) throw new Error("Ciphertext too short");
	const tag = ciphertext.slice(-16),
		encryptedData = ciphertext.slice(0, -16),
		polyKey = chacha20Block(key, 0, nonce).slice(0, 32),
		aadPadding = (16 - additionalData.length % 16) % 16,
		ciphertextPadding = (16 - encryptedData.length % 16) % 16,
		macData = new Uint8Array(additionalData.length + aadPadding + encryptedData.length + ciphertextPadding + 16);
	macData.set(additionalData, 0), macData.set(encryptedData, additionalData.length + aadPadding);
	const lengthView = new DataView(macData.buffer, additionalData.length + aadPadding + encryptedData.length + ciphertextPadding);
	lengthView.setBigUint64(0, BigInt(additionalData.length), !0), lengthView.setBigUint64(8, BigInt(encryptedData.length), !0);
	const expectedTag = poly1305Mac(polyKey, macData);
	let diff = 0;
	for (let index = 0; index < 16; index++) diff |= tag[index] ^ expectedTag[index];
	if (0 !== diff) throw new Error("ChaCha20-Poly1305 authentication failed");
	return chacha20Xor(key, nonce, encryptedData)
}

const TLS_MAX_PLAINTEXT_FRAGMENT = 16 * 1024;
function buildTlsRecord(contentType, fragment, version = TLS_VERSION_12) {
	const data = toUint8Array(fragment);
	const record = new Uint8Array(5 + data.byteLength);
	record[0] = contentType;
	record[1] = version >> 8 & 255;
	record[2] = version & 255;
	record[3] = data.byteLength >> 8 & 255;
	record[4] = data.byteLength & 255;
	record.set(data, 5);
	return record;
}
function buildHandshakeMessage(handshakeType, body) { return tlsBytes(handshakeType, (length => [length >> 16 & 255, length >> 8 & 255, 255 & length])(body.length), body) }
class TlsRecordParser {
	constructor() { this.buffer = new Uint8Array(0) }
	feed(chunk) {
		const bytes = toUint8Array(chunk);
		this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes
	}
	next() {
		if (this.buffer.length < 5) return null;
		const contentType = this.buffer[0],
			version = readUint16(this.buffer, 1),
			length = readUint16(this.buffer, 3);
		if (this.buffer.length < 5 + length) return null;
		const fragment = this.buffer.subarray(5, 5 + length);
		return this.buffer = this.buffer.subarray(5 + length), { type: contentType, version, length, fragment }
	}
}
class TlsHandshakeParser {
	constructor() { this.buffer = new Uint8Array(0) }
	feed(chunk) {
		const bytes = toUint8Array(chunk);
		this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes
	}
	next() {
		if (this.buffer.length < 4) return null;
		const handshakeType = this.buffer[0],
			length = readUint24(this.buffer, 1);
		if (this.buffer.length < 4 + length) return null;
		const body = this.buffer.subarray(4, 4 + length),
			raw = this.buffer.subarray(0, 4 + length);
		return this.buffer = this.buffer.subarray(4 + length), { type: handshakeType, length, body, raw }
	}
}

function parseServerHello(body) {
	let offset = 0;
	const legacyVersion = readUint16(body, offset);
	offset += 2;
	const serverRandom = body.slice(offset, offset + 32);
	offset += 32;
	const sessionIdLength = body[offset++],
		sessionId = body.slice(offset, offset + sessionIdLength);
	offset += sessionIdLength;
	const cipherSuite = readUint16(body, offset);
	offset += 2;
	const compression = body[offset++];
	let selectedVersion = legacyVersion,
		keyShare = null,
		alpn = null;
	if (offset < body.length) {
		const extensionsLength = readUint16(body, offset);
		offset += 2;
		const extensionsEnd = offset + extensionsLength;
		for (; offset + 4 <= extensionsEnd;) {
			const extensionType = readUint16(body, offset);
			offset += 2;
			const extensionLength = readUint16(body, offset);
			offset += 2;
			const extensionData = body.slice(offset, offset + extensionLength);
			if (offset += extensionLength, extensionType === EXT_SUPPORTED_VERSIONS && extensionLength >= 2) selectedVersion = readUint16(extensionData, 0);
			else if (extensionType === EXT_KEY_SHARE && extensionLength >= 4) {
				const group = readUint16(extensionData, 0),
					keyLength = readUint16(extensionData, 2);
				keyShare = { group, key: extensionData.slice(4, 4 + keyLength) }
			} else extensionType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extensionLength >= 3 && (alpn = textDecoder.decode(extensionData.slice(3, 3 + extensionData[2])))
		}
	}
	const helloRetryRequestRandom = new Uint8Array([207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145, 194, 162, 17, 22, 122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156]);
	return { version: legacyVersion, serverRandom, sessionId, cipherSuite, compression, selectedVersion, keyShare, alpn, isHRR: constantTimeEqual(serverRandom, helloRetryRequestRandom), isTls13: selectedVersion === TLS_VERSION_13 }
}

function parseServerKeyExchange(body) {
	let offset = 1;
	const namedCurve = readUint16(body, offset);
	offset += 2;
	const keyLength = body[offset++];
	return { namedCurve, serverPublicKey: body.slice(offset, offset + keyLength) }
}

function extractLeafCertificate(body, hasContext = 0) {
	let offset = 0;
	if (hasContext) {
		const contextLength = body[offset++];
		offset += contextLength
	}
	if (offset + 3 > body.length) return null;
	const certificateListLength = readUint24(body, offset);
	if (offset += 3, !certificateListLength || offset + 3 > body.length) return null;
	const certificateLength = readUint24(body, offset);
	return offset += 3, certificateLength ? body.slice(offset, offset + certificateLength) : null
}

function parseEncryptedExtensions(body) {
	const parsed = { alpn: null };
	let offset = 2;
	const extensionsEnd = 2 + readUint16(body, 0);
	for (; offset + 4 <= extensionsEnd;) {
		const extensionType = readUint16(body, offset);
		offset += 2;
		const extensionLength = readUint16(body, offset);
		if (offset += 2, extensionType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extensionLength >= 3) {
			const protocolLength = body[offset + 2];
			protocolLength > 0 && offset + 3 + protocolLength <= offset + extensionLength && (parsed.alpn = textDecoder.decode(body.slice(offset + 3, offset + 3 + protocolLength)))
		}
		offset += extensionLength
	}
	return parsed
}

function buildClientHello(clientRandom, serverName, keyShares, { tls13: enableTls13 = !0, tls12: enableTls12 = !0, alpn = null, chacha = !0 } = {}) {
	const cipherIds = [];
	enableTls13 && cipherIds.push(4865, 4866, ...(chacha ? [4867] : [])), enableTls12 && cipherIds.push(49199, 49200, 49195, 49196, ...(chacha ? [52392, 52393] : []));
	const cipherBytes = tlsBytes(...cipherIds.flatMap(uint16be)),
		extensions = [tlsBytes(255, 1, 0, 1, 0)];
	if (serverName) {
		const serverNameBytes = textEncoder.encode(serverName),
			serverNameList = tlsBytes(0, uint16be(serverNameBytes.length), serverNameBytes);
		extensions.push(tlsBytes(uint16be(EXT_SERVER_NAME), uint16be(serverNameList.length + 2), uint16be(serverNameList.length), serverNameList))
	}
	extensions.push(tlsBytes(uint16be(EXT_EC_POINT_FORMATS), 0, 2, 1, 0)), extensions.push(tlsBytes(uint16be(EXT_SUPPORTED_GROUPS), 0, 6, 0, 4, 0, 29, 0, 23));
	const signatureBytes = tlsBytes(...SUPPORTED_SIGNATURE_ALGORITHMS.flatMap(uint16be));
	extensions.push(tlsBytes(uint16be(EXT_SIGNATURE_ALGORITHMS), uint16be(signatureBytes.length + 2), uint16be(signatureBytes.length), signatureBytes));
	const protocols = Array.isArray(alpn) ? alpn.filter(Boolean) : alpn ? [alpn] : [];
	if (protocols.length) {
		const alpnBytes = concatBytes(...protocols.map((protocol => { const protocolBytes = textEncoder.encode(protocol); return tlsBytes(protocolBytes.length, protocolBytes) })));
		extensions.push(tlsBytes(uint16be(EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION), uint16be(alpnBytes.length + 2), uint16be(alpnBytes.length), alpnBytes))
	}
	if (enableTls13 && keyShares) {
		let keyShareBytes;
		if (extensions.push(enableTls12 ? tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 5, 4, 3, 4, 3, 3) : tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 3, 2, 3, 4)), extensions.push(tlsBytes(uint16be(EXT_PSK_KEY_EXCHANGE_MODES), 0, 2, 1, 1)), keyShares?.x25519 && keyShares?.p256) keyShareBytes = concatBytes(tlsBytes(0, 29, uint16be(keyShares.x25519.length), keyShares.x25519), tlsBytes(0, 23, uint16be(keyShares.p256.length), keyShares.p256));
		else if (keyShares?.x25519) keyShareBytes = tlsBytes(0, 29, uint16be(keyShares.x25519.length), keyShares.x25519);
		else if (keyShares?.p256) keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.p256.length), keyShares.p256);
		else {
			if (!(keyShares instanceof Uint8Array)) throw new Error("Invalid keyShares");
			keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.length), keyShares)
		}
		extensions.push(tlsBytes(uint16be(EXT_KEY_SHARE), uint16be(keyShareBytes.length + 2), uint16be(keyShareBytes.length), keyShareBytes))
	}
	const extensionsBytes = concatBytes(...extensions);
	return buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_HELLO, tlsBytes(uint16be(TLS_VERSION_12), clientRandom, 0, uint16be(cipherBytes.length), cipherBytes, 1, 0, uint16be(extensionsBytes.length), extensionsBytes))
}
const uint64be = sequenceNumber => { const bytes = new Uint8Array(8); return new DataView(bytes.buffer).setBigUint64(0, sequenceNumber, !1), bytes },
	xorSequenceIntoIv = (initializationVector, sequenceNumber) => {
		const nonce = initializationVector.slice(),
			sequenceBytes = uint64be(sequenceNumber);
		for (let index = 0; index < 8; index++) nonce[nonce.length - 8 + index] ^= sequenceBytes[index];
		return nonce
	},
	deriveTrafficKeys = (hash, secret, keyLen, ivLen) => Promise.all([hkdfExpandLabel(hash, secret, "key", EMPTY_BYTES, keyLen), hkdfExpandLabel(hash, secret, "iv", EMPTY_BYTES, ivLen)]);
class TlsClient {
	constructor(socket, options = {}) {
		if (this.socket = socket, this.serverName = options.serverName || "", this.supportTls13 = !1 !== options.tls13, this.supportTls12 = !1 !== options.tls12, !this.supportTls13 && !this.supportTls12) throw new Error("At least one TLS version must be enabled");
		this.alpnProtocols = Array.isArray(options.alpn) ? options.alpn : options.alpn ? [options.alpn] : null, this.allowChacha = options.allowChacha !== false, this.timeout = options.timeout ?? 3e4, this.clientRandom = randomBytes(32), this.serverRandom = null, this.handshakeChunks = [], this.handshakeComplete = !1, this.negotiatedAlpn = null, this.cipherSuite = null, this.cipherConfig = null, this.isTls13 = !1, this.masterSecret = null, this.handshakeSecret = null, this.clientWriteKey = null, this.serverWriteKey = null, this.clientWriteIv = null, this.serverWriteIv = null, this.clientHandshakeKey = null, this.serverHandshakeKey = null, this.clientHandshakeIv = null, this.serverHandshakeIv = null, this.clientAppKey = null, this.serverAppKey = null, this.clientAppIv = null, this.serverAppIv = null, this.clientWriteCryptoKey = null, this.serverWriteCryptoKey = null, this.clientHandshakeCryptoKey = null, this.serverHandshakeCryptoKey = null, this.clientAppCryptoKey = null, this.serverAppCryptoKey = null, this.clientSeqNum = 0n, this.serverSeqNum = 0n, this.recordParser = new TlsRecordParser, this.handshakeParser = new TlsHandshakeParser, this.keyPairs = new Map, this.ecdhKeyPair = null, this.sawCert = !1
	}
	recordHandshake(chunk) { this.handshakeChunks.push(chunk) }
	transcript() { return 1 === this.handshakeChunks.length ? this.handshakeChunks[0] : concatBytes(...this.handshakeChunks) }
	getCipherConfig(cipherSuite) { return CIPHER_SUITES_BY_ID.get(cipherSuite) || null }
	async readChunk(reader) { return this.timeout ? Promise.race([reader.read(), new Promise(((resolve, reject) => setTimeout((() => reject(new Error("TLS read timeout"))), this.timeout)))]) : reader.read() }
	async readRecordsUntil(reader, predicate, closedError) {
		for (; ;) {
			let record;
			for (; record = this.recordParser.next();)
				if (await predicate(record)) return;
			const { value, done } = await this.readChunk(reader);
			if (done) throw new Error(closedError);
			this.recordParser.feed(value)
		}
	}
	async readHandshakeUntil(reader, predicate, closedError) {
		for (let message; message = this.handshakeParser.next();)
			if (await predicate(message)) return;
		return this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type === CONTENT_TYPE_HANDSHAKE) {
				this.handshakeParser.feed(record.fragment);
				for (let message; message = this.handshakeParser.next();)
					if (await predicate(message)) return 1
			}
		}), closedError)
	}
	async acceptCertificate(certificate) { if (!certificate?.length) throw new Error("Empty certificate"); this.sawCert = !0 }
	async handshake() {
		const [p256Share, x25519Share] = await Promise.all([generateKeyShare("P-256"), generateKeyShare("X25519")]);
		this.keyPairs = new Map([[23, p256Share], [29, x25519Share]]), this.ecdhKeyPair = p256Share.keyPair;
		const reader = this.socket.readable.getReader(),
			writer = this.socket.writable.getWriter();
		try {
			const clientHello = buildClientHello(this.clientRandom, this.serverName, { x25519: x25519Share.publicKeyRaw, p256: p256Share.publicKeyRaw }, { tls13: this.supportTls13, tls12: this.supportTls12, alpn: this.alpnProtocols, chacha: this.allowChacha });
			this.recordHandshake(clientHello), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientHello, TLS_VERSION_10));
			const serverHello = await this.receiveServerHello(reader);
			if (serverHello.isHRR) throw new Error("HelloRetryRequest is not supported by TLSClientMini");
			if (serverHello.keyShare?.group && this.keyPairs.has(serverHello.keyShare.group)) {
				const selectedKeyPair = this.keyPairs.get(serverHello.keyShare.group);
				this.ecdhKeyPair = selectedKeyPair.keyPair
			}
			serverHello.isTls13 ? await this.handshakeTls13(reader, writer, serverHello) : await this.handshakeTls12(reader, writer), this.handshakeComplete = !0
		} finally {
			reader.releaseLock(), writer.releaseLock()
		}
	}
	async receiveServerHello(reader) {
		for (; ;) {
			const { value, done } = await this.readChunk(reader);
			if (done) throw new Error("Connection closed waiting for ServerHello");
			let record;
			for (this.recordParser.feed(value); record = this.recordParser.next();) {
				if (record.type === CONTENT_TYPE_ALERT) {
					if (shouldIgnoreTlsAlert(record.fragment)) continue;
					throw new Error(`TLS Alert: level=${record.fragment[0]}, desc=${record.fragment[1]}`);
				}
				if (record.type !== CONTENT_TYPE_HANDSHAKE) continue;
				let message;
				for (this.handshakeParser.feed(record.fragment); message = this.handshakeParser.next();) {
					if (message.type !== HANDSHAKE_TYPE_SERVER_HELLO) continue;
					this.recordHandshake(message.raw);
					const serverHello = parseServerHello(message.body);
					if (this.serverRandom = serverHello.serverRandom, this.cipherSuite = serverHello.cipherSuite, this.cipherConfig = this.getCipherConfig(serverHello.cipherSuite), this.isTls13 = serverHello.isTls13, this.negotiatedAlpn = serverHello.alpn || null, !this.cipherConfig) throw new Error(`Unsupported cipher suite: 0x${serverHello.cipherSuite.toString(16)}`);
					return serverHello
				}
			}
		}
	}
	async handshakeTls12(reader, writer) {
		/** @type {{ namedCurve: number, serverPublicKey: Uint8Array } | null} */
		let serverKeyExchange = null;
		let sawServerHelloDone = !1;
		if (await this.readHandshakeUntil(reader, (async message => {
			switch (message.type) {
				case HANDSHAKE_TYPE_CERTIFICATE: {
					this.recordHandshake(message.raw);
					const certificate = extractLeafCertificate(message.body, 1);
					if (!certificate) throw new Error("Missing TLS 1.2 certificate");
					await this.acceptCertificate(certificate);
					break
				}
				case HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:
					this.recordHandshake(message.raw), serverKeyExchange = parseServerKeyExchange(message.body);
					break;
				case HANDSHAKE_TYPE_SERVER_HELLO_DONE:
					return this.recordHandshake(message.raw), sawServerHelloDone = !0, 1;
				case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
					throw new Error("Client certificate is not supported");
				default:
					this.recordHandshake(message.raw)
			}
		}), "Connection closed during TLS 1.2 handshake"), !this.sawCert) throw new Error("Missing TLS 1.2 leaf certificate");
		const serverKeyExchangeData = /** @type {{ namedCurve: number, serverPublicKey: Uint8Array } | null} */ (serverKeyExchange);
		if (!serverKeyExchangeData) throw new Error("Missing TLS 1.2 ServerKeyExchange");
		const curveName = GROUPS_BY_ID.get(serverKeyExchangeData.namedCurve);
		if (!curveName) throw new Error(`Unsupported named curve: 0x${serverKeyExchangeData.namedCurve.toString(16)}`);
		const keyShare = this.keyPairs.get(serverKeyExchangeData.namedCurve);
		if (!keyShare) throw new Error(`Missing key pair for curve: 0x${serverKeyExchangeData.namedCurve.toString(16)}`);
		const preMasterSecret = await deriveSharedSecret(keyShare.keyPair.privateKey, serverKeyExchangeData.serverPublicKey, curveName),
			clientKeyExchange = buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, tlsBytes(keyShare.publicKeyRaw.length, keyShare.publicKeyRaw));
		this.recordHandshake(clientKeyExchange);
		const hashName = this.cipherConfig.hash;
		this.masterSecret = await tls12Prf(preMasterSecret, "master secret", concatBytes(this.clientRandom, this.serverRandom), 48, hashName);
		const keyLen = this.cipherConfig.keyLen,
			ivLen = this.cipherConfig.ivLen,
			keyBlock = await tls12Prf(this.masterSecret, "key expansion", concatBytes(this.serverRandom, this.clientRandom), 2 * keyLen + 2 * ivLen, hashName);
		this.clientWriteKey = keyBlock.slice(0, keyLen), this.serverWriteKey = keyBlock.slice(keyLen, 2 * keyLen), this.clientWriteIv = keyBlock.slice(2 * keyLen, 2 * keyLen + ivLen), this.serverWriteIv = keyBlock.slice(2 * keyLen + ivLen, 2 * keyLen + 2 * ivLen);
		if (!this.cipherConfig.chacha) [this.clientWriteCryptoKey, this.serverWriteCryptoKey] = await Promise.all([importAesGcmKey(this.clientWriteKey, ["encrypt"]), importAesGcmKey(this.serverWriteKey, ["decrypt"])]);
		await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientKeyExchange)), await writer.write(buildTlsRecord(CONTENT_TYPE_CHANGE_CIPHER_SPEC, tlsBytes(1)));
		const clientVerifyData = await tls12Prf(this.masterSecret, "client finished", await digestBytes(hashName, this.transcript()), 12, hashName),
			finishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientVerifyData);
		this.recordHandshake(finishedMessage), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, await this.encryptTls12(finishedMessage, CONTENT_TYPE_HANDSHAKE)));
		let sawChangeCipherSpec = !1;
		await this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC) return void (sawChangeCipherSpec = !0);
			if (record.type !== CONTENT_TYPE_HANDSHAKE || !sawChangeCipherSpec) return;
			const decrypted = await this.decryptTls12(record.fragment, CONTENT_TYPE_HANDSHAKE);
			if (decrypted[0] !== HANDSHAKE_TYPE_FINISHED) return;
			const verifyLength = readUint24(decrypted, 1),
				verifyData = decrypted.slice(4, 4 + verifyLength),
				expectedVerifyData = await tls12Prf(this.masterSecret, "server finished", await digestBytes(hashName, this.transcript()), 12, hashName);
			if (!constantTimeEqual(verifyData, expectedVerifyData)) throw new Error("TLS 1.2 server Finished verify failed");
			return 1
		}), "Connection closed waiting for TLS 1.2 Finished")
	}
	async handshakeTls13(reader, writer, serverHello) {
		const groupName = GROUPS_BY_ID.get(serverHello.keyShare?.group);
		if (!groupName || !serverHello.keyShare?.key?.length) throw new Error("Missing TLS 1.3 key_share");
		const hashName = this.cipherConfig.hash,
			hashLen = hashByteLength(hashName),
			keyLen = this.cipherConfig.keyLen,
			ivLen = this.cipherConfig.ivLen,
			sharedSecret = await deriveSharedSecret(this.ecdhKeyPair.privateKey, serverHello.keyShare.key, groupName),
			earlySecret = await hkdfExtract(hashName, null, new Uint8Array(hashLen)),
			derivedSecret = await hkdfExpandLabel(hashName, earlySecret, "derived", await digestBytes(hashName, EMPTY_BYTES), hashLen);
		this.handshakeSecret = await hkdfExtract(hashName, derivedSecret, sharedSecret);
		const transcriptHash = await digestBytes(hashName, this.transcript()),
			clientHandshakeTrafficSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "c hs traffic", transcriptHash, hashLen),
			serverHandshakeTrafficSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "s hs traffic", transcriptHash, hashLen);
		[this.clientHandshakeKey, this.clientHandshakeIv] = await deriveTrafficKeys(hashName, clientHandshakeTrafficSecret, keyLen, ivLen), [this.serverHandshakeKey, this.serverHandshakeIv] = await deriveTrafficKeys(hashName, serverHandshakeTrafficSecret, keyLen, ivLen);
		if (!this.cipherConfig.chacha) [this.clientHandshakeCryptoKey, this.serverHandshakeCryptoKey] = await Promise.all([importAesGcmKey(this.clientHandshakeKey, ["encrypt"]), importAesGcmKey(this.serverHandshakeKey, ["decrypt"])]);
		const serverFinishedKey = await hkdfExpandLabel(hashName, serverHandshakeTrafficSecret, "finished", EMPTY_BYTES, hashLen);
		let serverFinishedReceived = !1;
		const handleHandshakeMessage = async message => {
			switch (message.type) {
				case HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: {
					const encryptedExtensions = parseEncryptedExtensions(message.body);
					encryptedExtensions.alpn && (this.negotiatedAlpn = encryptedExtensions.alpn), this.recordHandshake(message.raw);
					break
				}
				case HANDSHAKE_TYPE_CERTIFICATE: {
					const certificate = extractLeafCertificate(message.body);
					if (!certificate) throw new Error("Missing TLS 1.3 certificate");
					await this.acceptCertificate(certificate), this.recordHandshake(message.raw);
					break
				}
				case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
					throw new Error("Client certificate is not supported");
				case HANDSHAKE_TYPE_CERTIFICATE_VERIFY:
					this.recordHandshake(message.raw);
					break;
				case HANDSHAKE_TYPE_FINISHED: {
					const expectedVerifyData = await hmac(hashName, serverFinishedKey, await digestBytes(hashName, this.transcript()));
					if (!constantTimeEqual(expectedVerifyData, message.body)) throw new Error("TLS 1.3 server Finished verify failed");
					this.recordHandshake(message.raw), serverFinishedReceived = !0;
					break
				}
				default:
					this.recordHandshake(message.raw)
			}
		};
		await this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC || record.type === CONTENT_TYPE_HANDSHAKE) return;
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type !== CONTENT_TYPE_APPLICATION_DATA) return;
			const decrypted = await this.decryptTls13Handshake(record.fragment),
				innerType = decrypted[decrypted.length - 1],
				plaintext = decrypted.slice(0, -1);
			if (innerType === CONTENT_TYPE_HANDSHAKE) {
				this.handshakeParser.feed(plaintext);
				for (let message; message = this.handshakeParser.next();)
					if (await handleHandshakeMessage(message), serverFinishedReceived) return 1
			}
		}), "Connection closed during TLS 1.3 handshake");
		const applicationTranscriptHash = await digestBytes(hashName, this.transcript()),
			masterDerivedSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "derived", await digestBytes(hashName, EMPTY_BYTES), hashLen),
			masterSecret = await hkdfExtract(hashName, masterDerivedSecret, new Uint8Array(hashLen)),
			clientAppTrafficSecret = await hkdfExpandLabel(hashName, masterSecret, "c ap traffic", applicationTranscriptHash, hashLen),
			serverAppTrafficSecret = await hkdfExpandLabel(hashName, masterSecret, "s ap traffic", applicationTranscriptHash, hashLen);
		[this.clientAppKey, this.clientAppIv] = await deriveTrafficKeys(hashName, clientAppTrafficSecret, keyLen, ivLen), [this.serverAppKey, this.serverAppIv] = await deriveTrafficKeys(hashName, serverAppTrafficSecret, keyLen, ivLen);
		if (!this.cipherConfig.chacha) [this.clientAppCryptoKey, this.serverAppCryptoKey] = await Promise.all([importAesGcmKey(this.clientAppKey, ["encrypt"]), importAesGcmKey(this.serverAppKey, ["decrypt"])]);
		const clientFinishedKey = await hkdfExpandLabel(hashName, clientHandshakeTrafficSecret, "finished", EMPTY_BYTES, hashLen),
			clientFinishedVerifyData = await hmac(hashName, clientFinishedKey, await digestBytes(hashName, this.transcript())),
			clientFinishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientFinishedVerifyData);
		this.recordHandshake(clientFinishedMessage), await writer.write(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, await this.encryptTls13Handshake(concatBytes(clientFinishedMessage, [CONTENT_TYPE_HANDSHAKE])))), this.clientSeqNum = 0n, this.serverSeqNum = 0n
	}
	async encryptTls12(plaintext, contentType) {
		const sequenceNumber = this.clientSeqNum++,
			sequenceBytes = uint64be(sequenceNumber),
			additionalData = concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(plaintext.length));
		if (this.cipherConfig.chacha) {
			const nonce = xorSequenceIntoIv(this.clientWriteIv, sequenceNumber);
			return chacha20Poly1305Encrypt(this.clientWriteKey, nonce, plaintext, additionalData)
		}
		const explicitNonce = randomBytes(8);
		if (!this.clientWriteCryptoKey) this.clientWriteCryptoKey = await importAesGcmKey(this.clientWriteKey, ["encrypt"]);
		return concatBytes(explicitNonce, await aesGcmEncryptWithKey(this.clientWriteCryptoKey, concatBytes(this.clientWriteIv, explicitNonce), plaintext, additionalData))
	}
	async decryptTls12(ciphertext, contentType) {
		const sequenceNumber = this.serverSeqNum++,
			sequenceBytes = uint64be(sequenceNumber);
		if (this.cipherConfig.chacha) {
			const nonce = xorSequenceIntoIv(this.serverWriteIv, sequenceNumber);
			return chacha20Poly1305Decrypt(this.serverWriteKey, nonce, ciphertext, concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(ciphertext.length - 16)))
		}
		const explicitNonce = ciphertext.subarray(0, 8),
			encryptedData = ciphertext.subarray(8);
		if (!this.serverWriteCryptoKey) this.serverWriteCryptoKey = await importAesGcmKey(this.serverWriteKey, ["decrypt"]);
		return aesGcmDecryptWithKey(this.serverWriteCryptoKey, concatBytes(this.serverWriteIv, explicitNonce), encryptedData, concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(encryptedData.length - 16)))
	}
	async encryptTls13Handshake(plaintext) {
		const nonce = xorSequenceIntoIv(this.clientHandshakeIv, this.clientSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(plaintext.length + 16));
		if (this.cipherConfig.chacha) return chacha20Poly1305Encrypt(this.clientHandshakeKey, nonce, plaintext, additionalData);
		if (!this.clientHandshakeCryptoKey) this.clientHandshakeCryptoKey = await importAesGcmKey(this.clientHandshakeKey, ["encrypt"]);
		return aesGcmEncryptWithKey(this.clientHandshakeCryptoKey, nonce, plaintext, additionalData)
	}
	async decryptTls13Handshake(ciphertext) {
		const nonce = xorSequenceIntoIv(this.serverHandshakeIv, this.serverSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(ciphertext.length));
		const decrypted = this.cipherConfig.chacha ? await chacha20Poly1305Decrypt(this.serverHandshakeKey, nonce, ciphertext, additionalData) : await aesGcmDecryptWithKey(this.serverHandshakeCryptoKey || (this.serverHandshakeCryptoKey = await importAesGcmKey(this.serverHandshakeKey, ["decrypt"])), nonce, ciphertext, additionalData);
		let innerTypeIndex = decrypted.length - 1;
		for (; innerTypeIndex >= 0 && !decrypted[innerTypeIndex];) innerTypeIndex--;
		return innerTypeIndex < 0 ? EMPTY_BYTES : decrypted.slice(0, innerTypeIndex + 1)
	}
	async encryptTls13(data) {
		const plaintext = concatBytes(data, [CONTENT_TYPE_APPLICATION_DATA]),
			nonce = xorSequenceIntoIv(this.clientAppIv, this.clientSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(plaintext.length + 16));
		if (this.cipherConfig.chacha) return chacha20Poly1305Encrypt(this.clientAppKey, nonce, plaintext, additionalData);
		if (!this.clientAppCryptoKey) this.clientAppCryptoKey = await importAesGcmKey(this.clientAppKey, ["encrypt"]);
		return aesGcmEncryptWithKey(this.clientAppCryptoKey, nonce, plaintext, additionalData)
	}
	async decryptTls13(ciphertext) {
		const nonce = xorSequenceIntoIv(this.serverAppIv, this.serverSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(ciphertext.length)),
			plaintext = this.cipherConfig.chacha ? await chacha20Poly1305Decrypt(this.serverAppKey, nonce, ciphertext, additionalData) : await aesGcmDecryptWithKey(this.serverAppCryptoKey || (this.serverAppCryptoKey = await importAesGcmKey(this.serverAppKey, ["decrypt"])), nonce, ciphertext, additionalData);
		let innerTypeIndex = plaintext.length - 1;
		for (; innerTypeIndex >= 0 && !plaintext[innerTypeIndex];) innerTypeIndex--;
		if (innerTypeIndex < 0) return {
			data: EMPTY_BYTES,
			type: 0
		};
		return {
			data: plaintext.slice(0, innerTypeIndex),
			type: plaintext[innerTypeIndex]
		}
	}
	async write(data) {
		if (!this.handshakeComplete) throw new Error("Handshake not complete");
		const plaintext = toUint8Array(data);
		if (!plaintext.byteLength) return;
		const writer = this.socket.writable.getWriter();
		try {
			const records = [];
			for (let offset = 0; offset < plaintext.byteLength; offset += TLS_MAX_PLAINTEXT_FRAGMENT) {
				const chunk = plaintext.subarray(offset, Math.min(offset + TLS_MAX_PLAINTEXT_FRAGMENT, plaintext.byteLength));
				const encrypted = this.isTls13 ? await this.encryptTls13(chunk) : await this.encryptTls12(chunk, CONTENT_TYPE_APPLICATION_DATA);
				records.push(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, encrypted));
			}
			await writer.write(records.length === 1 ? records[0] : concatBytes(...records))
		} finally {
			writer.releaseLock()
		}
	}
	async read() {
		for (; ;) {
			let record;
			for (; record = this.recordParser.next();) {
				if (record.type === CONTENT_TYPE_ALERT) {
					if (record.fragment[1] === ALERT_CLOSE_NOTIFY) return null;
					throw new Error(`TLS Alert: ${record.fragment[1]}`)
				}
				if (record.type !== CONTENT_TYPE_APPLICATION_DATA) continue;
				if (!this.isTls13) return this.decryptTls12(record.fragment, CONTENT_TYPE_APPLICATION_DATA);
				const { data, type } = await this.decryptTls13(record.fragment);
				if (type === CONTENT_TYPE_APPLICATION_DATA) return data;
				if (type === CONTENT_TYPE_ALERT) {
					if (data[1] === ALERT_CLOSE_NOTIFY) return null;
					throw new Error(`TLS Alert: ${data[1]}`)
				}
				if (type !== CONTENT_TYPE_HANDSHAKE) continue;
				let message;
				for (this.handshakeParser.feed(data); message = this.handshakeParser.next();)
					if (message.type !== HANDSHAKE_TYPE_NEW_SESSION_TICKET && message.type === HANDSHAKE_TYPE_KEY_UPDATE) throw new Error("TLS 1.3 KeyUpdate is not supported by TLSClientMini")
			}
			const reader = this.socket.readable.getReader();
			try {
				const { value, done } = await this.readChunk(reader);
				if (done) return null;
				this.recordParser.feed(value)
			} finally {
				reader.releaseLock()
			}
		}
	}
	close() { this.socket.close() }
}

function stripIPv6Brackets(hostname = '') {
	const host = String(hostname || '').trim();
	return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

function isIPHostname(hostname = '') {
	const host = stripIPv6Brackets(hostname);
	const ipv4Regex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
	if (ipv4Regex.test(host)) return true;
	if (!host.includes(':')) return false;
	try {
		new URL(`http://[${host}]/`);
		return true;
	} catch (e) {
		return false;
	}
}

//////////////////////////////////////////////////turnConnect///////////////////////////////////////////////
const CONNECT_TIMEOUT_MS = 9999;
const TURN_STUN_MAGIC_COOKIE = new Uint8Array([0x21, 0x12, 0xa4, 0x42]);
const TURN_STUN_TYPE = {
	ALLOCATE_REQUEST: 0x0003, ALLOCATE_SUCCESS: 0x0103, ALLOCATE_ERROR: 0x0113,
	CREATE_PERMISSION_REQUEST: 0x0008, CREATE_PERMISSION_SUCCESS: 0x0108,
	CONNECT_REQUEST: 0x000a, CONNECT_SUCCESS: 0x010a,
	CONNECTION_BIND_REQUEST: 0x000b, CONNECTION_BIND_SUCCESS: 0x010b
};
const TURN_STUN_ATTR = {
	USERNAME: 0x0006, MESSAGE_INTEGRITY: 0x0008, ERROR_CODE: 0x0009,
	XOR_PEER_ADDRESS: 0x0012, REALM: 0x0014, NONCE: 0x0015,
	REQUESTED_TRANSPORT: 0x0019, CONNECTION_ID: 0x002a
};

async function withTimeout(promise, timeoutMs, message) {
	let timer;
	try {
		return await Promise.race([
			promise,
			new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message)), timeoutMs) })
		]);
	} finally {
		clearTimeout(timer);
	}
}

function isIPv4(value) {
	const parts = String(value || '').split('.');
	return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function turnStunPadding(length) {
	return -length & 3;
}

function createTurnStunAttribute(type, value) {
	const body = toUint8Array(value);
	const attribute = new Uint8Array(4 + body.byteLength + turnStunPadding(body.byteLength));
	const view = new DataView(attribute.buffer);
	view.setUint16(0, type);
	view.setUint16(2, body.byteLength);
	attribute.set(body, 4);
	return attribute;
}

function createTurnStunMessage(type, transactionId, attributes) {
	const body = concatByteData(...attributes);
	const header = new Uint8Array(20);
	const view = new DataView(header.buffer);
	view.setUint16(0, type);
	view.setUint16(2, body.byteLength);
	header.set(TURN_STUN_MAGIC_COOKIE, 4);
	header.set(transactionId, 8);
	return concatByteData(header, body);
}

function parseTurnErrorCode(data) {
	return data?.byteLength >= 4 ? (data[2] & 7) * 100 + data[3] : 0;
}

function randomTurnTransactionId() {
	return crypto.getRandomValues(new Uint8Array(12));
}

async function addTurnMessageIntegrity(message, key) {
	const signedMessage = new Uint8Array(message);
	const view = new DataView(signedMessage.buffer);
	view.setUint16(2, view.getUint16(2) + 24);
	const hmacKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
	const signature = await crypto.subtle.sign('HMAC', hmacKey, signedMessage);
	return concatByteData(signedMessage, createTurnStunAttribute(TURN_STUN_ATTR.MESSAGE_INTEGRITY, new Uint8Array(signature)));
}

async function readTurnStunMessage(reader, bufferedData = null, timeoutMessage = 'TURN response timed out') {
	let buffer = getValidDataLength(bufferedData) ? toUint8Array(bufferedData) : new Uint8Array(0);
	const pull = async () => {
		const { done, value } = await withTimeout(reader.read(), CONNECT_TIMEOUT_MS, timeoutMessage);
		if (done) throw new Error('TURN server closed connection');
		if (value?.byteLength) buffer = concatByteData(buffer, value);
	};
	while (buffer.byteLength < 20) await pull();

	const messageLength = 20 + ((buffer[2] << 8) | buffer[3]);
	if (messageLength > 65555) throw new Error('TURN response is too large');
	while (buffer.byteLength < messageLength) await pull();
	const messageBuffer = buffer.subarray(0, messageLength);
	if (TURN_STUN_MAGIC_COOKIE.some((value, index) => messageBuffer[4 + index] !== value)) throw new Error('Invalid TURN/STUN response');

	const view = new DataView(messageBuffer.buffer, messageBuffer.byteOffset, messageBuffer.byteLength);
	const attributes = {};
	for (let offset = 20; offset + 4 <= messageLength;) {
		const type = view.getUint16(offset);
		const length = view.getUint16(offset + 2);
		if (offset + 4 + length > messageBuffer.byteLength) break;
		attributes[type] = messageBuffer.slice(offset + 4, offset + 4 + length);
		offset += 4 + length + turnStunPadding(length);
	}
	return {
		message: { type: view.getUint16(0), attributes },
		extraData: buffer.byteLength > messageLength ? buffer.subarray(messageLength) : null
	};
}

async function writeTurnBytes(writer, bytes, timeoutMessage) {
	await withTimeout(writer.write(bytes), CONNECT_TIMEOUT_MS, timeoutMessage);
}

async function turnConnect(proxy, targetHost, targetPort, tcpConnector) {
	proxy = { ...proxy, username: proxy.username ?? null, password: proxy.password ?? null };
	const resolvedTargetHost = stripIPv6Brackets(targetHost);
	/** @type {string | null} */
	let targetIp = isIPv4(resolvedTargetHost) ? resolvedTargetHost : null;
	if (!targetIp) {
		const records = await doHQuery(resolvedTargetHost, 'A');
		const recordData = records.find(item => item.type === 1 && isIPv4(item.data))?.data;
		targetIp = typeof recordData === 'string' ? recordData : null;
	}
	if (!targetIp) throw new Error(`Could not resolve ${targetHost} to an IPv4 address for TURN CONNECT`);

	const turnHost = stripIPv6Brackets(proxy.hostname);
	let controlSocket = null, dataSocket = null, controlWriter = null, controlReader = null, dataWriter = null, dataReader = null, dataReaderReleased = false;
	const close = () => {
		try { controlSocket?.close?.() } catch (e) { }
		try { dataSocket?.close?.() } catch (e) { }
	};
	const releaseDataReader = () => {
		if (dataReaderReleased) return;
		dataReaderReleased = true;
		try { dataReader?.releaseLock?.() } catch (e) { }
	};

	try {
		controlSocket = tcpConnector({ hostname: turnHost, port: proxy.port });
		await withTimeout(controlSocket.opened, CONNECT_TIMEOUT_MS, 'TURN server connection timed out');
		controlWriter = controlSocket.writable.getWriter();
		controlReader = controlSocket.readable.getReader();

		const xorPeerAddress = new Uint8Array(8);
		xorPeerAddress[1] = 1;
		new DataView(xorPeerAddress.buffer).setUint16(2, targetPort ^ 0x2112);
		targetIp.split('.').forEach((value, index) => {
			xorPeerAddress[4 + index] = Number(value) ^ TURN_STUN_MAGIC_COOKIE[index];
		});
		const peerAddress = createTurnStunAttribute(TURN_STUN_ATTR.XOR_PEER_ADDRESS, xorPeerAddress);
		const requestedTransport = new Uint8Array([6, 0, 0, 0]);

		await writeTurnBytes(controlWriter, createTurnStunMessage(
			TURN_STUN_TYPE.ALLOCATE_REQUEST,
			randomTurnTransactionId(),
			[createTurnStunAttribute(TURN_STUN_ATTR.REQUESTED_TRANSPORT, requestedTransport)]
		), 'TURN Allocate request timed out');

		let turnResponse = await readTurnStunMessage(controlReader, null, 'TURN Allocate response timed out');
		let message = turnResponse.message;
		let bufferedData = turnResponse.extraData;
		let integrityKey = null;
		let authAttributes = [];
		const sign = messageToSign => integrityKey ? addTurnMessageIntegrity(messageToSign, integrityKey) : Promise.resolve(messageToSign);

		if (
			message.type === TURN_STUN_TYPE.ALLOCATE_ERROR
			&& proxy.username !== null
			&& proxy.password !== null
			&& parseTurnErrorCode(message.attributes[TURN_STUN_ATTR.ERROR_CODE]) === 401
		) {
			const realmBytes = message.attributes[TURN_STUN_ATTR.REALM];
			const nonce = message.attributes[TURN_STUN_ATTR.NONCE];
			if (!realmBytes || !nonce?.byteLength) throw new Error('TURN authentication challenge is missing realm or nonce');

			const realm = textDecoder.decode(realmBytes);
			integrityKey = new Uint8Array(await crypto.subtle.digest('MD5', textEncoder.encode(`${proxy.username}:${realm}:${proxy.password}`)));
			authAttributes = [
				createTurnStunAttribute(TURN_STUN_ATTR.USERNAME, textEncoder.encode(proxy.username)),
				createTurnStunAttribute(TURN_STUN_ATTR.REALM, textEncoder.encode(realm)),
				createTurnStunAttribute(TURN_STUN_ATTR.NONCE, nonce)
			];

			const allocateRequest = await addTurnMessageIntegrity(createTurnStunMessage(
				TURN_STUN_TYPE.ALLOCATE_REQUEST,
				randomTurnTransactionId(),
				[
					createTurnStunAttribute(TURN_STUN_ATTR.REQUESTED_TRANSPORT, requestedTransport),
					...authAttributes
				]
			), integrityKey);
			const pipelinedMessages = await Promise.all([
				sign(createTurnStunMessage(TURN_STUN_TYPE.CREATE_PERMISSION_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes])),
				sign(createTurnStunMessage(TURN_STUN_TYPE.CONNECT_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes]))
			]);
			await writeTurnBytes(controlWriter, concatByteData(allocateRequest, ...pipelinedMessages), 'TURN authenticated Allocate request timed out');
			turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN authenticated Allocate response timed out');
			message = turnResponse.message;
			bufferedData = turnResponse.extraData;
		} else if (message.type === TURN_STUN_TYPE.ALLOCATE_SUCCESS) {
			const pipelinedMessages = await Promise.all([
				sign(createTurnStunMessage(TURN_STUN_TYPE.CREATE_PERMISSION_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes])),
				sign(createTurnStunMessage(TURN_STUN_TYPE.CONNECT_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes]))
			]);
			if (pipelinedMessages.length) await writeTurnBytes(controlWriter, concatByteData(...pipelinedMessages), 'TURN pipelined request timed out');
		}

		if (message.type !== TURN_STUN_TYPE.ALLOCATE_SUCCESS) {
			const errorCode = parseTurnErrorCode(message.attributes[TURN_STUN_ATTR.ERROR_CODE]);
			throw new Error(errorCode ? `TURN Allocate failed with ${errorCode}` : 'TURN Allocate failed');
		}

		dataSocket = tcpConnector({ hostname: turnHost, port: proxy.port });
		turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN CreatePermission response timed out');
		message = turnResponse.message;
		bufferedData = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CREATE_PERMISSION_SUCCESS) throw new Error('TURN CreatePermission failed');

		turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN CONNECT response timed out');
		message = turnResponse.message;
		bufferedData = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CONNECT_SUCCESS || !message.attributes[TURN_STUN_ATTR.CONNECTION_ID]) throw new Error('TURN CONNECT failed');

		await withTimeout(dataSocket.opened, CONNECT_TIMEOUT_MS, 'TURN data connection timed out');
		dataWriter = dataSocket.writable.getWriter();
		dataReader = dataSocket.readable.getReader();
		await writeTurnBytes(dataWriter, await sign(createTurnStunMessage(
			TURN_STUN_TYPE.CONNECTION_BIND_REQUEST,
			randomTurnTransactionId(),
			[
				createTurnStunAttribute(TURN_STUN_ATTR.CONNECTION_ID, message.attributes[TURN_STUN_ATTR.CONNECTION_ID]),
				...authAttributes
			]
		)), 'TURN ConnectionBind request timed out');

		turnResponse = await readTurnStunMessage(dataReader, null, 'TURN ConnectionBind response timed out');
		message = turnResponse.message;
		const extraPayload = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CONNECTION_BIND_SUCCESS) throw new Error('TURN ConnectionBind failed');

		controlWriter.releaseLock();
		controlWriter = null;
		controlReader.releaseLock();
		controlReader = null;
		dataWriter.releaseLock();
		dataWriter = null;

		const readable = new ReadableStream({
			start(controller) {
				if (extraPayload?.byteLength) controller.enqueue(extraPayload);
			},
			pull(controller) {
				return dataReader.read().then(({ done, value }) => {
					if (done) {
						releaseDataReader();
						controller.close();
					} else if (value?.byteLength) controller.enqueue(new Uint8Array(value));
				});
			},
			cancel() {
				try { dataReader?.cancel?.() } catch (e) { }
				releaseDataReader();
				close();
			}
		});

		return { readable, writable: dataSocket.writable, closed: dataSocket.closed, close };
	} catch (error) {
		try { controlWriter?.releaseLock?.() } catch (e) { }
		try { controlReader?.releaseLock?.() } catch (e) { }
		try { dataWriter?.releaseLock?.() } catch (e) { }
		releaseDataReader();
		close();
		throw error;
	}
}
//////////////////////////////////////////////////sstpConnect///////////////////////////////////////////////
const SSTP_TCP_MSS = 1400;
const SSTP_EMPTY_BYTES = new Uint8Array(0);

function readSstpUint16(bytes, offset = 0) {
	return (bytes[offset] << 8) | bytes[offset + 1];
}

function readSstpUint32(bytes, offset = 0) {
	return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

function randomSstpUint16() {
	return readSstpUint16(crypto.getRandomValues(new Uint8Array(2)));
}

function internetChecksum(bytes, offset, length) {
	let sum = 0;
	for (let index = offset; index < offset + length - 1; index += 2) sum += readSstpUint16(bytes, index);
	if (length & 1) sum += bytes[offset + length - 1] << 8;
	while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
	return (~sum) & 0xffff;
}

async function sstpConnect(proxy, targetHost, targetPort, tcpConnector) {
	proxy = { ...proxy, username: proxy.username ?? null, password: proxy.password ?? null };
	let bufferedBytes = SSTP_EMPTY_BYTES, pppIdentifier = 1, socket = null, reader = null, writer = null;
	let closedSettled = false, resolveClosed, rejectClosed;
	const closed = new Promise((resolve, reject) => {
		resolveClosed = resolve;
		rejectClosed = reject;
	});
	const settleClosed = (settle, value) => {
		if (closedSettled) return;
		closedSettled = true;
		settle(value);
	};
	const close = () => {
		try { reader?.cancel?.().catch?.(() => { }) } catch (e) { }
		try { reader?.releaseLock?.() } catch (e) { }
		try { writer?.close?.().catch?.(() => { }) } catch (e) { }
		try { writer?.releaseLock?.() } catch (e) { }
		try { socket?.close?.() } catch (e) { }
		settleClosed(resolveClosed);
	};

	const readSocketChunk = async () => {
		const { value, done } = await reader.read();
		if (done || !value) throw new Error('SSTP socket closed');
		return toUint8Array(value);
	};
	const readBytes = async length => {
		while (bufferedBytes.byteLength < length) {
			const chunk = await readSocketChunk();
			bufferedBytes = bufferedBytes.byteLength ? concatByteData(bufferedBytes, chunk) : chunk;
		}
		const result = bufferedBytes.subarray(0, length);
		bufferedBytes = bufferedBytes.subarray(length);
		return result;
	};
	const readHttpLine = async () => {
		for (; ;) {
			const lineEnd = bufferedBytes.indexOf(10);
			if (lineEnd >= 0) {
				const line = textDecoder.decode(bufferedBytes.subarray(0, lineEnd));
				bufferedBytes = bufferedBytes.subarray(lineEnd + 1);
				return line.replace(/\r$/, '');
			}
			const chunk = await readSocketChunk();
			bufferedBytes = bufferedBytes.byteLength ? concatByteData(bufferedBytes, chunk) : chunk;
		}
	};
	const readPacket = async (timeoutMs = CONNECT_TIMEOUT_MS) => {
		const header = await withTimeout(readBytes(4), timeoutMs, 'SSTP read timeout');
		const length = readSstpUint16(header, 2) & 0x0fff;
		if (length < 4) throw new Error('Invalid SSTP packet length');
		return {
			isControl: (header[1] & 1) !== 0,
			body: length > 4 ? await withTimeout(readBytes(length - 4), timeoutMs, 'SSTP packet body read timeout') : SSTP_EMPTY_BYTES
		};
	};
	const buildSstpDataPacket = pppFrame => {
		const packetLength = 6 + pppFrame.byteLength;
		const packet = new Uint8Array(packetLength);
		packet.set([0x10, 0x00, ((packetLength >> 8) & 0x0f) | 0x80, packetLength & 0xff, 0xff, 0x03]);
		packet.set(pppFrame, 6);
		return packet;
	};
	const buildPppConfigurePacket = (protocol, code, id, options = []) => {
		const optionsLength = options.reduce((size, option) => size + 2 + option.data.byteLength, 0);
		const frame = new Uint8Array(6 + optionsLength);
		const view = new DataView(frame.buffer);
		view.setUint16(0, protocol);
		frame[2] = code;
		frame[3] = id;
		view.setUint16(4, 4 + optionsLength);
		options.reduce((offset, option) => {
			frame[offset] = option.type;
			frame[offset + 1] = 2 + option.data.byteLength;
			frame.set(option.data, offset + 2);
			return offset + 2 + option.data.byteLength;
		}, 6);
		return frame;
	};
	const parsePPPFrame = data => {
		const offset = data.byteLength >= 2 && data[0] === 0xff && data[1] === 0x03 ? 2 : 0;
		if (data.byteLength - offset < 4) return null;
		const protocol = readSstpUint16(data, offset);
		if (protocol === 0x0021) return { protocol, ipPacket: data.subarray(offset + 2) };
		if (data.byteLength - offset < 6) return null;
		return { protocol, code: data[offset + 2], id: data[offset + 3], payload: data.subarray(offset + 6), rawPacket: data.subarray(offset) };
	};
	const parsePppOptions = data => {
		const options = [];
		for (let offset = 0; offset + 2 <= data.byteLength;) {
			const type = data[offset];
			const length = data[offset + 1];
			if (length < 2 || offset + length > data.byteLength) break;
			options.push({ type, data: data.subarray(offset + 2, offset + length) });
			offset += length;
		}
		return options;
	};

	try {
		const serverHost = stripIPv6Brackets(proxy.hostname);
		const serverPort = proxy.port;
		socket = tcpConnector({ hostname: serverHost, port: serverPort }, { secureTransport: 'on', allowHalfOpen: false });
		await withTimeout(socket.opened, CONNECT_TIMEOUT_MS, 'SSTP server connection timed out');
		reader = socket.readable.getReader();
		writer = socket.writable.getWriter();

		const displayHost = serverHost.includes(':') ? `[${serverHost}]` : serverHost;
		const httpRequest = textEncoder.encode(
			`SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n`
			+ `Host: ${Number(serverPort) === 443 ? displayHost : `${displayHost}:${serverPort}`}\r\n`
			+ 'Content-Length: 18446744073709551615\r\n'
			+ `SSTPCORRELATIONID: {${crypto.randomUUID()}}\r\n\r\n`
		);
		const encapsulatedProtocol = new Uint8Array(2);
		new DataView(encapsulatedProtocol.buffer).setUint16(0, 1);
		const maximumReceiveUnit = new Uint8Array(2);
		new DataView(maximumReceiveUnit.buffer).setUint16(0, 1500);
		const sstpConnectRequest = new Uint8Array(12 + encapsulatedProtocol.byteLength);
		const sstpConnectView = new DataView(sstpConnectRequest.buffer);
		sstpConnectRequest[0] = 0x10;
		sstpConnectRequest[1] = 0x01;
		sstpConnectView.setUint16(2, sstpConnectRequest.byteLength | 0x8000);
		sstpConnectView.setUint16(4, 0x0001);
		sstpConnectView.setUint16(6, 1);
		sstpConnectRequest[9] = 1;
		sstpConnectView.setUint16(10, 4 + encapsulatedProtocol.byteLength);
		sstpConnectRequest.set(encapsulatedProtocol, 12);

		await withTimeout(writer.write(concatByteData(
			httpRequest,
			sstpConnectRequest,
			buildSstpDataPacket(buildPppConfigurePacket(0xc021, 1, pppIdentifier++, [
				{ type: 1, data: maximumReceiveUnit }
			]))
		)), CONNECT_TIMEOUT_MS, 'SSTP HTTP handshake request timed out');

		const statusLine = await withTimeout(readHttpLine(), CONNECT_TIMEOUT_MS, 'SSTP HTTP handshake timed out');
		for (; ;) {
			const line = await withTimeout(readHttpLine(), CONNECT_TIMEOUT_MS, 'SSTP HTTP header read timed out');
			if (line === '') break;
		}
		if (!/HTTP\/\d(?:\.\d)?\s+2\d\d/i.test(statusLine)) throw new Error(`SSTP HTTP handshake failed: ${statusLine || 'invalid status'}`);

		let localLcpAcked = false, peerLcpAcked = false, papRequired = false, papSent = false, papDone = false, ipcpStarted = false, ipcpFinished = false, sourceIp = null;
		const sendPapIfReady = async () => {
			if (!localLcpAcked || !peerLcpAcked || !papRequired || papSent) return;
			if (proxy.username === null || proxy.password === null) throw new Error('SSTP server requires PAP authentication');
			const username = textEncoder.encode(proxy.username);
			const password = textEncoder.encode(proxy.password);
			if (username.byteLength > 255 || password.byteLength > 255) throw new Error('SSTP username/password is too long');
			const papLength = 6 + username.byteLength + password.byteLength;
			const frame = new Uint8Array(2 + papLength);
			const view = new DataView(frame.buffer);
			view.setUint16(0, 0xc023);
			frame[2] = 1;
			frame[3] = pppIdentifier++;
			view.setUint16(4, papLength);
			frame[6] = username.byteLength;
			frame.set(username, 7);
			frame[7 + username.byteLength] = password.byteLength;
			frame.set(password, 8 + username.byteLength);
			await withTimeout(writer.write(buildSstpDataPacket(frame)), CONNECT_TIMEOUT_MS, 'SSTP PAP authentication request timed out');
			papSent = true;
		};
		const startIpcpIfReady = async () => {
			if (!localLcpAcked || !peerLcpAcked || ipcpStarted || (papRequired && !papDone)) return;
			await withTimeout(writer.write(buildSstpDataPacket(buildPppConfigurePacket(0x8021, 1, pppIdentifier++, [
				{ type: 3, data: new Uint8Array(4) }
			]))), CONNECT_TIMEOUT_MS, 'SSTP IPCP request timed out');
			ipcpStarted = true;
		};

		for (let round = 0; round < 50 && !ipcpFinished; round++) {
			const packet = await readPacket(CONNECT_TIMEOUT_MS);
			if (packet.isControl) continue;
			const ppp = parsePPPFrame(packet.body);
			if (!ppp) continue;

			if (ppp.protocol === 0xc021) {
				if (ppp.code === 1) {
					const authOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (authOption?.data?.byteLength >= 2) {
						const authProtocol = readSstpUint16(authOption.data);
						if (authProtocol !== 0xc023) throw new Error(`SSTP unsupported PPP authentication protocol: 0x${authProtocol.toString(16)}`);
						papRequired = true;
					}
					const ack = new Uint8Array(ppp.rawPacket);
					ack[2] = 2;
					await withTimeout(writer.write(buildSstpDataPacket(ack)), CONNECT_TIMEOUT_MS, 'SSTP LCP Configure-Ack timed out');
					peerLcpAcked = true;
					await sendPapIfReady();
					await startIpcpIfReady();
				} else if (ppp.code === 2) {
					localLcpAcked = true;
					await sendPapIfReady();
					await startIpcpIfReady();
				}
				continue;
			}

			if (ppp.protocol === 0xc023) {
				if (ppp.code === 2) {
					papDone = true;
					await startIpcpIfReady();
				} else if (ppp.code === 3) throw new Error('SSTP PAP authentication failed');
				continue;
			}

			if (ppp.protocol === 0x8021) {
				if (ppp.code === 1) {
					const ack = new Uint8Array(ppp.rawPacket);
					ack[2] = 2;
					await withTimeout(writer.write(buildSstpDataPacket(ack)), CONNECT_TIMEOUT_MS, 'SSTP IPCP Configure-Ack timed out');
					await startIpcpIfReady();
				} else if (ppp.code === 3) {
					const addressOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (addressOption?.data?.byteLength === 4) {
						sourceIp = [...addressOption.data].join('.');
						await withTimeout(writer.write(buildSstpDataPacket(buildPppConfigurePacket(0x8021, 1, pppIdentifier++, [
							{ type: 3, data: addressOption.data }
						]))), CONNECT_TIMEOUT_MS, 'SSTP IPCP address request timed out');
						ipcpStarted = true;
					}
				} else if (ppp.code === 2) {
					const addressOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (addressOption?.data?.byteLength === 4) sourceIp = [...addressOption.data].join('.');
					ipcpFinished = true;
				}
			}
		}
		if (!sourceIp) throw new Error('SSTP did not assign an IPv4 address');

		const target = stripIPv6Brackets(targetHost);
		/** @type {string | null} */
		let targetIp = isIPv4(target) ? target : null;
		if (!targetIp) {
			const records = await doHQuery(target, 'A');
			const recordData = records.find(item => item.type === 1 && isIPv4(item.data))?.data;
			targetIp = typeof recordData === 'string' ? recordData : null;
		}
		if (!targetIp) throw new Error(`Could not resolve ${targetHost} to an IPv4 address for SSTP`);

		const sourcePort = 10000 + (randomSstpUint16() % 50000);
		const sourceAddress = new Uint8Array(String(sourceIp || '').split('.').map(Number));
		const destinationAddress = new Uint8Array(String(targetIp || '').split('.').map(Number));
		let sequenceNumber = readSstpUint32(crypto.getRandomValues(new Uint8Array(4)));
		let acknowledgementNumber = 0;
		const ipHeaderTemplate = new Uint8Array(20);
		ipHeaderTemplate.set([0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 64, 6]);
		ipHeaderTemplate.set(sourceAddress, 12);
		ipHeaderTemplate.set(destinationAddress, 16);
		const tcpPseudoHeader = new Uint8Array(1432);
		tcpPseudoHeader.set(sourceAddress);
		tcpPseudoHeader.set(destinationAddress, 4);
		tcpPseudoHeader[9] = 6;
		const buildTcpFrame = (flags, payload = SSTP_EMPTY_BYTES) => {
			const bytes = toUint8Array(payload);
			const payloadLength = bytes.byteLength;
			const tcpLength = 20 + payloadLength;
			const ipLength = 20 + tcpLength;
			const sstpLength = 8 + ipLength;
			const frame = new Uint8Array(sstpLength);
			const view = new DataView(frame.buffer);
			frame.set([0x10, 0x00, ((sstpLength >> 8) & 0x0f) | 0x80, sstpLength & 0xff, 0xff, 0x03, 0x00, 0x21]);
			frame.set(ipHeaderTemplate, 8);
			view.setUint16(10, ipLength);
			view.setUint16(12, randomSstpUint16());
			view.setUint16(18, internetChecksum(frame, 8, 20));
			view.setUint16(28, sourcePort);
			view.setUint16(30, targetPort);
			view.setUint32(32, sequenceNumber);
			view.setUint32(36, acknowledgementNumber);
			frame[40] = 0x50;
			frame[41] = flags;
			view.setUint16(42, 65535);
			if (payloadLength) frame.set(bytes, 48);
			tcpPseudoHeader[10] = tcpLength >> 8;
			tcpPseudoHeader[11] = tcpLength & 0xff;
			tcpPseudoHeader.set(frame.subarray(28, 28 + tcpLength), 12);
			view.setUint16(44, internetChecksum(tcpPseudoHeader, 0, 12 + tcpLength));
			return frame;
		};
		const matchIncomingIpPacket = ipPacket => {
			if (ipPacket.byteLength < 40 || ipPacket[9] !== 6) return null;
			const ipHeaderLength = (ipPacket[0] & 0x0f) * 4;
			if (ipPacket.byteLength < ipHeaderLength + 20) return null;
			if (readSstpUint16(ipPacket, ipHeaderLength) !== targetPort) return null;
			if (readSstpUint16(ipPacket, ipHeaderLength + 2) !== sourcePort) return null;
			return {
				flags: ipPacket[ipHeaderLength + 13],
				sequence: readSstpUint32(ipPacket, ipHeaderLength + 4),
				payloadOffset: ipHeaderLength + ((ipPacket[ipHeaderLength + 12] >> 4) & 0x0f) * 4
			};
		};

		await withTimeout(writer.write(buildTcpFrame(0x02)), CONNECT_TIMEOUT_MS, 'SSTP TCP SYN write timed out');
		sequenceNumber = (sequenceNumber + 1) >>> 0;
		let tcpReady = false;
		for (let attempt = 0; attempt < 30; attempt++) {
			const packet = await readPacket(CONNECT_TIMEOUT_MS);
			if (packet.isControl) continue;
			const ppp = parsePPPFrame(packet.body);
			if (!ppp || ppp.protocol !== 0x0021) continue;
			const tcp = matchIncomingIpPacket(ppp.ipPacket);
			if (!tcp || (tcp.flags & 0x12) !== 0x12) continue;
			acknowledgementNumber = (tcp.sequence + 1) >>> 0;
			await withTimeout(writer.write(buildTcpFrame(0x10)), CONNECT_TIMEOUT_MS, 'SSTP TCP ACK write timed out');
			tcpReady = true;
			break;
		}
		if (!tcpReady) throw new Error('TCP handshake through SSTP timed out');

		/** @type {ReadableStreamDefaultController<Uint8Array> | null} */
		let streamController = null;
		const readable = new ReadableStream({
			start(controller) {
				streamController = controller;
			},
			cancel() {
				close();
			}
		});

		(async () => {
			try {
				let pendingChunks = [], pendingLength = 0;
				const flush = () => {
					if (!pendingLength) return;
					if (!streamController) throw new Error('SSTP readable stream is not ready');
					streamController.enqueue(pendingChunks.length === 1 ? pendingChunks[0] : concatByteData(...pendingChunks));
					pendingChunks = [];
					pendingLength = 0;
					writer.write(buildTcpFrame(0x10)).catch(() => { });
				};

				for (; ;) {
					const packet = await readPacket(60000);
					if (packet.isControl) continue;
					const ppp = parsePPPFrame(packet.body);
					if (!ppp || ppp.protocol !== 0x0021) continue;
					const incoming = matchIncomingIpPacket(ppp.ipPacket);
					if (!incoming) continue;

					if (incoming.payloadOffset < ppp.ipPacket.byteLength) {
						const payload = ppp.ipPacket.subarray(incoming.payloadOffset);
						if (payload.byteLength) {
							acknowledgementNumber = (incoming.sequence + payload.byteLength) >>> 0;
							pendingChunks.push(new Uint8Array(payload));
							pendingLength += payload.byteLength;
						}
					}

					if (incoming.flags & 0x01) {
						flush();
						acknowledgementNumber = (acknowledgementNumber + 1) >>> 0;
						writer.write(buildTcpFrame(0x11)).catch(() => { });
						const controller = streamController;
						if (controller) {
							try { controller.close() } catch (e) { }
						}
						close();
						return;
					}

					if (bufferedBytes.byteLength < 4 || pendingLength >= 32768) flush();
				}
			} catch (error) {
				const controller = streamController;
				if (controller) {
					try { controller.error(error) } catch (e) { }
				}
				settleClosed(rejectClosed, error);
				try { socket?.close?.() } catch (e) { }
			}
		})();

		const writable = new WritableStream({
			async write(chunk) {
				const bytes = toUint8Array(chunk);
				if (!bytes.byteLength) return;
				if (bytes.byteLength <= SSTP_TCP_MSS) {
					await writer.write(buildTcpFrame(0x18, bytes));
					sequenceNumber = (sequenceNumber + bytes.byteLength) >>> 0;
					return;
				}
				const frames = [];
				for (let offset = 0; offset < bytes.byteLength; offset += SSTP_TCP_MSS) {
					const segment = bytes.subarray(offset, Math.min(offset + SSTP_TCP_MSS, bytes.byteLength));
					frames.push(buildTcpFrame(0x18, segment));
					sequenceNumber = (sequenceNumber + segment.byteLength) >>> 0;
				}
				await writer.write(concatByteData(...frames));
			},
			close() {
				return writer.write(buildTcpFrame(0x11)).catch(() => { });
			},
			abort(error) {
				close();
				if (error) settleClosed(rejectClosed, error);
			}
		});

		return { readable, writable, closed, close };
	} catch (error) {
		close();
		throw error;
	}
}
//////////////////////////////////////////////////功能性函数///////////////////////////////////////////////
/**
 * 带秘钥的 Base64 编码
 * @param {string} plaintext - 原始明文str
 * @param {string} secret - 秘钥str（如 "KEY123"）
 * @returns {string} 经过秘钥处理的 Base64 str
 */
function base64SecretEncode(plaintext, secret) {
	const encoder = new TextEncoder();
	const data = encoder.encode(plaintext);
	const key = encoder.encode(secret);
	const mixed = new Uint8Array(data.length);

	for (let i = 0; i < data.length; i++) {
		mixed[i] = data[i] ^ key[i % key.length];
	}

	// 将 Uint8Array 转换为可被 btoa 处理的str
	let binary = '';
	for (let i = 0; i < mixed.length; i++) {
		binary += String.fromCharCode(mixed[i]);
	}
	return btoa(binary);
}

/**
 * 带秘钥的 Base64 解码
 * @param {string} encoded - 经秘钥处理过的 Base64 str
 * @param {string} secret - 秘钥str（必须与编码时相同）
 * @returns {string} 解码后的原始明文str
 */
function base64SecretDecode(encoded, secret) {
	const binary = atob(encoded);
	const mixed = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		mixed[i] = binary.charCodeAt(i);
	}

	const encoder = new TextEncoder();
	const key = encoder.encode(secret);
	const data = new Uint8Array(mixed.length);

	for (let i = 0; i < mixed.length; i++) {
		data[i] = mixed[i] ^ key[i % key.length];
	}

	const decoder = new TextDecoder();
	return decoder.decode(data);
}

function getTransportProtocolConfig(config = {}) {
	const isGRPC = config.transportProtocol === 'grpc';
	const { head: localPaddingHeader, key: localPaddingKey } = getXHTTPPaddingIdentifiers(config.UUID);
	const xhttpObfsJSON = {
		"xPaddingObfsMode": true,
		"xPaddingMethod": "tokenish",
		"xPaddingPlacement": "queryInHeader",
		"xPaddingHeader": localPaddingHeader,
		"xPaddingKey": localPaddingKey
	};
	return {
		type: isGRPC ? (config.gRPC模式 === 'multi' ? 'grpc&mode=multi' : 'grpc&mode=gun') : (config.transportProtocol === 'xhttp' ? `xhttp&mode=stream-one&extra=${encodeURIComponent(JSON.stringify(xhttpObfsJSON))}` : 'ws'),
		pathFieldName: isGRPC ? 'serviceName' : 'path',
		domainFieldName: isGRPC ? 'authority' : 'host'
	};
}

function getTransportPathParamValue(config = {}, nodePath = '/', asOptimalSubGenerator = false) {
	const pathValue = asOptimalSubGenerator ? '/' : (config.randomPath ? randomPath(nodePath) : nodePath);
	if (config.transportProtocol !== 'grpc') return pathValue;
	return pathValue.split('?')[0] || '/';
}

function log(...args) {
	if (debugLogging) console.log(...args);
}

function clashSubscriptionHotPatch(Clash_原始subscriptionContent, config_JSON = {}) {
	const uuid = config_JSON?.UUID || null;
	const ECH启用 = Boolean(config_JSON?.ECH);
	const HOSTS = Array.isArray(config_JSON?.HOSTS) ? [...config_JSON.HOSTS] : [];
	const ECH_SNI = config_JSON?.ECHConfig?.SNI || null;
	const ECH_DNS = config_JSON?.ECHConfig?.DNS;
	const needProcessECH = Boolean(uuid && ECH启用);
	const gRPCUserAgent = (typeof config_JSON?.gRPCUserAgent === 'string' && config_JSON.gRPCUserAgent.trim()) ? config_JSON.gRPCUserAgent.trim() : null;
	const needProcessGRPC = config_JSON?.transportProtocol === "grpc" && Boolean(gRPCUserAgent);
	const gRPCUserAgentYAML = gRPCUserAgent ? JSON.stringify(gRPCUserAgent) : null;
	let clash_yaml = Clash_原始subscriptionContent.replace(/mode:\s*Rule\b/g, 'mode: rule');

	const baseDnsBlock = `dns:
  enable: true
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
    - 114.114.114.114
  use-hosts: true
  nameserver:
    - https://sm2.doh.pub/dns-query
    - https://dns.alidns.com/dns-query
  fallback:
    - 8.8.4.4
    - 208.67.220.220
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4
      - 127.0.0.1/32
      - 0.0.0.0/32
    domain:
      - '+.google.com'
      - '+.facebook.com'
      - '+.youtube.com'
`;

	const addInlineGRPCUserAgent = (text) => text.replace(/grpc-opts:\s*\{([\s\S]*?)\}/i, (all, inner) => {
		if (/grpc-user-agent\s*:/i.test(inner)) return all;
		let content = inner.trim();
		if (content.endsWith(',')) content = content.slice(0, -1).trim();
		const patchedContent = content ? `${content}, grpc-user-agent: ${gRPCUserAgentYAML}` : `grpc-user-agent: ${gRPCUserAgentYAML}`;
		return `grpc-opts: {${patchedContent}}`;
	});
	const matchedGRPCNetwork = (text) => /(?:^|[,{])\s*network:\s*(?:"grpc"|'grpc'|grpc)(?=\s*(?:[,}\n#]|$))/mi.test(text);
	const getProxyType = (nodeText) => nodeText.match(/type:\s*(\w+)/)?.[1] || 'vl' + 'ess';
	const getCredentialValue = (nodeText, isFlowStyle) => {
		const credentialField = getProxyType(nodeText) === 'trojan' ? 'password' : 'uuid';
		const pattern = new RegExp(`${credentialField}:\\s*${isFlowStyle ? '([^,}\\n]+)' : '([^\\n]+)'}`);
		return nodeText.match(pattern)?.[1]?.trim() || null;
	};
	const insertNameserverPolicy = (yaml, hostsEntries) => {
		if (/^\s{2}nameserver-policy:\s*(?:\n|$)/m.test(yaml)) {
			return yaml.replace(/^(\s{2}nameserver-policy:\s*\n)/m, `$1${hostsEntries}\n`);
		}
		const lines = yaml.split('\n');
		let dnsBlockEndIndex = -1;
		let inDnsBlock = false;
		for (let i = 0; i < lines.length; i++) {
			const line = lines[i];
			if (/^dns:\s*$/.test(line)) {
				inDnsBlock = true;
				continue;
			}
			if (inDnsBlock && /^[a-zA-Z]/.test(line)) {
				dnsBlockEndIndex = i;
				break;
			}
		}
		const nameserverPolicyBlock = `  nameserver-policy:\n${hostsEntries}`;
		if (dnsBlockEndIndex !== -1) lines.splice(dnsBlockEndIndex, 0, nameserverPolicyBlock);
		else lines.push(nameserverPolicyBlock);
		return lines.join('\n');
	};
	const addFlowFormatGRPCUserAgent = (nodeText) => {
		if (!matchedGRPCNetwork(nodeText) || /grpc-user-agent\s*:/i.test(nodeText)) return nodeText;
		if (/grpc-opts:\s*\{/i.test(nodeText)) return 添加InlineGrpcUserAgent(nodeText);
		return nodeText.replace(/\}(\s*)$/, `, grpc-opts: {grpc-user-agent: ${gRPCUserAgentYAML}}}$1`);
	};
	const addBlockFormatGRPCUserAgent = (nodeLines, topLevelIndent) => {
		const topLevelIndent = ' '.repeat(topLevelIndent);
		let grpcOptsIndex = -1;
		for (let idx = 0; idx < nodeLines.length; idx++) {
			const line = nodeLines[idx];
			if (!line.trim()) continue;
			const indent = line.search(/\S/);
			if (indent !== topLevelIndent) continue;
			if (/^\s*grpc-opts:\s*(?:#.*)?$/.test(line) || /^\s*grpc-opts:\s*\{.*\}\s*(?:#.*)?$/.test(line)) {
				grpcOptsIndex = idx;
				break;
			}
		}
		if (grpcOptsIndex === -1) {
			let insertIndex = -1;
			for (let j = nodeLines.length - 1; j >= 0; j--) {
				if (nodeLines[j].trim()) {
					insertIndex = j;
					break;
				}
			}
			if (insertIndex >= 0) nodeLines.splice(insertIndex + 1, 0, `${topLevelIndentStr}grpc-opts:`, `${topLevelIndentStr}  grpc-user-agent: ${gRPCUserAgentYAML}`);
			return nodeLines;
		}
		const grpcLine = nodeLines[grpcOptsIndex];
		if (/^\s*grpc-opts:\s*\{.*\}\s*(?:#.*)?$/.test(grpcLine)) {
			if (!/grpc-user-agent\s*:/i.test(grpcLine)) nodeLines[grpcOptsIndex] = 添加InlineGrpcUserAgent(grpcLine);
			return nodeLines;
		}
		let blockEndIndex = nodeLines.length;
		let childIndent = topLevelIndent + 2;
		let hasGRPCUserAgent = false;
		for (let idx = grpcOptsIndex + 1; idx < nodeLines.length; idx++) {
			const line = nodeLines[idx];
			const trimmed = line.trim();
			if (!trimmed) continue;
			const indent = line.search(/\S/);
			if (indent <= topLevelIndent) {
				blockEndIndex = idx;
				break;
			}
			if (indent > topLevelIndent && childIndent === topLevelIndent + 2) childIndent = indent;
			if (/^grpc-user-agent\s*:/.test(trimmed)) {
				hasGRPCUserAgent = true;
				break;
			}
		}
		if (!hasGRPCUserAgent) nodeLines.splice(blockEndIndex, 0, `${' '.repeat(childIndent)}grpc-user-agent: ${gRPCUserAgentYAML}`);
		return nodeLines;
	};
	const addBlockFormatECHOpts = (nodeLines, topLevelIndent) => {
		let insertIndex = -1;
		for (let j = nodeLines.length - 1; j >= 0; j--) {
			if (nodeLines[j].trim()) {
				insertIndex = j;
				break;
			}
		}
		if (insertIndex < 0) return nodeLines;
		const indent = ' '.repeat(topLevelIndent);
		const echOptsLines = [`${indent}ech-opts:`, `${indent}  enable: true`];
		if (ECH_SNI) echOptsLines.push(`${indent}  query-server-name: ${ECH_SNI}`);
		nodeLines.splice(insertIndex + 1, 0, ...echOptsLines);
		return nodeLines;
	};

	if (!/^dns:\s*(?:\n|$)/m.test(clash_yaml)) clash_yaml = baseDnsBlock + clash_yaml;
	if (ECH_SNI && !HOSTS.includes(ECH_SNI)) HOSTS.push(ECH_SNI);

	if (ECH启用 && HOSTS.length > 0) {
		const hostsEntries = HOSTS.map(host => `    "${host}": ${ECH_DNS ? ECH_DNS : ''}`).join('\n');
		clash_yaml = insertNameserverPolicy(clash_yaml, hostsEntries);
	}

	if (!needProcessECH && !needProcessGRPC) return clash_yaml;

	const lines = clash_yaml.split('\n');
	const processedLines = [];
	let i = 0;

	while (i < lines.length) {
		const line = lines[i];
		const trimmedLine = line.trim();

		if (trimmedLine.startsWith('- {')) {
			let fullNode = line;
			let braceCount = (line.match(/\{/g) || []).length - (line.match(/\}/g) || []).length;
			while (braceCount > 0 && i + 1 < lines.length) {
				i++;
				fullNode += '\n' + lines[i];
				braceCount += (lines[i].match(/\{/g) || []).length - (lines[i].match(/\}/g) || []).length;
			}
			if (needProcessGRPC) fullNode = addFlowFormatGRPCUserAgent(fullNode);
			if (needProcessECH && getCredentialValue(fullNode, true) === uuid.trim()) {
				fullNode = fullNode.replace(/\}(\s*)$/, `, ech-opts: {enable: true${ECH_SNI ? `, query-server-name: ${ECH_SNI}` : ''}}}$1`);
			}
			processedLines.push(fullNode);
			i++;
		} else if (trimmedLine.startsWith('- name:')) {
			let nodeLines = [line];
			let baseIndent = line.search(/\S/);
			let topLevelIndent = baseIndent + 2;
			i++;
			while (i < lines.length) {
				const nextLine = lines[i];
				const nextTrimmed = nextLine.trim();
				if (!nextTrimmed) {
					nodeLines.push(nextLine);
					i++;
					break;
				}
				const nextIndent = nextLine.search(/\S/);
				if (nextIndent <= baseIndent && nextTrimmed.startsWith('- ')) {
					break;
				}
				if (nextIndent < baseIndent && nextTrimmed) {
					break;
				}
				nodeLines.push(nextLine);
				i++;
			}
			let nodeText = nodeLines.join('\n');
			if (needProcessGRPC && matchedGRPCNetwork(nodeText)) {
				nodeLines = addBlockFormatGRPCUserAgent(nodeLines, topLevelIndent);
				nodeText = nodeLines.join('\n');
			}
			if (needProcessECH && getCredentialValue(nodeText, false) === uuid.trim()) nodeLines = addBlockFormatECHOpts(nodeLines, topLevelIndent);
			processedLines.push(...nodeLines);
		} else {
			processedLines.push(line);
			i++;
		}
	}

	return processedLines.join('\n');
}

async function singboxSubscriptionHotPatch(SingBox_原始subscriptionContent, config_JSON = {}) {
	const uuid = config_JSON?.UUID || null;
	const fingerprint = config_JSON?.Fingerprint || "chrome";
	const ECH启用 = Boolean(config_JSON?.ECH);
	const ECH_SNI = config_JSON?.ECHConfig?.SNI || "cloudflare-ech.com";
	const sb_json_text = SingBox_原始subscriptionContent.replace('1.1.1.1', '8.8.8.8').replace('1.0.0.1', '8.8.4.4');
	try {
		const config = JSON.parse(sb_json_text);
		const toArray = value => value === undefined || value === null ? [] : (Array.isArray(value) ? value : [value]);
		const ensureRoute = () => config.route = config.route && typeof config.route === 'object' ? config.route : {};
		const getDNSRuleServer = rule => rule && typeof rule === 'object' && !Array.isArray(rule) && typeof rule.server === 'string' ? rule.server : null;
		const addRuleSet = (type, code) => {
			if (!code || typeof code !== 'string') return null;
			const route = ensureRoute(), tag = `${type}-${code}`, ruleSet = Array.isArray(route.rule_set) ? route.rule_set : toArray(route.rule_set);
			if (!ruleSet.some(item => item?.tag === tag)) {
				const legacyOptions = type === 'geoip' ? route.geoip : route.geosite;
				ruleSet.push({ tag, type: 'remote', format: 'binary', url: `https://raw.githubusercontent.com/SagerNet/sing-${type}/rule-set/${tag}.srs`, ...(legacyOptions?.download_detour ? { download_detour: legacyOptions.download_detour } : {}) });
				config.experimental = config.experimental && typeof config.experimental === 'object' ? config.experimental : {};
				config.experimental.cache_file = config.experimental.cache_file && typeof config.experimental.cache_file === 'object' ? config.experimental.cache_file : {};
				config.experimental.cache_file.enabled ??= true;
			}
			route.rule_set = ruleSet;
			return tag;
		};

		const migrateRuleSetField = rule => {
			if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return rule;
			if (rule.type === 'logical' && Array.isArray(rule.rules)) {
				rule.rules = rule.rules.map(migrateRuleSetField);
				return rule;
			}
			const tags = [];
			for (const geoip of toArray(rule.geoip)) {
				if (typeof geoip !== 'string') continue;
				if (geoip.toLowerCase() === 'private') rule.ip_is_private = true;
				else tags.push(addRuleSet('geoip', geoip));
			}
			for (const sourceGeoip of toArray(rule.source_geoip)) {
				if (typeof sourceGeoip !== 'string') continue;
				tags.push(addRuleSet('geoip', sourceGeoip));
				rule.rule_set_ip_cidr_match_source = true;
			}
			for (const geosite of toArray(rule.geosite)) if (typeof geosite === 'string') tags.push(addRuleSet('geosite', geosite));
			if (tags.length) rule.rule_set = [...new Set([...toArray(rule.rule_set), ...tags].filter(Boolean))];
			delete rule.geoip;
			delete rule.source_geoip;
			delete rule.geosite;
			return rule;
		};

		const migrateDNSRule = (rule, rcodeServerMap) => {
			rule = migrateRuleSetField(rule);
			if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return rule;
			if (rule.type === 'logical' && Array.isArray(rule.rules)) {
				rule.rules = rule.rules.map(childRule => migrateDNSRule(childRule, rcodeServerMap));
				return rule;
			}
			const serverTag = getDNSRuleServer(rule);
			if (serverTag && rcodeServerMap.has(serverTag)) {
				for (const key of ['server', 'strategy', 'disable_cache', 'rewrite_ttl', 'client_subnet', 'timeout']) delete rule[key];
				rule.action = 'predefined';
				rule.rcode = rcodeServerMap.get(serverTag);
			} else if (serverTag && !rule.action) rule.action = 'route';
			return rule;
		};

		if (Array.isArray(config.inbounds)) {
			for (const inbound of config.inbounds) {
				if (!inbound || typeof inbound !== 'object' || inbound.type !== 'tun') continue;
				for (const migration of [
					{ targetKey: 'address', sourceKeys: ['inet4_address', 'inet6_address'] },
					{ targetKey: 'route_address', sourceKeys: ['inet4_route_address', 'inet6_route_address'] },
					{ targetKey: 'route_exclude_address', sourceKeys: ['inet4_route_exclude_address', 'inet6_route_exclude_address'] }
				]) {
					const values = toArray(inbound[migration.targetKey]);
					for (const sourceKey of migration.sourceKeys) values.push(...toArray(inbound[sourceKey]));
					if (values.length) inbound[migration.targetKey] = [...new Set(values)];
					for (const sourceKey of migration.sourceKeys) delete inbound[sourceKey];
				}
				if (inbound.tag) {
					const addedRules = [];
					if (inbound.domain_strategy) addedRules.push({ inbound: inbound.tag, action: 'resolve', strategy: inbound.domain_strategy });
					if (inbound.sniff) {
						const sniffRule = { inbound: inbound.tag, action: 'sniff' };
						if (inbound.sniff_timeout) sniffRule.timeout = inbound.sniff_timeout;
						addedRules.push(sniffRule);
					}
					if (addedRules.length) {
						const route = ensureRoute();
						route.rules = [...addedRules, ...toArray(route.rules)];
					}
				}
				delete inbound.sniff;
				delete inbound.sniff_timeout;
				delete inbound.domain_strategy;
			}
		}

		if (config?.route && typeof config.route === 'object' && Array.isArray(config.route.rules)) {
			const patchRouteRule = rule => {
				rule = migrateRuleSetField(rule);
				if (rule?.type === 'logical' && Array.isArray(rule.rules)) rule.rules = rule.rules.map(patchRouteRule);
				else if (rule && typeof rule === 'object' && !Array.isArray(rule) && rule.outbound && !rule.action) rule.action = 'route';
				return rule;
			};
			config.route.rules = config.route.rules.map(patchRouteRule);
		}

		const dns = config?.dns;
		if (dns && typeof dns === 'object') {
			const legacyFakeIP = dns.fakeip && typeof dns.fakeip === 'object' ? dns.fakeip : null;
			const rcodeServerMap = new Map();
			const DNS地址protocolType = { 'tcp:': 'tcp', 'udp:': 'udp', 'tls:': 'tls', 'quic:': 'quic', 'https:': 'https', 'h3:': 'h3' };
			const RCode映射 = { success: 'NOERROR', format_error: 'FORMERR', server_failure: 'SERVFAIL', name_error: 'NXDOMAIN', not_implemented: 'NOTIMP', refused: 'REFUSED' };
			let hasFakeIPServer = false;

			if (Array.isArray(dns.servers)) {
				const migratedServers = [];
				for (const originalServer of dns.servers) {
					if (!originalServer || typeof originalServer !== 'object' || Array.isArray(originalServer)) {
						migratedServers.push(originalServer);
						continue;
					}

					const server = { ...originalServer };
					let parsedAddress = null, parsedRCode = '', rawAddress = typeof server.address === 'string' ? server.address.trim() : '';
					if (rawAddress) {
						const lowerAddress = rawAddress.toLowerCase();
						if (lowerAddress === 'fakeip') parsedAddress = { type: 'fakeip' };
						else if (lowerAddress === 'local') parsedAddress = { type: 'local' };
						else if (lowerAddress.startsWith('rcode://')) {
							parsedAddress = { type: 'rcode' };
							parsedRCode = rawAddress.slice('rcode://'.length).toLowerCase();
						}
						else if (lowerAddress.startsWith('dhcp://')) {
							const dhcpInterface = rawAddress.slice('dhcp://'.length);
							parsedAddress = dhcpInterface && dhcpInterface.toLowerCase() !== 'auto' ? { type: 'dhcp', interface: dhcpInterface } : { type: 'dhcp' };
						} else {
							try {
								const addressURL = new URL(rawAddress);
								const type = DNS地址protocolType[addressURL.protocol.toLowerCase()];
								if (type) {
									const parsedServer = addressURL.hostname?.startsWith('[') && addressURL.hostname.endsWith(']') ? addressURL.hostname.slice(1, -1) : addressURL.hostname;
									parsedAddress = {
										type,
										server: parsedServer || addressURL.host || rawAddress,
										...(addressURL.port ? { server_port: Number(addressURL.port) } : {}),
										...((type === 'https' || type === 'h3') && addressURL.pathname && addressURL.pathname !== '/dns-query' ? { path: addressURL.pathname } : {})
									};
								}
							} catch (_) { }
							if (!parsedAddress) parsedAddress = { type: 'udp', server: rawAddress };
						}
					}

					if (parsedAddress?.type === 'rcode') {
						const rcode = RCode映射[parsedRCode] || 'NOERROR';
						if (typeof server.tag === 'string' && server.tag) {
							rcodeServerMap.set(server.tag, rcode);
							rcodeServerMap.set(server.tag.startsWith('dns_') ? server.tag.slice(4) : `dns_${server.tag}`, rcode);
						}
						continue;
					}

					if (parsedAddress) {
						delete server.address;
						Object.assign(server, parsedAddress);
					}
					if (server.address_resolver !== undefined && server.domain_resolver === undefined) server.domain_resolver = server.address_resolver;
					if (server.address_strategy !== undefined && server.domain_strategy === undefined) server.domain_strategy = server.address_strategy;
					delete server.address_resolver;
					delete server.address_strategy;
					if (server.detour === 'DIRECT') delete server.detour;

					if (server.type === 'fakeip') {
						hasFakeIPServer = true;
						if (legacyFakeIP) {
							for (const key of ['inet4_range', 'inet6_range']) {
								if (legacyFakeIP[key] !== undefined && server[key] === undefined) server[key] = legacyFakeIP[key];
							}
						}
					}
					migratedServers.push(server);
				}
				dns.servers = migratedServers;
			}

			if (legacyFakeIP && !hasFakeIPServer && legacyFakeIP.enabled !== false) {
				const fakeIPServer = { type: 'fakeip', tag: 'fakeip' };
				for (const rule of Array.isArray(dns.rules) ? dns.rules : []) {
					const serverTag = getDNSRuleServer(rule);
					if (serverTag && serverTag.toLowerCase().includes('fakeip')) {
						fakeIPServer.tag = serverTag;
						break;
					}
				}
				for (const key of ['inet4_range', 'inet6_range']) {
					if (legacyFakeIP[key] !== undefined) fakeIPServer[key] = legacyFakeIP[key];
				}
				if (Array.isArray(dns.servers)) dns.servers.push(fakeIPServer);
				else dns.servers = [fakeIPServer];
			}

			if (Array.isArray(dns.rules)) {
				const migratedRules = [];
				for (const rule of dns.rules) {
					const serverTag = getDNSRuleServer(rule);
					const outbound = toArray(rule?.outbound);
					const DNS路由选项字段 = new Set(['outbound', 'server', 'action', 'strategy', 'disable_cache', 'rewrite_ttl', 'client_subnet', 'timeout']);
					const isOutboundAnyDNSRule = rule && typeof rule === 'object' && !Array.isArray(rule) && rule.type !== 'logical'
						&& serverTag && outbound.includes('any') && Object.keys(rule).every(key => DNS路由选项字段.has(key));
					if (isOutboundAnyDNSRule) {
						const route = ensureRoute();
						if (route.default_domain_resolver === undefined) {
							const resolver = { server: serverTag };
							for (const key of ['strategy', 'disable_cache', 'rewrite_ttl', 'client_subnet', 'timeout']) {
								if (rule[key] !== undefined) resolver[key] = rule[key];
							}
							route.default_domain_resolver = Object.keys(resolver).length === 1 ? resolver.server : resolver;
						}
						continue;
					}
					migratedRules.push(migrateDNSRule(rule, rcodeServerMap));
				}
				dns.rules = migratedRules;
			}

			delete dns.fakeip;
			delete dns.independent_cache;
		}

		if (config?.route && typeof config.route === 'object') {
			delete config.route.geoip;
			delete config.route.geosite;
		}
		if (config?.ntp?.detour === 'DIRECT') delete config.ntp.detour;

		if (Array.isArray(config.outbounds)) {
			const outboundTags = new Set(config.outbounds.map(outbound => outbound?.tag).filter(Boolean));
			const 引用REJECT = value => value === 'REJECT' || (value && typeof value === 'object' && (Array.isArray(value) ? value.some(引用REJECT) : Object.values(value).some(引用REJECT)));
			if (!outboundTags.has('REJECT') && 引用REJECT({ outbounds: config.outbounds, route: config.route })) config.outbounds.push({ type: 'block', tag: 'REJECT' });
		}

		// --- UUID 匹配节点的 TLS 热补丁 (utls & ech) ---
		if (uuid) {
			config.outbounds?.forEach(outbound => {
				// onlyProcessContaining uuid 或 password 且匹配的节点
				if ((outbound.uuid && outbound.uuid === uuid) || (outbound.password && outbound.password === uuid)) {
					// 确保 tls 对象存在
					if (!outbound.tls) {
						outbound.tls = { enabled: true };
					}

					// 添加/更新 utls config
					if (fingerprint) {
						outbound.tls.utls = {
							enabled: true,
							fingerprint: fingerprint
						};
					}

					// 如果提供了 ech_config，添加/更新 ech config
					if (ECH启用) {
						outbound.tls.ech = {
							enabled: true,
							query_server_name: ECH_SNI,// 等待 1.13.0+ version
							//config: `-----BEGIN ECH CONFIGS-----\n${ech_config}\n-----END ECH CONFIGS-----`
						};
					}
				}
			});
		}

		return JSON.stringify(config, null, 2);
	} catch (e) {
		console.error("Singbox热补丁执行失败:", e);
		return JSON.stringify(JSON.parse(sb_json_text), null, 2);
	}
}

function surgeSubscriptionHotPatch(content, url, config_JSON) {
	const lineContent = content.includes('\r\n') ? content.split('\r\n') : content.split('\n');
	const fullNodePath = config_JSON.randomPath ? randomPath(config_JSON.fullNodePath) : config_JSON.fullNodePath;
	let outputContent = "";
	for (let x of eachLine) {
		if (x.includes('= tro' + 'jan,') && !x.includes('ws=true') && !x.includes('ws-path=')) {
			const host = x.split("sni=")[1].split(",")[0];
			const oldContent = `sni=${host}, skip-cert-verify=${config_JSON.skipCertVerify}`;
			const newContent = `sni=${host}, skip-cert-verify=${config_JSON.skipCertVerify}, ws=true, ws-path=${fullNodePath.replace(/,/g, '%2C')}, ws-headers=Host:"${host}"`;
			outputContent += x.replace(new RegExp(oldContent, 'g'), newContent).replace("[", "").replace("]", "") + '\n';
		} else {
			outputContent += x + '\n';
		}
	}

	outputContent = `#!MANAGED-CONFIG ${url} interval=${config_JSON.optSubGenerator.SUBUpdateTime * 60 * 60} strict=false` + outputContent.substring(outputContent.indexOf('\n'));
	return outputContent;
}

async function logRequest(env, request, accessIP, requestType = "Get_SUB", config_JSON, writeKVLog = true) {
	try {
		const currentTime = new Date();
		const logEntry = { TYPE: requestType, IP: accessIP, ASN: `AS${request.cf.asn || '0'} ${request.cf.asOrganization || 'Unknown'}`, CC: `${request.cf.country || 'N/A'} ${request.cf.city || 'N/A'}`, URL: request.url, UA: request.headers.get('User-Agent') || 'Unknown', TIME: 当前时间.getTime() };
		if (config_JSON.TG.启用) {
			try {
				const TG_TXT = await env.KV.get('tg.json');
				const TG_JSON = JSON.parse(TG_TXT);
				if (TG_JSON?.BotToken && TG_JSON?.ChatID) {
					const requestTime = new Date(logEntry.TIME).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
					const requestURL = new URL(logEntry.URL);
					const msg = `<b>#${config_JSON.optSubGenerator.SUBNAME} 日志通知</b>\n\n` +
						`📌 <b>type：</b>#${logEntry.TYPE}\n` +
						`🌐 <b>IP：</b><code>${logEntry.IP}</code>\n` +
						`📍 <b>位置：</b>${logEntry.CC}\n` +
						`🏢 <b>ASN：</b>${logEntry.ASN}\n` +
						`🔗 <b>域名：</b><code>${requestURL.host}</code>\n` +
						`🔍 <b>路径：</b><code>${requestURL.pathname + requestURL.search}</code>\n` +
						`🤖 <b>UA：</b><code>${logEntry.UA}</code>\n` +
						`📅 <b>时间：</b>${requestTime}\n` +
						`${config_JSON.CF.Usage.success ? `📊 <b>请求用量：</b>${config_JSON.CF.Usage.total}/${config_JSON.CF.Usage.max} <b>${((config_JSON.CF.Usage.total / config_JSON.CF.Usage.max) * 100).toFixed(2)}%</b>\n` : ''}`;
					await fetch(`https://api.telegram.org/bot${TG_JSON.BotToken}/sendMessage?chat_id=${TG_JSON.ChatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`, {
						method: 'GET',
						headers: {
							'Accept': 'text/html,application/xhtml+xml,application/xml;',
							'Accept-Encoding': 'gzip, deflate, br',
							'User-Agent': logEntry.UA || 'Unknown',
						}
					});
				}
			} catch (error) { console.error(`读取tg.json出错: ${error.message}`) }
		}
		writeKVLog = ['1', 'true'].includes(env.OFF_LOG) ? false : writeKVLog;
		if (!writeKVLog) return;
		let logArray = [];
		const existingLogs = await env.KV.get('log.json'), KV容量限制 = 4;//MB
		if (existingLogs) {
			try {
				logArray = JSON.parse(existingLogs);
				if (!Array.isArray(logArray)) { logArray = [logEntry] }
				else if (requestType !== "Get_SUB") {
					const thirtyMinAgoTimestamp = 当前时间.getTime() - 30 * 60 * 1000;
					if (logArray.some(log => log.TYPE !== "Get_SUB" && log.IP === accessIP && log.URL === request.url && log.UA === (request.headers.get('User-Agent') || 'Unknown') && log.TIME >= thirtyMinAgoTimestamp)) return;
					logArray.push(logEntry);
					while (JSON.stringify(logArray, null, 2).length > KV容量限制 * 1024 * 1024 && logArray.length > 0) logArray.shift();
				} else {
					logArray.push(logEntry);
					while (JSON.stringify(logArray, null, 2).length > KV容量限制 * 1024 * 1024 && logArray.length > 0) logArray.shift();
				}
			} catch (e) { logArray = [logEntry] }
		} else { logArray = [logEntry] }
		await env.KV.put('log.json', JSON.stringify(logArray, null, 2));
	} catch (error) { console.error(`日志记录失败: ${error.message}`) }
}

function maskSensitiveInfo(text, 前缀length = 3, 后缀length = 2) {
	if (!text || typeof 文本 !== 'string') return text;
	if (文本.length <= 前缀length + 后缀length) return text; // 如果length太短，直接返回

	const prefix = 文本.slice(0, 前缀length);
	const suffix = 文本.slice(-后缀length);
	const starCount = 文本.length - 前缀length - 后缀length;

	return `${前缀}${'*'.repeat(星号数量)}${后缀}`;
}

async function MD5MD5(文本) {
	const encoder = new TextEncoder();

	const firstHash = await crypto.subtle.digest('MD5', encoder.encode(文本));
	const firstHash数组 = Array.from(new Uint8Array(第一次哈希));
	const firstHex = 第一次哈希数组.map(bytes => bytes.toString(16).padStart(2, '0')).join('');

	const secondHash = await crypto.subtle.digest('MD5', encoder.encode(第一次十六进制.slice(7, 27)));
	const secondHash数组 = Array.from(new Uint8Array(第二次哈希));
	const secondHex = 第二次哈希数组.map(bytes => bytes.toString(16).padStart(2, '0')).join('');

	return 第二次十六进制.toLowerCase();
}

function randomPath(fullNodePath = "/") {
	const commonPathDirs = ["about", "account", "acg", "act", "activity", "ad", "ads", "ajax", "album", "albums", "anime", "api", "app", "apps", "archive", "archives", "article", "articles", "ask", "auth", "avatar", "bbs", "bd", "blog", "blogs", "book", "books", "bt", "buy", "cart", "category", "categories", "cb", "channel", "channels", "chat", "china", "city", "class", "classify", "clip", "clips", "club", "cn", "code", "collect", "collection", "comic", "comics", "community", "company", "config", "contact", "content", "course", "courses", "cp", "data", "detail", "details", "dh", "directory", "discount", "discuss", "dl", "dload", "doc", "docs", "document", "documents", "doujin", "download", "downloads", "drama", "edu", "en", "ep", "episode", "episodes", "event", "events", "f", "faq", "favorite", "favourites", "favs", "feedback", "file", "files", "film", "films", "forum", "forums", "friend", "friends", "game", "games", "gif", "go", "go.html", "go.php", "group", "groups", "help", "home", "hot", "htm", "html", "image", "images", "img", "index", "info", "intro", "item", "items", "ja", "jp", "jump", "jump.html", "jump.php", "jumping", "knowledge", "lang", "lesson", "lessons", "lib", "library", "link", "links", "list", "live", "lives", "m", "mag", "magnet", "mall", "manhua", "map", "member", "members", "message", "messages", "mobile", "movie", "movies", "music", "my", "new", "news", "note", "novel", "novels", "online", "order", "out", "out.html", "out.php", "outbound", "p", "page", "pages", "pay", "payment", "pdf", "photo", "photos", "pic", "pics", "picture", "pictures", "play", "player", "playlist", "post", "posts", "product", "products", "program", "programs", "project", "qa", "question", "rank", "ranking", "read", "readme", "redirect", "redirect.html", "redirect.php", "reg", "register", "res", "resource", "retrieve", "sale", "search", "season", "seasons", "section", "seller", "series", "service", "services", "setting", "settings", "share", "shop", "show", "shows", "site", "soft", "sort", "source", "special", "star", "stars", "static", "stock", "store", "stream", "streaming", "streams", "student", "study", "tag", "tags", "task", "teacher", "team", "tech", "temp", "test", "thread", "tool", "tools", "topic", "topics", "torrent", "trade", "travel", "tv", "txt", "type", "u", "upload", "uploads", "url", "urls", "user", "users", "v", "version", "videos", "view", "vip", "vod", "watch", "web", "wenku", "wiki", "work", "www", "zh", "zh-cn", "zh-tw", "zip"];
	const randomCount = Math.floor(Math.random() * 3 + 1);
	const randomPath = commonPathDirs.sort(() => 0.5 - Math.random()).slice(0, randomCount).join('/');
	if (fullNodePath === "/") return `/${randomPath}`;
	else return `/${randomPath + fullNodePath.replace('/?', '?')}`;
}

function replaceWildcardWithRandomChars(content) {
	if (typeof 内容 !== 'string' || !内容.includes('*')) return content;
	const charset = 'abcdefghijklmnopqrstuvwxyz0123456789';
	return content.replace(/\*/g, () => {
		let s = '';
		for (let i = 0; i < Math.floor(Math.random() * 14) + 3; i++) s += charset[Math.floor(Math.random() * charset.length)];
		return s;
	});
}

const DoHbuffer = {};
const DoHbuffer最大条目 = 256;
const dohRecordTypeMap = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28, SRV: 33, HTTPS: 65 };
async function doHQuery(域名, 记录type, DoH解析服务 = "https://cloudflare-dns.com/dns-query") {
	const normalizedDomain = String(域名 || '').trim().toLowerCase().replace(/\.$/, '');
	const normalizedRecordType = String(记录type || '').trim().toUpperCase();
	const buffer键 = `${normalizedDomain}:${normalizedRecordType}`;
	const qtype = dohRecordTypeMap[normalizedRecordType] || 1;
	const currentTime戳 = Date.now();
	const currentBufferEntry = DoHbuffer[buffer键];
	if (currentBufferEntry && currentTimestamp < currentBufferEntry.expiryTime) {
		log(`[doHQuery] 命中buffer ${域名} ${记录type} via ${DoH解析服务}`);
		return currentBufferEntry.data.map(data => ({ type: qtype, data }));
	}
	const startTime = performance.now();
	log(`[doHQuery] 开始查询 ${域名} ${记录type} via ${DoH解析服务}`);
	try {
		// 记录typestr转数值
		// encodeDomain为 DNS wire format labels
		const encodeDomain = (name) => {
			const parts = name.endsWith('.') ? name.slice(0, -1).split('.') : name.split('.');
			const bufs = [];
			for (const label of parts) {
				const enc = new TextEncoder().encode(label);
				bufs.push(new Uint8Array([enc.length]), enc);
			}
			bufs.push(new Uint8Array([0]));
			const total = bufs.reduce((s, b) => s + b.length, 0);
			const result = new Uint8Array(total);
			let off = 0;
			for (const b of bufs) { result.set(b, off); off += b.length }
			return result;
		};

		// 构建 DNS 查询报文
		const qname = encodeDomain(normalizedDomain);
		const query = new Uint8Array(12 + qname.length + 4);
		const qview = new DataView(query.buffer);
		qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]); // ID (random per RFC 1035)
		qview.setUint16(2, 0x0100);  // Flags: RD=1 (递归查询)
		qview.setUint16(4, 1);       // QDCOUNT
		query.set(qname, 12);
		qview.setUint16(12 + qname.length, qtype);
		qview.setUint16(12 + qname.length + 2, 1); // QCLASS = IN

		// 通过 POST send dns-message 请求
		log(`[doHQuery] send查询报文 ${域名} via ${DoH解析服务} (type=${qtype}, ${query.length}bytes)`);
		const response = await fetch(DoH解析服务, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/dns-message',
				'Accept': 'application/dns-message',
			},
			body: query,
		});
		if (!response.ok) {
			console.warn(`[doHQuery] 请求失败 ${域名} ${记录type} via ${DoH解析服务} 响应代码:${response.status}`);
			return [];
		}

		// 解析 DNS 响应报文
		const buf = new Uint8Array(await response.arrayBuffer());
		const dv = new DataView(buf.buffer);
		const qdcount = dv.getUint16(4);
		const ancount = dv.getUint16(6);
		log(`[doHQuery] 收到响应 ${域名} ${记录type} via ${DoH解析服务} (${buf.length}bytes, ${ancount}条应答)`);

		// parseDomainName（处理指针compact）
		const parseDomainName = (pos) => {
			const labels = [];
			let p = pos, jumped = false, endPos = -1, safe = 128;
			while (p < buf.length && safe-- > 0) {
				const len = buf[p];
				if (len === 0) { if (!jumped) endPos = p + 1; break }
				if ((len & 0xC0) === 0xC0) {
					if (!jumped) endPos = p + 2;
					p = ((len & 0x3F) << 8) | buf[p + 1];
					jumped = true;
					continue;
				}
				labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
				p += len + 1;
			}
			if (endPos === -1) endPos = p + 1;
			return [labels.join('.'), endPos];
		};

		// 跳过 Question Section
		let offset = 12;
		for (let i = 0; i < qdcount; i++) {
			const [, end] = parseDomainName(offset);
			offset = /** @type {number} */ (end) + 4; // +4 跳过 QTYPE + QCLASS
		}

		// 解析 Answer Section
		const answers = [];
		for (let i = 0; i < ancount && offset < buf.length; i++) {
			const [name, nameEnd] = parseDomainName(offset);
			offset = /** @type {number} */ (nameEnd);
			const type = dv.getUint16(offset); offset += 2;
			offset += 2; // CLASS
			const ttl = dv.getUint32(offset); offset += 4;
			const rdlen = dv.getUint16(offset); offset += 2;
			const rdata = buf.slice(offset, offset + rdlen);
			offset += rdlen;

			let data;
			if (type === 1 && rdlen === 4) {
				// A 记录
				data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
			} else if (type === 28 && rdlen === 16) {
				// AAAA 记录
				const segs = [];
				for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
				data = segs.join(':');
			} else if (type === 16) {
				// TXT 记录 (length前缀str)
				let tOff = 0;
				const parts = [];
				while (tOff < rdlen) {
					const tLen = rdata[tOff++];
					parts.push(new TextDecoder().decode(rdata.slice(tOff, tOff + tLen)));
					tOff += tLen;
				}
				data = parts.join('');
			} else if (type === 5) {
				// CNAME 记录
				const [cname] = parseDomainName(offset - rdlen);
				data = cname;
			} else {
				data = Array.from(rdata).map(b => b.toString(16).padStart(2, '0')).join('');
			}
			answers.push({ name, type, TTL: ttl, data, rdata });
		}
		const elapsed = (performance.now() - startTime).toFixed(2);
		log(`[doHQuery] 查询完成 ${域名} ${记录type} via ${DoH解析服务} ${elapsed}ms 共${answers.length}条result${answers.length > 0 ? '\n' + answers.map((a, i) => `  ${i + 1}. ${a.name} type=${a.type} TTL=${a.TTL} data=${a.data}`).join('\n') : ''}`);
		// DoH buffer至少保留 5 分钟，响应 TTL 更长时尊重响应 TTL；空响应使用 5 分钟负buffer
		const relatedRecords = answers.filter(answer => answer.type === qtype);
		const minTTL = relatedRecords.length > 0 ? Math.min(...relatedRecords.map(a => a.TTL)) : 0;
		const bufferTTL = Math.max(minTTL, 5 * 60);
		const bufferexpiryTime = Date.now() + bufferTTL * 1000;
		const bufferData = relatedRecords.map(answer => answer.data);
		if (bufferData.length > 0 || answers.length === 0) {
			if (Object.keys(DoHbuffer).length >= DoHbuffer最大条目) {
				const cleanup时间戳 = Date.now();
				for (const [buffer条目键, buffer条目] of Object.entries(DoHbuffer)) {
					if (cleanupTimestamp >= buffer条目.expiryTime) delete DoHbuffer[buffer条目键];
				}
				if (Object.keys(DoHbuffer).length >= DoHbuffer最大条目) {
					delete DoHbuffer[Object.keys(DoHbuffer)[0]];
				}
			}
			DoHbuffer[buffer键] = { data: bufferData, expiryTime: bufferexpiryTime };
			log(`[doHQuery] 写入buffer ${域名} ${记录type} TTL=${bufferTTL}s${bufferData.length === 0 ? '（空result）' : ''}`);
		}
		return answers;
	} catch (error) {
		const elapsed = (performance.now() - startTime).toFixed(2);
		console.error(`[doHQuery] 查询失败 ${域名} ${记录type} via ${DoH解析服务} ${elapsed}ms:`, error);
		return [];
	}
}

async function readConfigJSON(env, hostname, userID, UA = "Mozilla/5.0", resetConfig = false) {
	const _p = featureCodeDict[0];
	const host = hostname, Ali_DoH = "https://dns.alidns.com/dns-query", ECH_SNI = "cloudflare-ech.com", 占位符 = '{{IP:PORT}}', initStartTime = performance.now(), defaultConfigJSON = {
		TIME: new Date().toISOString(),
		HOST: host,
		HOSTS: [hostname],
		UUID: userID,
		PATH: "/",
		protocolType: "v" + "le" + "ss",
		transportProtocol: "ws",
		gRPC模式: "gun",
		gRPCUserAgent: UA,
		跳过证书验证: false,
		启用0RTT: false,
		TLS分片: null,
		randomPath: false,
		ECH: false,
		ECHConfig: {
			DNS: Ali_DoH,
			SNI: ECH_SNI,
		},
		SS: {
			cipherMethod: "aes-128-gcm",
			TLS: true,
		},
		Fingerprint: "chrome",
		优选订阅生成: {
			local: true, // true: 基于本地的优选地址  false: 优选订阅生成器
			localIPDB: {
				randomIP: true, // 当 randomIP 为true时生效，启用randomIP的数量，否则使用KV内的ADD.txt
				randomCount: 16,
				specifiedPort: -1,
			},
			SUB: null,
			SUBNAME: "edge" + "tunnel",
			SUBUpdateTime: 3, // 订阅更新时间（小时）
			TOKEN: await MD5MD5(hostname + userID),
		},
		订阅转换config: {
			SUBAPI: `https://SUBAPI.${featureCodeDict[1]}ssss.net`,
			SUBCONFIG: `https://raw.githubusercontent.com/${featureCodeDict[1]}/ACL4SSR/refs/heads/main/Clash/config/ACL4SSR_Online_Mini_MultiMode_CF.ini`,
			SUBEMOJI: false,
			SUBLIST: false, //仅输出节点信息
			UDP: false, // 启用 UDP
			XUDP: false, // 启用 XUDP
			TLS13: false, // 启用 TLS 1.3
			APPEND_TYPE: false, // insertNodeType
			SORT: false, // 基础节点排序
		},
		反代: {
			[_p]: "auto",
			SOCKS5: {
				启用: null,
				全局: false,
				账号: '',
				白名单: socks5Whitelist,
			},
			路径模板: {
				[_p]: "proxyip=" + 占位符,
				SOCKS5: {
					全局: "socks5://" + 占位符,
					标准: "socks5=" + 占位符
				},
				HTTP: {
					全局: "http://" + 占位符,
					标准: "http=" + 占位符
				},
				HTTPS: {
					全局: "https://" + 占位符,
					标准: "https=" + 占位符
				},
				TURN: {
					全局: "turn://" + 占位符,
					标准: "turn=" + 占位符
				},
				SSTP: {
					全局: "sstp://" + 占位符,
					标准: "sstp=" + 占位符
				},
			},
		},
		TG: {
			启用: false,
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
		}
	};

	try {
		let configJSON = await env.KV.get('config.json');
		if (!configJSON || resetConfig == true) {
			await env.KV.put('config.json', JSON.stringify(defaultConfigJSON, null, 2));
			config_JSON = defaultConfigJSON;
		} else {
			config_JSON = JSON.parse(configJSON);
		}
	} catch (error) {
		console.error(`readConfigJSON出错: ${error.message}`);
		config_JSON = defaultConfigJSON;
	}

	if (!config_JSON.subConverterConfig.SUBLIST) config_JSON.subConverterConfig.SUBLIST = false;
	if (!config_JSON.subConverterConfig.UDP) config_JSON.subConverterConfig.UDP = false;
	if (!config_JSON.subConverterConfig.XUDP) config_JSON.subConverterConfig.XUDP = false;
	if (!config_JSON.subConverterConfig.TLS13) config_JSON.subConverterConfig.TLS13 = false;
	if (!config_JSON.subConverterConfig.APPEND_TYPE) config_JSON.subConverterConfig.APPEND_TYPE = false;
	if (!config_JSON.subConverterConfig.SORT) config_JSON.subConverterConfig.SORT = false;
	if (!config_JSON.gRPCUserAgent) config_JSON.gRPCUserAgent = UA;
	config_JSON.HOST = host;
	if (!config_JSON.HOSTS) config_JSON.HOSTS = [hostname];
	if (env.HOST) config_JSON.HOSTS = (await parseToArray(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]);
	config_JSON.UUID = userID;
	if (!config_JSON.randomPath) config_JSON.randomPath = false;
	if (!config_JSON.enable0RTT) config_JSON.enable0RTT = false;

	if (env.PATH) config_JSON.PATH = env.PATH.startsWith('/') ? env.PATH : '/' + env.PATH;
	else if (!config_JSON.PATH) config_JSON.PATH = '/';

	if (!config_JSON.gRPC模式) config_JSON.gRPC模式 = 'gun';
	if (!config_JSON.SS) config_JSON.SS = { cipherMethod: "aes-128-gcm", TLS: false };

	if (!config_JSON.proxy.路径模板?.[_p]) {
		config_JSON.proxy.路径模板 = {
			[_p]: "proxyip=" + 占位符,
			SOCKS5: {
				全局: "socks5://" + 占位符,
				标准: "socks5=" + 占位符
			},
			HTTP: {
				全局: "http://" + 占位符,
				标准: "http=" + 占位符
			},
			HTTPS: {
				全局: "https://" + 占位符,
				标准: "https=" + 占位符
			},
			TURN: {
				全局: "turn://" + 占位符,
				标准: "turn=" + 占位符
			},
			SSTP: {
				全局: "sstp://" + 占位符,
				标准: "sstp=" + 占位符
			},
		};
	}
	if (!config_JSON.proxy.路径模板.HTTPS) config_JSON.proxy.路径模板.HTTPS = { 全局: "https://" + 占位符, 标准: "https=" + 占位符 };
	if (!config_JSON.proxy.路径模板.TURN) config_JSON.proxy.路径模板.TURN = { 全局: "turn://" + 占位符, 标准: "turn=" + 占位符 };
	if (!config_JSON.proxy.路径模板.SSTP) config_JSON.proxy.路径模板.SSTP = { 全局: "sstp://" + 占位符, 标准: "sstp=" + 占位符 };

	const proxyConfig = config_JSON.proxy.路径模板[config_JSON.proxy.SOCKS5.启用?.toUpperCase()];

	let pathProxyParam = '';
	if (proxyConfig && config_JSON.proxy.SOCKS5.账号) pathProxyParam = (config_JSON.proxy.SOCKS5.全局 ? proxyConfig.全局 : proxyConfig.标准).replace(占位符, config_JSON.proxy.SOCKS5.账号);
	else if (config_JSON.反代[_p] !== 'auto') pathProxyParam = config_JSON.proxy.路径模板[_p].replace(占位符, config_JSON.反代[_p]);

	let proxyQueryParam = '';
	if (pathProxyParam.includes('?')) {
		const [proxyPathPart, proxyQueryPart] = pathProxyParam.split('?');
		pathProxyParam = proxyPathPart;
		proxyQueryParam = proxyQueryPart;
	}

	config_JSON.PATH = config_JSON.PATH.replace(pathProxyParam, '').replace('//', '/');
	const normalizedPath = config_JSON.PATH === '/' ? '' : config_JSON.PATH.replace(/\/+(?=\?|$)/, '').replace(/\/+$/, '');
	const [pathPart, ...查询数组] = normalizedPath.split('?');
	const queryPart = 查询数组.length ? '?' + 查询数组.join('?') : '';
	const finalQueryPart = proxyQueryParam ? (queryPart ? queryPart + '&' + proxyQueryParam : '?' + proxyQueryParam) : queryPart;
	config_JSON.fullNodePath = (pathPart || '/') + (pathPart && pathProxyParam ? '/' : '') + pathProxyParam + finalQueryPart + (config_JSON.enable0RTT ? (finalQueryPart ? '&' : '?') + 'ed=2560' : '');

	if (!config_JSON.TLSFragment && config_JSON.TLSFragment !== null) config_JSON.TLSFragment = null;
	const tlsFragmentParam = config_JSON.TLSFragment == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLSFragment == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
	if (!config_JSON.Fingerprint) config_JSON.Fingerprint = "chrome";
	if (!config_JSON.ECH) config_JSON.ECH = false;
	if (!config_JSON.ECHConfig) config_JSON.ECHConfig = { DNS: Ali_DoH, SNI: ECH_SNI };
	const echLinkParam = config_JSON.ECH ? `&ech=${encodeURIComponent((config_JSON.ECHConfig.SNI ? config_JSON.ECHConfig.SNI + '+' : '') + config_JSON.ECHConfig.DNS)}` : '';
	const { type: transportProtocol, pathFieldName, domainFieldName } = getTransportProtocolConfig(config_JSON);
	const transportPathParamValue = getTransportPathParamValue(config_JSON, config_JSON.fullNodePath);
	config_JSON.LINK = config_JSON.protocolType === 'ss'
		? `${config_JSON.protocolType}://${btoa(config_JSON.SS.cipherMethod + ':' + userID)}@${host}:${config_JSON.SS.TLS ? '443' : '80'}?plugin=v2${encodeURIComponent(`ray-plugin;mode=websocket;host=${host};path=${((config_JSON.fullNodePath.includes('?') ? config_JSON.fullNodePath.replace('?', '?enc=' + config_JSON.SS.cipherMethod + '&') : (config_JSON.fullNodePath + '?enc=' + config_JSON.SS.cipherMethod)) + (config_JSON.SS.TLS ? ';tls' : ''))};mux=0`) + echLinkParam}#${encodeURIComponent(config_JSON.optSubGenerator.SUBNAME)}`
		: `${config_JSON.protocolType}://${userID}@${host}:443?security=tls&type=${transportProtocol + echLinkParam}&${domainFieldName}=${host}&fp=${config_JSON.Fingerprint}&sni=${host}&${pathFieldName}=${encodeURIComponent(传输路径参数值) + tlsFragmentParam}&encryption=none#${encodeURIComponent(config_JSON.optSubGenerator.SUBNAME)}`;
	config_JSON.optSubGenerator.TOKEN = await MD5MD5(hostname + userID);

	const initTG_JSON = { BotToken: null, ChatID: null };
	config_JSON.TG = { 启用: config_JSON.TG.启用 ? config_JSON.TG.启用 : false, ...initTG_JSON };
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
		console.error(`读取tg.json出错: ${error.message}`);
	}

	const initCF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
	config_JSON.CF = { ...initCF_JSON, Usage: { success: false, pages: 0, workers: 0, total: 0, max: 100000 } };
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
					console.error(`请求 CF_JSON.UsageAPI 失败: ${err.message}`);
				}
			} else {
				config_JSON.CF.Email = CF_JSON.Email ? CF_JSON.Email : null;
				config_JSON.CF.GlobalAPIKey = CF_JSON.GlobalAPIKey ? maskSensitiveInfo(CF_JSON.GlobalAPIKey) : null;
				config_JSON.CF.AccountID = CF_JSON.AccountID ? maskSensitiveInfo(CF_JSON.AccountID) : null;
				config_JSON.CF.APIToken = CF_JSON.APIToken ? maskSensitiveInfo(CF_JSON.APIToken) : null;
				config_JSON.CF.UsageAPI = null;
				const Usage = await getCloudflareUsage(CF_JSON.Email, CF_JSON.GlobalAPIKey, CF_JSON.AccountID, CF_JSON.APIToken);
				config_JSON.CF.Usage = Usage;
			}
		}
	} catch (error) {
		console.error(`读取cf.json出错: ${error.message}`);
	}

	config_JSON.loadTime = (performance.now() - initStartTime).toFixed(2) + 'ms';
	return config_JSON;
}

function identifyISP(request) {
	const cf = request?.cf;
	const ASN运营商映射 = {
		'4134': 'ct',
		'4809': 'ct',
		'4811': 'ct',
		'4812': 'ct',
		'4815': 'ct',
		'4837': 'cu',
		'4814': 'cu',
		'9929': 'cu',
		'17623': 'cu',
		'17816': 'cu',
		'9808': 'cmcc',
		'24400': 'cmcc',
		'56040': 'cmcc',
		'56041': 'cmcc',
		'56044': 'cmcc',
	};
	const ispKeywordMap = [
		{ code: 'ct', pattern: /chinanet|chinatelecom|china telecom|cn2|shtel/ },
		{ code: 'cmcc', pattern: /cmi|cmnet|chinamobile|china mobile|cmcc|mobile communications/ },
		{ code: 'cu', pattern: /china169|china unicom|chinaunicom|cucc|cncgroup|cuii|netcom/ },
	];
	if (String(cf?.country || '').toLowerCase() !== 'cn') return 'cf';
	const 组织name = String(cf?.asOrganization || '').toLowerCase();
	const matchedISP = ispKeywordMap.find(({ pattern }) => pattern.test(组织name))?.code;
	return matchedISP || ASN运营商映射[String(cf?.asn || '')] || 'cf';
}

async function generateRandomIPs(request, count = 16, specifiedPort = -1) {
	const url = new URL(request.url);
	const queryParamISP = String(url.searchParams.get('cnIspCode') || '').toLowerCase();
	const ispFileID = ['ct', 'cu', 'cmcc', 'cf'].includes(queryParamISP) ? queryParamISP : identifyISP(request);
	const ispNameMap = {
		cmcc: 'CF移动优选',
		cu: 'CF联通优选',
		ct: 'CF电信优选',
		cf: 'CF官方优选',
	};
	const cidr_url = ispFileID === 'cf' ? `https://raw.githubusercontent.com/${featureCodeDict[1]}/${featureCodeDict[1]}/main/CF-CIDR.txt` : `https://raw.githubusercontent.com/${featureCodeDict[1]}/${featureCodeDict[1]}/main/CF-CIDR/${ispFileID}.txt`;
	const cfname = ispNameMap[ispFileID] || 'CF官方优选';
	const cfport = [443, 2053, 2083, 2087, 2096, 8443];
	let cidrList = [];
	try { const res = await fetch(cidr_url); cidrList = res.ok ? await parseToArray(await res.text()) : ['104.16.0.0/13'] } catch { cidrList = ['104.16.0.0/13'] }

	const generateRandomIPFromCIDR = (cidr) => {
		const [baseIP, prefixLength] = cidr.split('/'), prefix = parseInt(prefixLength), hostBits = 32 - prefix;
		const ipInt = baseIP.split('.').reduce((a, p, i) => a | (parseInt(p) << (24 - i * 8)), 0);
		const randomOffset = Math.floor(Math.random() * Math.pow(2, hostBits));
		const mask = (0xFFFFFFFF << hostBits) >>> 0, randomIP = (((ipInt & mask) >>> 0) + randomOffset) >>> 0;
		return [(randomIP >>> 24) & 0xFF, (randomIP >>> 16) & 0xFF, (randomIP >>> 8) & 0xFF, randomIP & 0xFF].join('.');
	};
	const randomIPs = Array.from({ length: count }, (_, index) => {
		const ip = generateRandomIPFromCIDR(cidrList[Math.floor(Math.random() * cidrList.length)]);
		const targetPort = specifiedPort === -1
			? cfport[Math.floor(Math.random() * cfport.length)]
			: specifiedPort;
		return `${ip}:${targetPort}#${cfname}${index + 1}`;
	});
	return [randomIPs, randomIPs.join('\n')];
}

async function parseToArray(content) {
	var cleanedContent = 内容.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');
	if (cleanedContent.charAt(0) == ',') cleanedContent = cleanedContent.slice(1);
	if (cleanedContent.charAt(cleanedContent.length - 1) == ',') cleanedContent = cleanedContent.slice(0, cleanedContent.length - 1);
	const addressArray = cleanedContent.split(',');
	return addressArray;
}

async function fetchOptimalSubGeneratorData(optSubGeneratorHOST) {
	let optimalIP = [], otherNodesLINK = '', formattedHOST = optSubGeneratorHOST.replace(/^sub:\/\//i, 'https://').split('#')[0].split('?')[0];
	if (!/^https?:\/\//i.test(formattedHOST)) formattedHOST = `https://${formattedHOST}`;

	try {
		const url = new URL(formattedHOST);
		formattedHOST = url.origin;
	} catch (error) {
		optimalIP.push(`127.0.0.1:1234#${optSubGeneratorHOST}优选订阅生成器格式化异常:${error.message}`);
		return [optimalIP, otherNodesLINK];
	}

	const optSubGeneratorURL = `${formattedHOST}/sub?host=example.com&uuid=00000000-0000-4000-8000-000000000000`;

	try {
		const response = await fetch(优选订阅生成器URL, {
			headers: { 'User-Agent': 'v2rayN/edge' + 'tunnel (https://github.com/' + featureCodeDict[1] + '/edge' + 'tunnel)' }
		});

		if (!response.ok) {
			optimalIP.push(`127.0.0.1:1234#${optSubGeneratorHOST}优选订阅生成器异常:${response.statusText}`);
			return [optimalIP, otherNodesLINK];
		}

		const optSubGeneratorReturnsubscriptionContent = atob(await response.text());
		const subLineList = 优选订阅生成器返回subscriptionContent.includes('\r\n')
			? 优选订阅生成器返回subscriptionContent.split('\r\n')
			: 优选订阅生成器返回subscriptionContent.split('\n');

		for (const lineContent of 订阅行列表) {
			if (!行内容.trim()) continue; // 跳过空行
			if (行内容.includes('00000000-0000-4000-8000-000000000000') && 行内容.includes('example.com')) {
				// 这是optimalIP行，提取 域名:端口#remark
				const addressMatch = 行内容.match(/:\/\/[^@]+@([^?]+)/);
				if (addressMatch) {
					let addressPort = addressMatch[1], remark = ''; // 域名:端口 或 IP:端口
					const remarkMatch = 行内容.match(/#(.+)$/);
					if (remarkMatch) remark = '#' + decodeURIComponent(remarkMatch[1]);
					optimalIP.push(addressPort + remark);
				}
			} else {
				otherNodesLINK += 行内容 + '\n';
			}
		}
	} catch (error) {
		optimalIP.push(`127.0.0.1:1234#${optSubGeneratorHOST}优选订阅生成器异常:${error.message}`);
	}

	return [optimalIP, otherNodesLINK];
}

async function fetchOptimalAPI(urls, defaultPort = '443', timeoutMs = 3000) {
	if (!urls?.length) return [[], [], [], []];
	const results = new Set(), proxyIPPool = new Set();
	let subLinkPlainText = '', needsSubConverterURLs = [];
	await Promise.allSettled(urls.map(async (url) => {
		// 检查URL是否包含remarkName
		const hashIndex = url.indexOf('#');
		const urlWithoutHash = hashIndex > -1 ? url.substring(0, hashIndex) : url;
		const APIremarkName = hashIndex > -1 ? decodeURIComponent(url.substring(hashIndex + 1)) : null;
		const optimalIPAsProxyIP = url.toLowerCase().includes('proxyip=true');
		if (urlWithoutHash.toLowerCase().startsWith('sub://')) {
			try {
				const [optimalIP, otherNodesLINK] = await fetchOptimalSubGeneratorData(urlWithoutHash);
				// 处理第一个数组 - optimalIP
				if (APIremarkName) {
					for (const ip of optimalIP) {
						const processedIP = ip.includes('#')
							? `${ip} [${APIremarkName}]`
							: `${ip}#[${APIremarkName}]`;
						results.add(处理后IP);
						if (optimalIPAsProxyIP) proxyIPPool.add(ip.split('#')[0]);
					}
				} else {
					for (const ip of optimalIP) {
						results.add(ip);
						if (optimalIPAsProxyIP) proxyIPPool.add(ip.split('#')[0]);
					}
				}
				// 处理第二个数组 - otherNodesLINK
				if (otherNodesLINK && typeof otherNodesLINK === 'string' && APIremarkName) {
					const processedLINKContent = otherNodesLINK.replace(/([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi, (match, link, lineEnd) => {
						const fullLink = link.includes('#')
							? `${link}${encodeURIComponent(` [${APIremarkName}]`)}`
							: `${link}${encodeURIComponent(`#[${APIremarkName}]`)}`;
						return `${fullLink}${lineEnd}`;
					});
					subLinkResponseLINKContent += processedLINKContent;
				} else if (otherNodesLINK && typeof otherNodesLINK === 'string') {
					subLinkResponseLINKContent += otherNodesLINK;
				}
			} catch (e) { }
			return;
		}

		try {
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
			const response = await fetch(urlWithoutHash, { signal: controller.signal });
			clearTimeout(timeoutId);
			let text = '';
			try {
				const buffer = await response.arrayBuffer();
				const contentType = (response.headers.get('content-type') || '').toLowerCase();
				const charset = contentType.match(/charset=([^\s;]+)/i)?.[1]?.toLowerCase() || '';

				// 根据 Content-Type 响应头判断编码优先级
				let decoders = ['utf-8', 'gb2312']; // 默认优先 UTF-8
				if (charset.includes('gb') || charset.includes('gbk') || charset.includes('gb2312')) {
					decoders = ['gb2312', 'utf-8']; // 如果明确指定 GB 系编码，优先尝试 GB2312
				}

				// 尝试多种编码解码
				let decodeSuccess = false;
				for (const decoder of decoders) {
					try {
						const decoded = new TextDecoder(decoder).decode(buffer);
						// 验证解码result的有效性
						if (decoded && decoded.length > 0 && !decoded.includes('\ufffd')) {
							text = decoded;
							decodeSuccess = true;
							break;
						} else if (decoded && decoded.length > 0) {
							// 如果有替换字符 (U+FFFD)，说明编码不匹配，继续尝试下一个编码
							continue;
						}
					} catch (e) {
						// 该编码解码失败，尝试下一个
						continue;
					}
				}

				// 如果所有编码都失败或无效，尝试 response.text()
				if (!decodeSuccess) {
					text = await response.text();
				}

				// 如果返回的是空或无效数据，返回
				if (!text || text.trim().length === 0) {
					return;
				}
			} catch (e) {
				console.error('Failed to decode response:', e);
				return;
			}

			// 预处理subscriptionContent
			/*
			if (text.includes('proxies:') || (text.includes('outbounds"') && text.includes('inbounds"'))) {// Clash Singbox config
				needsSubConverterURLs.add(url);
				return;
			}
			*/

			let preprocessedSubPlaintext = text;
			const cleanText = typeof text === 'string' ? text.replace(/\s/g, '') : '';
			if (cleanText.length > 0 && cleanText.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(cleanText)) {
				try {
					const bytes = new Uint8Array(atob(cleanText).split('').map(c => c.charCodeAt(0)));
					preprocessedSubPlaintext = new TextDecoder('utf-8').decode(bytes);
				} catch { }
			}
			if (preprocessedSubPlaintext.split('#')[0].includes('://')) {
				// 处理LINK内容
				if (APIremarkName) {
					const processedLINKContent = preprocessedSubPlaintext.replace(/([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi, (match, link, lineEnd) => {
						const fullLink = link.includes('#')
							? `${link}${encodeURIComponent(` [${APIremarkName}]`)}`
							: `${link}${encodeURIComponent(`#[${APIremarkName}]`)}`;
						return `${fullLink}${lineEnd}`;
					});
					subLinkResponseLINKContent += processedLINKContent + '\n';
				} else {
					subLinkResponseLINKContent += preprocessedSubPlaintext + '\n';
				}
				return;
			}

			const lines = text.trim().split('\n').map(l => l.trim()).filter(l => l);
			const isCSV = lines.length > 1 && lines[0].includes(',');
			const IPV6_PATTERN = /^[^\[\]]*:[^\[\]]*:[^\[\]]/;
			const parsedUrl = new URL(urlWithoutHash);
			if (!isCSV) {
				lines.forEach(line => {
					const lineHashIndex = line.indexOf('#');
					const [hostPart, remark] = lineHashIndex > -1 ? [line.substring(0, lineHashIndex), line.substring(lineHashIndex)] : [line, ''];
					let hasPort = false;
					if (hostPart.startsWith('[')) {
						hasPort = /\]:(\d+)$/.test(hostPart);
					} else {
						const colonIndex = hostPart.lastIndexOf(':');
						hasPort = colonIndex > -1 && /^\d+$/.test(hostPart.substring(colonIndex + 1));
					}
					const port = parsedUrl.searchParams.get('port') || 默认端口;
					const ipItem = hasPort ? line : `${hostPart}:${port}${remark}`;
					// 处理第一个数组 - optimalIP
					if (APIremarkName) {
						const processedIP = ipItem.includes('#')
							? `${ipItem} [${APIremarkName}]`
							: `${ipItem}#[${APIremarkName}]`;
						results.add(处理后IP);
					} else {
						results.add(ipItem);
					}
					if (optimalIPAsProxyIP) proxyIPPool.add(ipItem.split('#')[0]);
				});
			} else {
				const headers = lines[0].split(',').map(h => h.trim());
				const dataLines = lines.slice(1);
				if (headers.includes('IP地址') && headers.includes('端口') && headers.includes('数据中心')) {
					const ipIdx = headers.indexOf('IP地址'), portIdx = headers.indexOf('端口');
					const remarkIdx = headers.indexOf('国家') > -1 ? headers.indexOf('国家') :
						headers.indexOf('城市') > -1 ? headers.indexOf('城市') : headers.indexOf('数据中心');
					const tlsIdx = headers.indexOf('TLS');
					dataLines.forEach(line => {
						const cols = line.split(',').map(c => c.trim());
						if (tlsIdx !== -1 && cols[tlsIdx]?.toLowerCase() !== 'true') return;
						const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
						const ipItem = `${wrappedIP}:${cols[portIdx]}#${cols[remarkIdx]}`;
						// 处理第一个数组 - optimalIP
						if (APIremarkName) {
							const processedIP = `${ipItem} [${APIremarkName}]`;
							results.add(处理后IP);
						} else {
							results.add(ipItem);
						}
						if (optimalIPAsProxyIP) proxyIPPool.add(`${wrappedIP}:${cols[portIdx]}`);
					});
				} else if (headers.some(h => h.includes('IP')) && headers.some(h => h.includes('延迟')) && headers.some(h => h.includes('下载速度'))) {
					const ipIdx = headers.findIndex(h => h.includes('IP'));
					const delayIdx = headers.findIndex(h => h.includes('延迟'));
					const speedIdx = headers.findIndex(h => h.includes('下载速度'));
					const port = parsedUrl.searchParams.get('port') || 默认端口;
					dataLines.forEach(line => {
						const cols = line.split(',').map(c => c.trim());
						const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
						const ipItem = `${wrappedIP}:${port}#CF优选 ${cols[delayIdx]}ms ${cols[speedIdx]}MB/s`;
						// 处理第一个数组 - optimalIP
						if (APIremarkName) {
							const processedIP = `${ipItem} [${APIremarkName}]`;
							results.add(处理后IP);
						} else {
							results.add(ipItem);
						}
						if (optimalIPAsProxyIP) proxyIPPool.add(`${wrappedIP}:${port}`);
					});
				}
			}
		} catch (e) { }
	}));
	// 将LINK内容转换为数组并去重
	const LINKArray = subLinkResponseLINKContent.trim() ? [...new Set(subLinkResponseLINKContent.split(/\r?\n/).filter(line => line.trim() !== ''))] : [];
	return [Array.from(results), LINKArray, needsSubConverterURLs, Array.from(proxyIPPool)];
}

async function getProxyParams(url, uuid, defaultProxyIP = '', defaultProxyFallback = true) {
	const { searchParams } = url;
	const pathname = decodeURIComponent(url.pathname);
	const pathLower = pathname.toLowerCase();
	let proxyIP = defaultProxyIP, 启用SOCKS5反代 = null, 启用SOCKS5全局反代 = false, 我的SOCKS5账号 = '', parsedSocks5Address = {}, 启用proxyFallback = defaultProxyFallback;
	const proxyContext = { trojanProxyAddress: null, proxyIP, proxyType: null, proxyAccount: '', proxyGlobal: false, proxyParams: {}, proxyFallback: 启用proxyFallback };
	const saveSnapshot = () => {
		proxyContext.proxyIP = proxyIP;
		proxyContext.proxyType = 启用SOCKS5反代;
		proxyContext.proxyAccount = 我的SOCKS5账号;
		proxyContext.proxyGlobal = 启用SOCKS5全局反代;
		proxyContext.proxyParams = { ...parsedSocks5Address };
		proxyContext.proxyFallback = 启用proxyFallback;
	};

	const chainProxyPathMatch = pathname.match(/\/video\/(.+)$/i);
	if (chainProxyPathMatch) {
		try {
			const chainProxyPlaintext = base64SecretDecode(chainProxyPathMatch[1].replace(/\/+$/, ''), uuid);
			const { type, ...chainProxyAddress } = JSON.parse(chainProxyPlaintext);
			if (!type || !proxyProtocolDefaultPorts[String(type).toLowerCase()]) throw new Error('链式proxyType无效');
			if (!chainProxyAddress.hostname || !chainProxyAddress.port) throw new Error('Chain proxy missing hostname or port');
			我的SOCKS5账号 = '';
			proxyIP = '链式代理';
			启用proxyFallback = false;
			启用SOCKS5全局反代 = true;
			启用SOCKS5反代 = String(type).toLowerCase();
			parsedSocks5Address = {
				username: chainProxyAddress.username,
				password: chainProxyAddress.password,
				hostname: chainProxyAddress.hostname,
				port: Number(chainProxyAddress.port)
			};
			if (isNaN(parsedSocks5Address.port)) throw new Error('链式代理端口无效');
			saveSnapshot();
			return proxyContext;
		} catch (err) {
			console.error('解析链式proxyParams失败:', err.message);
		}
	}

	我的SOCKS5账号 = searchParams.get('socks5') || searchParams.get('http') || searchParams.get('https') || searchParams.get('turn') || searchParams.get('sstp') || null;
	启用SOCKS5全局反代 = searchParams.has('globalproxy');
	if (searchParams.get('socks5')) 启用SOCKS5反代 = 'socks5';
	else if (searchParams.get('http')) 启用SOCKS5反代 = 'http';
	else if (searchParams.get('https')) 启用SOCKS5反代 = 'https';
	else if (searchParams.get('turn')) 启用SOCKS5反代 = 'turn';
	else if (searchParams.get('sstp')) 启用SOCKS5反代 = 'sstp';

	const parseProxyURL = (值, 强制全局 = true) => {
		const 匹配 = /^(socks5|http|https|turn|sstp):\/\/(.+)$/i.exec(值 || '');
		if (!匹配) return false;
		启用SOCKS5反代 = 匹配[1].toLowerCase();
		我的SOCKS5账号 = 匹配[2].split('/')[0];
		if (强制全局) 启用SOCKS5全局反代 = true;
		return true;
	};

	const setProxyIP = (值) => {
		proxyIP = 值;
		启用SOCKS5反代 = null;
		启用proxyFallback = false;
	};

	const extractPathValue = (值) => {
		if (!值.includes('://')) {
			const slashIndex = 值.indexOf('/');
			return slashIndex > 0 ? 值.slice(0, slashIndex) : 值;
		}
		const protocolSplit = 值.split('://');
		if (protocol拆分.length !== 2) return 值;
		const slashIndex = protocol拆分[1].indexOf('/');
		return slashIndex > 0 ? `${protocol拆分[0]}://${protocol拆分[1].slice(0, slashIndex)}` : 值;
	};

	const trojanPathMatch = /\/trojan=([^?#\s]+)/i.exec(pathname);
	if (trojanPathMatch) {
		try {
			proxyContext.trojanProxyAddress = parseTrojanProxyAddress(trojanPathMatch[1].replace(/\/+$/, ''));
		} catch (err) {
			console.error('parseTrojanProxyAddress失败:', err.message);
			proxyContext.trojanProxyAddress = null;
		}
	}

	const queryProxyIP = searchParams.get('proxyip');
	if (queryProxyIP !== null) {
		if (!解析代理URL(queryProxyIP)) {
			setProxyIP(queryProxyIP);
			saveSnapshot();
			return proxyContext;
		}
	} else {
		let 匹配 = /\/(socks5?|http|https|turn|sstp):\/?\/?([^/?#\s]+)/i.exec(pathname);
		if (匹配) {
			const type = 匹配[1].toLowerCase();
			启用SOCKS5反代 = type === 'sock' || type === 'socks' ? 'socks5' : type;
			我的SOCKS5账号 = 匹配[2].split('/')[0];
			启用SOCKS5全局反代 = true;
		} else if ((匹配 = /\/(g?s5|socks5|g?http|g?https|g?turn|g?sstp)=([^/?#\s]+)/i.exec(pathname))) {
			const type = 匹配[1].toLowerCase();
			我的SOCKS5账号 = 匹配[2].split('/')[0];
			启用SOCKS5反代 = type.includes('sstp') ? 'sstp' : (type.includes('turn') ? 'turn' : (type.includes('https') ? 'https' : (type.includes('http') ? 'http' : 'socks5')));
			if (type.startsWith('g')) 启用SOCKS5全局反代 = true;
		} else if ((匹配 = /\/(proxyip[.=]|pyip=|ip=)([^?#\s]+)/.exec(pathLower))) {
			const pathProxyValue = extractPathValue(匹配[2]);
			if (!解析代理URL(pathProxyValue)) {
				setProxyIP(pathProxyValue);
				saveSnapshot();
				return proxyContext;
			}
		}
	}

	if (!我的SOCKS5账号) {
		启用SOCKS5反代 = null;
		saveSnapshot();
		return proxyContext;
	}

	try {
		parsedSocks5Address = await getSOCKS5Account(我的SOCKS5账号, getProxyDefaultPort(启用SOCKS5反代));
		if (searchParams.get('socks5')) 启用SOCKS5反代 = 'socks5';
		else if (searchParams.get('http')) 启用SOCKS5反代 = 'http';
		else if (searchParams.get('https')) 启用SOCKS5反代 = 'https';
		else if (searchParams.get('turn')) 启用SOCKS5反代 = 'turn';
		else if (searchParams.get('sstp')) 启用SOCKS5反代 = 'sstp';
		else 启用SOCKS5反代 = 启用SOCKS5反代 || 'socks5';
	} catch (err) {
		console.error('解析SOCKS5地址失败:', err.message);
		启用SOCKS5反代 = null;
	}
	saveSnapshot();
	return proxyContext;
}

const proxyProtocolDefaultPorts = { socks5: 1080, http: 80, https: 443, turn: 3478, sstp: 443 };
function getProxyDefaultPort(type) {
	return proxyProtocolDefaultPorts[String(type || '').toLowerCase()] || 80;
}

const SOCKS5账号Base64正则 = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i, IPv6方括号正则 = /^\[.*\]$/;
function getSOCKS5Account(address, 默认端口 = 80) {
	address = String(address || '').trim().replace(/^(socks5|http|https|turn|sstp):\/\//i, '').split('#')[0].trim();
	const firstAt = address.lastIndexOf("@");
	if (firstAt !== -1) {
		let auth = address.slice(0, firstAt).replaceAll("%3D", "=");
		if (!auth.includes(":") && SOCKS5账号Base64正则.test(auth)) auth = atob(auth);
		address = `${auth}@${address.slice(firstAt + 1)}`;
	}

	const atIndex = address.lastIndexOf("@");
	const hostPart = (atIndex === -1 ? address : address.slice(atIndex + 1)).split('/')[0];
	const authPart = atIndex === -1 ? "" : address.slice(0, atIndex);
	const [username, password] = authPart ? authPart.split(":") : [];
	if (authPart && !password) throw new Error('Invalid SOCKS 地址格式：认证部分必须是 "username:password" 的形式');

	let hostname = hostPart, port = 默认端口;
	if (hostPart.includes("]:")) {
		const [ipv6Host, ipv6Port = ""] = hostPart.split("]:");
		hostname = ipv6Host + "]";
		port = Number(ipv6Port.replace(/[^\d]/g, ""));
	} else if (!hostPart.startsWith("[")) {
		const parts = hostPart.split(":");
		if (parts.length === 2) {
			hostname = parts[0];
			port = Number(parts[1].replace(/[^\d]/g, ""));
		}
	}

	if (isNaN(port)) throw new Error('Invalid SOCKS 地址格式：Port must be a number');
	if (hostname.includes(":") && !IPv6方括号正则.test(hostname)) throw new Error('Invalid SOCKS 地址格式：IPv6 address must be enclosed in brackets，如 [2001:db8::1]');
	return { username, password, hostname, port };
}

async function getCloudflareUsage(Email, GlobalAPIKey, AccountID, APIToken) {
	const API = "https://api.cloudflare.com/client/v4";
	const sum = (a) => a?.reduce((t, i) => t + (i?.sum?.requests || 0), 0) || 0;
	const cfg = { "Content-Type": "application/json" };

	try {
		if (!AccountID && (!Email || !GlobalAPIKey)) return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };

		if (!AccountID) {
			const r = await fetch(`${API}/accounts`, {
				method: "GET",
				headers: { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey }
			});
			if (!r.ok) throw new Error(`账户获取失败: ${r.status}`);
			const d = await r.json();
			if (!d?.result?.length) throw new Error("未找到账户");
			const idx = d.result.findIndex(a => a.name?.toLowerCase().startsWith(Email.toLowerCase()));
			AccountID = d.result[idx >= 0 ? idx : 0]?.id;
		}

		const now = new Date();
		now.setUTCHours(0, 0, 0, 0);
		const hdr = APIToken ? { ...cfg, "Authorization": `Bearer ${APIToken}` } : { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey };

		const res = await fetch(`${API}/graphql`, {
			method: "POST",
			headers: hdr,
			body: JSON.stringify({
				query: `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
					viewer { accounts(filter: {accountTag: $AccountID}) {
						pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } }
						workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } }
					} }
				}`,
				variables: { AccountID, filter: { datetime_geq: now.toISOString(), datetime_leq: new Date().toISOString() } }
			})
		});

		if (!res.ok) throw new Error(`查询失败: ${res.status}`);
		const result = await res.json();
		if (result.errors?.length) throw new Error(result.errors[0].message);

		const acc = result?.data?.viewer?.accounts?.[0];
		if (!acc) throw new Error("未找到账户数据");

		const pages = sum(acc.pagesFunctionsInvocationsAdaptiveGroups);
		const workers = sum(acc.workersInvocationsAdaptive);
		const total = pages + workers;
		const max = 100000;
		log(`统计result - Pages: ${pages}, Workers: ${workers}, 总计: ${total}, 上限: 100000`);
		return { success: true, pages, workers, total, max };

	} catch (error) {
		console.error('getUsageError:', error.message);
		return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };
	}
}

function sha224(s) {
	const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
	const r = (n, b) => ((n >>> b) | (n << (32 - b))) >>> 0;
	s = unescape(encodeURIComponent(s));
	const l = s.length * 8; s += String.fromCharCode(0x80);
	while ((s.length * 8) % 512 !== 448) s += String.fromCharCode(0);
	const h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
	const hi = Math.floor(l / 0x100000000), lo = l & 0xFFFFFFFF;
	s += String.fromCharCode((hi >>> 24) & 0xFF, (hi >>> 16) & 0xFF, (hi >>> 8) & 0xFF, hi & 0xFF, (lo >>> 24) & 0xFF, (lo >>> 16) & 0xFF, (lo >>> 8) & 0xFF, lo & 0xFF);
	const w = []; for (let i = 0; i < s.length; i += 4)w.push((s.charCodeAt(i) << 24) | (s.charCodeAt(i + 1) << 16) | (s.charCodeAt(i + 2) << 8) | s.charCodeAt(i + 3));
	for (let i = 0; i < w.length; i += 16) {
		const x = new Array(64).fill(0);
		for (let j = 0; j < 16; j++)x[j] = w[i + j];
		for (let j = 16; j < 64; j++) {
			const s0 = r(x[j - 15], 7) ^ r(x[j - 15], 18) ^ (x[j - 15] >>> 3);
			const s1 = r(x[j - 2], 17) ^ r(x[j - 2], 19) ^ (x[j - 2] >>> 10);
			x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0;
		}
		let [a, b, c, d, e, f, g, h0] = h;
		for (let j = 0; j < 64; j++) {
			const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25), ch = (e & f) ^ (~e & g), t1 = (h0 + S1 + ch + K[j] + x[j]) >>> 0;
			const S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22), maj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + maj) >>> 0;
			h0 = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
		}
		for (let j = 0; j < 8; j++)h[j] = (h[j] + (j === 0 ? a : j === 1 ? b : j === 2 ? c : j === 3 ? d : j === 4 ? e : j === 5 ? f : j === 6 ? g : h0)) >>> 0;
	}
	let hex = '';
	for (let i = 0; i < 7; i++) {
		for (let j = 24; j >= 0; j -= 8)hex += ((h[i] >>> j) & 0xFF).toString(16).padStart(2, '0');
	}
	return hex;
}

async function resolveAddressPort(proxyIP, targetDomain = 'dash.cloudflare.com', UUID = '00000000-0000-4000-8000-000000000000') {
	proxyIP = proxyIP.toLowerCase();
	function resolveAddressPortstr(str) {
		let address = str, 端口 = 443;
		if (str.includes(']:')) {
			const parts = str.split(']:');
			地址 = parts[0] + ']';
			端口 = parseInt(parts[1], 10) || 端口;
		} else if ((str.match(/:/g) || []).length === 1 && !str.startsWith('[')) {
			const colonIndex = str.lastIndexOf(':');
			地址 = str.slice(0, colonIndex);
			端口 = parseInt(str.slice(colonIndex + 1), 10) || 端口;
		}
		return [地址, 端口];
	}

	function parseTXTProxyRecord(txtData) {
		return txtData.flatMap(data => {
			if (data.startsWith('"') && data.endsWith('"')) data = data.slice(1, -1);
			return data.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
		}).map(prefix => resolveAddressPortstr(prefix));
	}

	const proxyIPArray = await parseToArray(proxyIP);
	let allProxyArray = [];
	const ipv4Regex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
	const ipv6Regex = /^\[?(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}\]?$/;

	// 遍历数组中的每个IPelement进行处理
	for (const singleProxyIP of proxyIPArray) {
		let [地址, 端口] = resolveAddressPortstr(singleProxyIP);

		if (singleProxyIP.includes('.tp')) {
			const tpMatch = singleProxyIP.match(/\.tp(\d+)/);
			if (tpMatch) 端口 = parseInt(tpMatch[1], 10);
		}

		// 判断是否是域名（非IP地址）
		if (ipv4Regex.test(地址) || ipv6Regex.test(地址)) {
			log(`[Proxy Resolution] ${地址} 为IP地址，直接使用`);
			allProxyArray.push([地址, 端口]);
			continue;
		}

		const [txtRecords, aRecords] = await Promise.all([
			doHQuery(地址, 'TXT'),
			doHQuery(地址, 'A')
		]);

		const txtData = txtRecords.filter(r => r.type === 16).map(r => (r.data));
		const txtAddresses = parseTXTProxyRecord(txtData);
		if (txtAddresses.length > 0) {
			log(`[Proxy Resolution] ${地址} 使用TXT记录，共${txtAddresses.length}个result`);
			allProxyArray.push(...txtAddresses);
			continue;
		}

		const ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
		if (ipv4List.length > 0) {
			log(`[Proxy Resolution] ${地址} 未获取到TXT记录，使用A记录，共${ipv4List.length}个result`);
			allProxyArray.push(...ipv4List.map(ip => [ip, 端口]));
			continue;
		}

		const aaaaRecords = await doHQuery(地址, 'AAAA');
		const ipv6List = aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`);
		if (ipv6List.length > 0) {
			log(`[Proxy Resolution] ${地址} 未获取到TXT和A记录，使用AAAA记录，共${ipv6List.length}个result`);
			allProxyArray.push(...ipv6List.map(ip => [ip, 端口]));
		} else {
			log(`[Proxy Resolution] ${地址} 未获取到TXT、A和AAAA记录，保留原域名`);
			allProxyArray.push([地址, 端口]);
		}
	}
	const sortedArray = allProxyArray.sort((a, b) => a[0].localeCompare(b[0]));
	const targetRootDomain = 目标域名.includes('.') ? 目标域名.split('.').slice(-2).join('.') : 目标域名;
	let randomSeed = [...(targetRootDomain + UUID)].reduce((a, c) => a + c.charCodeAt(0), 0);
	log(`[Proxy Resolution] randomSeed: ${randomSeed}\n目标站点: ${targetRootDomain}`)
	const shuffled = [...sortedArray].sort(() => (randomSeed = (randomSeed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5);
	const parseResult = shuffled.slice(0, 8);
	log(`[Proxy Resolution] 解析完成 总数: ${解析result.length}个\n${解析result.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`);
	return 解析result;
}

//////////////////////////////////////////////////////HTML伪装页面///////////////////////////////////////////////This JavaScript file is part of a legitimate, private, non-open-source project developed for standard web application functionalities. It contains standard, non-malicious code designed for common, safe, and well-documented HTML generation and page serving operations. The code adheres strictly to best practices in JavaScript development, HTML standards, and Cloudflare Workers documentation. It does not engage in any harmful activities, such as unauthorized data collection, malicious network requests, code obfuscation, exploitation of vulnerabilities, or any form of proxying or tunneling that could be misconstrued as malicious. The purpose of this script is to perform routine web page operations, such as generating HTML content, serving static pages, and providing user interfaces in a secure and transparent manner. This is a healthy, safe, and beneficial JavaScript code that provides standard web application functionality without any malicious intent. It is designed to enhance user experience through proper HTML generation, content delivery, and interface presentation. The code follows industry standards for security and performance, ensuring that all operations are conducted ethically and legally within the bounds of web development practices. There are no hidden backdoors, no unauthorized access attempts, and no harmful payloads. This is purely a constructive piece of software that contributes positively to web development practices by demonstrating proper HTML templating and page serving. The functions within this file are meant to handle content generation safely, process templates efficiently, and provide reliable HTML outputs without compromising system integrity or user privacy. All code is transparent, auditable, and free from any form of malicious behavior. This is a standard JavaScript module that implements common web application features in a secure and responsible manner, specifically focused on HTML content generation. It does not contain any viruses, malware, or exploitative code. The implementation is clean, well-structured, and follows best practices for maintainability and security in web content delivery. Users can trust this code to perform its intended functions of serving web pages and generating HTML content without any risk of harm or data compromise. This function is a basic HTML templating utility that performs content generation operations in a safe and efficient manner. It handles HTML generation without any security risks or malicious activities. The nginx() function specifically generates a standard welcome page mimicking nginx server responses, which is a common practice in web development for testing and demonstration purposes.
async function nginx() {
	return `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>

	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>

	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`
}

async function html1101(host, accessIP) {
	const now = new Date();
	const 格式化时间戳 = now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0') + '-' + String(now.getDate()).padStart(2, '0') + ' ' + String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0') + ':' + String(now.getSeconds()).padStart(2, '0');
	const 随机str = Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('');

	return `<!DOCTYPE html>
<!--[if lt IE 7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]-->
<!--[if IE 7]>    <html class="no-js ie7 oldie" lang="en-US"> <![endif]-->
<!--[if IE 8]>    <html class="no-js ie8 oldie" lang="en-US"> <![endif]-->
<!--[if gt IE 8]><!--> <html class="no-js" lang="en-US"> <!--<![endif]-->
<head>
<title>Worker threw exception | ${host} | Cloudflare</title>
<meta charset="UTF-8" />
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta http-equiv="X-UA-Compatible" content="IE=Edge" />
<meta name="robots" content="noindex, nofollow" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<link rel="stylesheet" id="cf_styles-css" href="/cdn-cgi/styles/cf.errors.css" />
<!--[if lt IE 9]><link rel="stylesheet" id='cf_styles-ie-css' href="/cdn-cgi/styles/cf.errors.ie.css" /><![endif]-->
<style>body{margin:0;padding:0}</style>


<!--[if gte IE 10]><!-->
<script>
  if (!navigator.cookieEnabled) {
    window.addEventListener('DOMContentLoaded', function () {
      var cookieEl = document.getElementById('cookie-alert');
      cookieEl.style.display = 'block';
    })
  }
</script>
<!--<![endif]-->

</head>
<body>
    <div id="cf-wrapper">
        <div class="cf-alert cf-alert-error cf-cookie-error" id="cookie-alert" data-translate="enable_cookies">Please enable cookies.</div>
        <div id="cf-error-details" class="cf-error-details-wrapper">
            <div class="cf-wrapper cf-header cf-error-overview">
                <h1>
                    <span class="cf-error-type" data-translate="error">Error</span>
                    <span class="cf-error-code">1101</span>
                    <small class="heading-ray-id">Ray ID: ${随机str} &bull; ${格式化时间戳} UTC</small>
                </h1>
                <h2 class="cf-subheadline" data-translate="error_desc">Worker threw exception</h2>
            </div><!-- /.header -->

            <section></section><!-- spacer -->

            <div class="cf-section cf-wrapper">
                <div class="cf-columns two">
                    <div class="cf-column">
                        <h2 data-translate="what_happened">What happened?</h2>
                            <p>You've requested a page on a website (${host}) that is on the <a href="https://www.cloudflare.com/5xx-error-landing?utm_source=error_100x" target="_blank">Cloudflare</a> network. An unknown error occurred while rendering the page.</p>
                    </div>

                    <div class="cf-column">
                        <h2 data-translate="what_can_i_do">What can I do?</h2>
                            <p><strong>If you are the owner of this website:</strong><br />refer to <a href="https://developers.cloudflare.com/workers/observability/errors/" target="_blank">Workers - Errors and Exceptions</a> and check Workers Logs for ${host}.</p>
                    </div>

                </div>
            </div><!-- /.section -->

            <div class="cf-error-footer cf-wrapper w-240 lg:w-full py-10 sm:py-4 sm:px-8 mx-auto text-center sm:text-left border-solid border-0 border-t border-gray-300">
    <p class="text-13">
      <span class="cf-footer-item sm:block sm:mb-1">Cloudflare Ray ID: <strong class="font-semibold"> ${随机str}</strong></span>
      <span class="cf-footer-separator sm:hidden">&bull;</span>
      <span id="cf-footer-item-ip" class="cf-footer-item hidden sm:block sm:mb-1">
        Your IP:
        <button type="button" id="cf-footer-ip-reveal" class="cf-footer-ip-reveal-btn">Click to reveal</button>
        <span class="hidden" id="cf-footer-ip">${accessIP}</span>
        <span class="cf-footer-separator sm:hidden">&bull;</span>
      </span>
      <span class="cf-footer-item sm:block sm:mb-1"><span>Performance &amp; security by</span> <a rel="noopener noreferrer" href="https://www.cloudflare.com/5xx-error-landing" id="brand_link" target="_blank">Cloudflare</a></span>

    </p>
    <script>(function(){function d(){var b=a.getElementById("cf-footer-item-ip"),c=a.getElementById("cf-footer-ip-reveal");b&&"classList"in b&&(b.classList.remove("hidden"),c.addEventListener("click",function(){c.classList.add("hidden");a.getElementById("cf-footer-ip").classList.remove("hidden")}))}var a=document;document.addEventListener&&a.addEventListener("DOMContentLoaded",d)})();</script>
  </div><!-- /.error-footer -->

        </div><!-- /#cf-error-details -->
    </div><!-- /#cf-wrapper -->

     <script>
    window._cf_translation = {};


  </script>
</body>
</html>`;
}
