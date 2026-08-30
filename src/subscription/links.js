/**
 * src/subscription/links.js
 * Link generators for proxy protocols (VLESS, Trojan, VMess, Shadowsocks, SOCKS5).
 */

import { generateVMessLink } from '../core/vmess.js';

export { generateVMessLink };

export function generateVLESSLink({
	uuid,
	host,
	port = 443,
	tls = true,
	security = 'tls',
	transport = 'ws',
	path = '/',
	hostHeader = '',
	sni = '',
	fp = 'chrome',
	alpn = '',
	flow = '',
	name = '',
}) {
	const params = new URLSearchParams();
	params.set('encryption', 'none');
	params.set('security', tls ? security || 'tls' : 'none');
	params.set('type', transport);

	if (hostHeader) params.set('host', hostHeader);
	if (path) params.set('path', path);
	if (sni) params.set('sni', sni);
	if (fp) params.set('fp', fp);
	if (alpn) params.set('alpn', alpn);
	if (flow) params.set('flow', flow);

	const tag = name ? `#${encodeURIComponent(name)}` : '';
	return `vless://${uuid}@${host}:${port}?${params.toString()}${tag}`;
}

export function generateTrojanLink({
	password,
	host,
	port = 443,
	tls = true,
	security = 'tls',
	transport = 'ws',
	path = '/',
	hostHeader = '',
	sni = '',
	fp = 'chrome',
	alpn = '',
	name = '',
}) {
	const params = new URLSearchParams();
	params.set('security', tls ? security || 'tls' : 'none');
	params.set('type', transport);

	if (hostHeader) params.set('host', hostHeader);
	if (path) params.set('path', path);
	if (sni) params.set('sni', sni);
	if (fp) params.set('fp', fp);
	if (alpn) params.set('alpn', alpn);

	const tag = name ? `#${encodeURIComponent(name)}` : '';
	return `trojan://${password}@${host}:${port}?${params.toString()}${tag}`;
}

export function generateShadowsocksLink({
	method = 'aes-128-gcm',
	password,
	host,
	port,
	name = '',
}) {
	const userInfo = `${method}:${password}`;
	let b64UserInfo;
	try {
		b64UserInfo = btoa(userInfo).replace(/=/g, '');
	} catch {
		b64UserInfo = userInfo;
	}
	const tag = name ? `#${encodeURIComponent(name)}` : '';
	return `ss://${b64UserInfo}@${host}:${port}${tag}`;
}

export function generateSocks5Link({
	host,
	port = 1080,
	username = '',
	password = '',
	name = '',
}) {
	const auth = username && password ? `${encodeURIComponent(username)}:${encodeURIComponent(password)}@` : '';
	const tag = name ? `#${encodeURIComponent(name)}` : '';
	return `socks5://${auth}${host}:${port}${tag}`;
}
