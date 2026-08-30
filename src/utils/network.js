/**
 * src/utils/network.js
 * Auto-generated from _worker.js refactor
 * Original: edgetunnel 2.1 (2026-08-11)
 */
import { tryParseURL } from './helpers.js';

export function stripIPv6Brackets(hostname = '') {
	const host = String(hostname || '').trim();
	return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

export function isIPHostname(hostname = '') {
	const host = stripIPv6Brackets(hostname);
	const ipv4Regex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
	if (ipv4Regex.test(host)) return true;
	if (!host.includes(':')) return false;
	return Boolean(tryParseURL(`http://[${host}]/`));
}

export function isDestinationSafe(address = '', port = 0) {
	const portNum = Number(port);
	if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
		return false;
	}

	const addr = stripIPv6Brackets(String(address || '').trim()).toLowerCase();
	if (!addr) return false;

	// Hostname SSRF Checks
	if (addr === 'localhost' || addr.endsWith('.local') || addr.endsWith('.internal')) {
		return false;
	}

	// IPv4 Checks
	const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
	const match = addr.match(ipv4Regex);
	if (match) {
		const octets = match.slice(1).map((x) => parseInt(x, 10));
		if (octets.some((o) => o < 0 || o > 255)) return false;
		const [o1, o2] = octets;

		// 127.0.0.0/8 (Loopback)
		if (o1 === 127) return false;
		// 10.0.0.0/8 (Private)
		if (o1 === 10) return false;
		// 172.16.0.0/12 (Private)
		if (o1 === 172 && o2 >= 16 && o2 <= 31) return false;
		// 192.168.0.0/16 (Private)
		if (o1 === 192 && o2 === 168) return false;
		// 169.254.0.0/16 (Link-Local)
		if (o1 === 169 && o2 === 254) return false;
		// 100.64.0.0/10 (Carrier-Grade NAT)
		if (o1 === 100 && o2 >= 64 && o2 <= 127) return false;
		// 0.0.0.0/8 (Current network)
		if (o1 === 0) return false;
		// Multicast & Broadcast (>= 224)
		if (o1 >= 224) return false;
	}

	// IPv6 Checks
	if (addr.includes(':')) {
		// Loopback ::1
		if (addr === '::1' || addr === '0:0:0:0:0:0:0:1' || /^0*(:0*)*:1$/.test(addr)) return false;
		// Link-local fe80::/10
		if (addr.startsWith('fe80:') || addr.startsWith('fe80::')) return false;
		// Unique local fc00::/7 (fc.. or fd..)
		if (addr.startsWith('fc') || addr.startsWith('fd')) return false;
		// Unspecified ::
		if (addr === '::' || addr === '0:0:0:0:0:0:0:0' || /^0*(:0*)*$/.test(addr)) return false;
	}

	return true;
}

//////////////////////////////////////////////////turnConnect///////////////////////////////////////////////

export async function withTimeout(promise, timeoutMs, message) {
	let timer;
	try {
		return await Promise.race([
			promise,
			new Promise((_, reject) => {
				timer = setTimeout(() => reject(new Error(message)), timeoutMs);
			}),
		]);
	} finally {
		clearTimeout(timer);
	}
}

export function isIPv4(value) {
	const parts = String(value || '').split('.');
	return (
		parts.length === 4 &&
		parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255)
	);
}

export function identifyISP(request) {
	const cf = request?.cf;
	const ASNISPMapping = {
		4134: 'ct',
		4809: 'ct',
		4811: 'ct',
		4812: 'ct',
		4815: 'ct',
		4837: 'cu',
		4814: 'cu',
		9929: 'cu',
		17623: 'cu',
		17816: 'cu',
		9808: 'cmcc',
		24400: 'cmcc',
		56040: 'cmcc',
		56041: 'cmcc',
		56044: 'cmcc',
	};
	const ispKeywordMap = [
		{ code: 'ct', pattern: /chinanet|chinatelecom|chinaTelecom|cn2|shtel/ },
		{ code: 'cmcc', pattern: /cmi|cmnet|chinamobile|chinaMobile|cmcc|mobileCommunications/ },
		{ code: 'cu', pattern: /china169|chinaUnicom|chinaunicom|cucc|cncgroup|cuii|netcom/ },
	];
	if (String(cf?.country || '').toLowerCase() !== 'cn') return 'cf';
	const organizationname = String(cf?.asOrganization || '').toLowerCase();
	const matchedISP = ispKeywordMap.find(({ pattern }) => pattern.test(organizationname))?.code;
	return matchedISP || ASNISPMapping[String(cf?.asn || '')] || 'cf';
}
