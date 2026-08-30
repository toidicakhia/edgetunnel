/**
 * src/utils/network.js
 * Auto-generated from _worker.js refactor
 * Original: edgetunnel 2.1 (2026-08-11)
 */
export function stripIPv6Brackets(hostname = '') {
	const host = String(hostname || '').trim();
	return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

export function isIPHostname(hostname = '') {
	const host = stripIPv6Brackets(hostname);
	const ipv4Regex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
	if (ipv4Regex.test(host)) return true;
	if (!host.includes(':')) return false;
	try {
		new URL(`http://[${host}]/`);
		return true;
	} catch {
		return false;
	}
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
