/**
 * src/subscription/surge.js
 * Surge configuration profile subscription hot-patching.
 */

import { randomPath } from '../utils/helpers.js';

export function surgeSubscriptionHotPatch(content, url, config_JSON) {
	const lineContent = content.includes('\r\n') ? content.split('\r\n') : content.split('\n');
	const fullNodePath = config_JSON?.randomPath
		? randomPath(config_JSON?.fullNodePath || '/')
		: config_JSON?.fullNodePath || '/';
	let outputContent = '';
	for (const x of lineContent) {
		if (x.includes('= trojan,') && !x.includes('ws=true') && !x.includes('ws-path=')) {
			const host = x.split('sni=')[1]?.split(',')[0] || '';
			const oldContent = `sni=${host}, skip-cert-verify=${config_JSON?.skipCertVerify}`;
			const newContent = `sni=${host}, skip-cert-verify=${config_JSON?.skipCertVerify}, ws=true, ws-path=${fullNodePath.replace(/,/g, '%2C')}, ws-headers=Host:"${host}"`;
			outputContent +=
				x
					.replace(new RegExp(oldContent, 'g'), newContent)
					.replace('[', '')
					.replace(']', '') + '\n';
		} else {
			outputContent += x + '\n';
		}
	}

	const interval = 12 * 60 * 60;
	outputContent =
		`#!MANAGED-CONFIG ${url} interval=${interval} strict=false` +
		outputContent.substring(outputContent.indexOf('\n'));
	return outputContent;
}
