/**
 * src/subscription/clash.js
 * Clash Meta / Clash YAML subscription hot-patching and generator.
 */

export function clashSubscriptionHotPatch(Clash_originalsubscriptionContent, config_JSON = {}) {
	const uuid = config_JSON?.UUID || null;
	const ECHenable = Boolean(config_JSON?.ECH);
	const HOSTS = Array.isArray(config_JSON?.HOSTS) ? [...config_JSON.HOSTS] : [];
	const ECH_SNI = config_JSON?.ECHConfig?.SNI || null;
	const ECH_DNS = config_JSON?.ECHConfig?.DNS;
	const needProcessECH = Boolean(uuid && ECHenable);
	const gRPCUserAgent =
		typeof config_JSON?.gRPCUserAgent === 'string' && config_JSON.gRPCUserAgent.trim()
			? config_JSON.gRPCUserAgent.trim()
			: null;
	const needProcessGRPC = config_JSON?.transportProtocol === 'grpc' && Boolean(gRPCUserAgent);
	const gRPCUserAgentYAML = gRPCUserAgent ? JSON.stringify(gRPCUserAgent) : null;
	let clash_yaml = Clash_originalsubscriptionContent.replace(/mode:\s*Rule\b/g, 'mode: rule');

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

	const addInlineGRPCUserAgent = (text) =>
		text.replace(/grpc-opts:\s*\{([\s\S]*?)\}/i, (all, inner) => {
			if (/grpc-user-agent\s*:/i.test(inner)) return all;
			let content = inner.trim();
			if (content.endsWith(',')) content = content.slice(0, -1).trim();
			const patchedContent = content
				? `${content}, grpc-user-agent: ${gRPCUserAgentYAML}`
				: `grpc-user-agent: ${gRPCUserAgentYAML}`;
			return `grpc-opts: {${patchedContent}}`;
		});
	const matchedGRPCNetwork = (text) =>
		/(?:^|[,{])\s*network:\s*(?:"grpc"|'grpc'|grpc)(?=\s*(?:[,}\n#]|$))/im.test(text);
	const getProxyType = (nodeText) => nodeText.match(/type:\s*(\w+)/)?.[1] || 'vless';
	const getCredentialValue = (nodeText, isFlowStyle) => {
		const credentialField = getProxyType(nodeText) === 'trojan' ? 'password' : 'uuid';
		const pattern = new RegExp(
			`${credentialField}:\\s*${isFlowStyle ? '([^,}\\n]+)' : '([^\\n]+)'}`
		);
		return nodeText.match(pattern)?.[1]?.trim() || null;
	};
	const insertNameserverPolicy = (yaml, hostsEntries) => {
		if (/^\s{2}nameserver-policy:\s*(?:\n|$)/m.test(yaml)) {
			return yaml.replace(/^(\s{2}nameserver-policy:\s*\n)/m, `$1${hostsEntries}\n`);
		}
		const lines = yaml.split('\n');
		let dnsBlockEndIndex = -1;
		let inDnsBlock = false;
		for (let idx = 0; idx < lines.length; idx++) {
			const line = lines[idx];
			if (/^dns:\s*$/.test(line)) {
				inDnsBlock = true;
				continue;
			}
			if (inDnsBlock && /^[a-zA-Z]/.test(line)) {
				dnsBlockEndIndex = idx;
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
		if (/grpc-opts:\s*\{/i.test(nodeText)) return addInlineGRPCUserAgent(nodeText);
		return nodeText.replace(
			/\}(\s*)$/,
			`, grpc-opts: {grpc-user-agent: ${gRPCUserAgentYAML}}}$1`
		);
	};
	const addBlockFormatGRPCUserAgent = (nodeLines, topLevelIndent) => {
		const topLevelIndentStr = ' '.repeat(topLevelIndent);
		let grpcOptsIndex = -1;
		for (let idx = 0; idx < nodeLines.length; idx++) {
			const line = nodeLines[idx];
			if (!line.trim()) continue;
			const indent = line.search(/\S/);
			if (indent !== topLevelIndent) continue;
			if (
				/^\s*grpc-opts:\s*(?:#.*)?$/.test(line) ||
				/^\s*grpc-opts:\s*\{.*\}\s*(?:#.*)?$/.test(line)
			) {
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
			if (insertIndex >= 0)
				nodeLines.splice(
					insertIndex + 1,
					0,
					`${topLevelIndentStr}grpc-opts:`,
					`${topLevelIndentStr}  grpc-user-agent: ${gRPCUserAgentYAML}`
				);
			return nodeLines;
		}
		const grpcLine = nodeLines[grpcOptsIndex];
		if (/^\s*grpc-opts:\s*\{.*\}\s*(?:#.*)?$/.test(grpcLine)) {
			if (!/grpc-user-agent\s*:/i.test(grpcLine))
				nodeLines[grpcOptsIndex] = addInlineGRPCUserAgent(grpcLine);
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
		if (!hasGRPCUserAgent)
			nodeLines.splice(
				blockEndIndex,
				0,
				`${' '.repeat(childIndent)}grpc-user-agent: ${gRPCUserAgentYAML}`
			);
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

	if (ECHenable && HOSTS.length > 0) {
		const hostsEntries = HOSTS.map((host) => `    "${host}": ${ECH_DNS ? ECH_DNS : ''}`).join(
			'\n'
		);
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
				braceCount +=
					(lines[i].match(/\{/g) || []).length - (lines[i].match(/\}/g) || []).length;
			}
			if (needProcessGRPC) fullNode = addFlowFormatGRPCUserAgent(fullNode);
			if (needProcessECH && getCredentialValue(fullNode, true) === uuid.trim()) {
				fullNode = fullNode.replace(
					/\}(\s*)$/,
					`, ech-opts: {enable: true${ECH_SNI ? `, query-server-name: ${ECH_SNI}` : ''}}}$1`
				);
			}
			processedLines.push(fullNode);
			i++;
		} else if (trimmedLine.startsWith('- name:')) {
			const nodeLines = [line];
			const baseIndent = line.search(/\S/);
			const topLevelIndent = baseIndent + 2;
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
				const patched = addBlockFormatGRPCUserAgent(nodeLines, topLevelIndent);
				nodeLines.length = 0;
				nodeLines.push(...patched);
				nodeText = nodeLines.join('\n');
			}
			if (needProcessECH && getCredentialValue(nodeText, false) === uuid.trim()) {
				const patched = addBlockFormatECHOpts(nodeLines, topLevelIndent);
				nodeLines.length = 0;
				nodeLines.push(...patched);
			}
			processedLines.push(...nodeLines);
		} else {
			processedLines.push(line);
			i++;
		}
	}

	return processedLines.join('\n');
}
