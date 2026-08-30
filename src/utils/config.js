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
	const getProxyType = (nodeText) => nodeText.match(/type:\s*(\w+)/)?.[1] || 'vl' + 'ess';
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
		if (/grpc-opts:\s*\{/i.test(nodeText)) return addInlineGrpcUserAgent(nodeText);
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
				nodeLines[grpcOptsIndex] = addInlineGrpcUserAgent(grpcLine);
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
			if (needProcessECH && getCredentialValue(nodeText, false) === uuid.trim())
				nodeLines = addBlockFormatECHOpts(nodeLines, topLevelIndent);
			processedLines.push(...nodeLines);
		} else {
			processedLines.push(line);
			i++;
		}
	}

	return processedLines.join('\n');
}

export async function singboxSubscriptionHotPatch(
	SingBox_originalsubscriptionContent,
	config_JSON = {}
) {
	const uuid = config_JSON?.UUID || null;
	const fingerprint = config_JSON?.Fingerprint || 'chrome';
	const ECHenable = Boolean(config_JSON?.ECH);
	const ECH_SNI = config_JSON?.ECHConfig?.SNI || 'cloudflare-ech.com';
	const sb_json_text = SingBox_originalsubscriptionContent.replace('1.1.1.1', '8.8.8.8').replace(
		'1.0.0.1',
		'8.8.4.4'
	);
	try {
		const config = JSON.parse(sb_json_text);
		const toArray = (value) =>
			value === undefined || value === null ? [] : Array.isArray(value) ? value : [value];
		const ensureRoute = () =>
			(config.route = config.route && typeof config.route === 'object' ? config.route : {});
		const getDNSRuleServer = (rule) =>
			rule &&
			typeof rule === 'object' &&
			!Array.isArray(rule) &&
			typeof rule.server === 'string'
				? rule.server
				: null;
		const addRuleSet = (type, code) => {
			if (!code || typeof code !== 'string') return null;
			const route = ensureRoute(),
				tag = `${type}-${code}`,
				ruleSet = Array.isArray(route.rule_set) ? route.rule_set : toArray(route.rule_set);
			if (!ruleSet.some((item) => item?.tag === tag)) {
				const legacyOptions = type === 'geoip' ? route.geoip : route.geosite;
				ruleSet.push({
					tag,
					type: 'remote',
					format: 'binary',
					url: `https://raw.githubusercontent.com/SagerNet/sing-${type}/rule-set/${tag}.srs`,
					...(legacyOptions?.download_detour
						? { download_detour: legacyOptions.download_detour }
						: {}),
				});
				config.experimental =
					config.experimental && typeof config.experimental === 'object'
						? config.experimental
						: {};
				config.experimental.cache_file =
					config.experimental.cache_file &&
					typeof config.experimental.cache_file === 'object'
						? config.experimental.cache_file
						: {};
				config.experimental.cache_file.enabled ??= true;
			}
			route.rule_set = ruleSet;
			return tag;
		};

		const migrateRuleSetField = (rule) => {
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
			for (const geosite of toArray(rule.geosite))
				if (typeof geosite === 'string') tags.push(addRuleSet('geosite', geosite));
			if (tags.length)
				rule.rule_set = [...new Set([...toArray(rule.rule_set), ...tags].filter(Boolean))];
			delete rule.geoip;
			delete rule.source_geoip;
			delete rule.geosite;
			return rule;
		};

		const migrateDNSRule = (rule, rcodeServerMap) => {
			rule = migrateRuleSetField(rule);
			if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return rule;
			if (rule.type === 'logical' && Array.isArray(rule.rules)) {
				rule.rules = rule.rules.map((childRule) =>
					migrateDNSRule(childRule, rcodeServerMap)
				);
				return rule;
			}
			const serverTag = getDNSRuleServer(rule);
			if (serverTag && rcodeServerMap.has(serverTag)) {
				for (const key of [
					'server',
					'strategy',
					'disable_cache',
					'rewrite_ttl',
					'client_subnet',
					'timeout',
				])
					delete rule[key];
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
					{
						targetKey: 'route_address',
						sourceKeys: ['inet4_route_address', 'inet6_route_address'],
					},
					{
						targetKey: 'route_exclude_address',
						sourceKeys: ['inet4_route_exclude_address', 'inet6_route_exclude_address'],
					},
				]) {
					const values = toArray(inbound[migration.targetKey]);
					for (const sourceKey of migration.sourceKeys)
						values.push(...toArray(inbound[sourceKey]));
					if (values.length) inbound[migration.targetKey] = [...new Set(values)];
					for (const sourceKey of migration.sourceKeys) delete inbound[sourceKey];
				}
				if (inbound.tag) {
					const addedRules = [];
					if (inbound.domain_strategy)
						addedRules.push({
							inbound: inbound.tag,
							action: 'resolve',
							strategy: inbound.domain_strategy,
						});
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

		if (
			config?.route &&
			typeof config.route === 'object' &&
			Array.isArray(config.route.rules)
		) {
			const patchRouteRule = (rule) => {
				rule = migrateRuleSetField(rule);
				if (rule?.type === 'logical' && Array.isArray(rule.rules))
					rule.rules = rule.rules.map(patchRouteRule);
				else if (
					rule &&
					typeof rule === 'object' &&
					!Array.isArray(rule) &&
					rule.outbound &&
					!rule.action
				)
					rule.action = 'route';
				return rule;
			};
			config.route.rules = config.route.rules.map(patchRouteRule);
		}

		const dns = config?.dns;
		if (dns && typeof dns === 'object') {
			const legacyFakeIP = dns.fakeip && typeof dns.fakeip === 'object' ? dns.fakeip : null;
			const rcodeServerMap = new Map();
			const DNSaddressprotocolType = {
				'tcp:': 'tcp',
				'udp:': 'udp',
				'tls:': 'tls',
				'quic:': 'quic',
				'https:': 'https',
				'h3:': 'h3',
			};
			const RCodemapping = {
				success: 'NOERROR',
				format_error: 'FORMERR',
				server_failure: 'SERVFAIL',
				name_error: 'NXDOMAIN',
				not_implemented: 'NOTIMP',
				refused: 'REFUSED',
			};
			let hasFakeIPServer = false;

			if (Array.isArray(dns.servers)) {
				const migratedServers = [];
				for (const originalServer of dns.servers) {
					if (
						!originalServer ||
						typeof originalServer !== 'object' ||
						Array.isArray(originalServer)
					) {
						migratedServers.push(originalServer);
						continue;
					}

					const server = { ...originalServer };
					let parsedAddress = null,
						parsedRCode = '',
						rawAddress =
							typeof server.address === 'string' ? server.address.trim() : '';
					if (rawAddress) {
						const lowerAddress = rawAddress.toLowerCase();
						if (lowerAddress === 'fakeip') parsedAddress = { type: 'fakeip' };
						else if (lowerAddress === 'local') parsedAddress = { type: 'local' };
						else if (lowerAddress.startsWith('rcode://')) {
							parsedAddress = { type: 'rcode' };
							parsedRCode = rawAddress.slice('rcode://'.length).toLowerCase();
						} else if (lowerAddress.startsWith('dhcp://')) {
							const dhcpInterface = rawAddress.slice('dhcp://'.length);
							parsedAddress =
								dhcpInterface && dhcpInterface.toLowerCase() !== 'auto'
									? { type: 'dhcp', interface: dhcpInterface }
									: { type: 'dhcp' };
						} else {
							try {
								const addressURL = new URL(rawAddress);
								const type =
									DNSaddressprotocolType[addressURL.protocol.toLowerCase()];
								if (type) {
									const parsedServer =
										addressURL.hostname?.startsWith('[') &&
										addressURL.hostname.endsWith(']')
											? addressURL.hostname.slice(1, -1)
											: addressURL.hostname;
									parsedAddress = {
										type,
										server: parsedServer || addressURL.host || rawAddress,
										...(addressURL.port
											? { server_port: Number(addressURL.port) }
											: {}),
										...((type === 'https' || type === 'h3') &&
										addressURL.pathname &&
										addressURL.pathname !== '/dns-query'
											? { path: addressURL.pathname }
											: {}),
									};
								}
							} catch (_) {}
							if (!parsedAddress) parsedAddress = { type: 'udp', server: rawAddress };
						}
					}

					if (parsedAddress?.type === 'rcode') {
						const rcode = RCodemapping[parsedRCode] || 'NOERROR';
						if (typeof server.tag === 'string' && server.tag) {
							rcodeServerMap.set(server.tag, rcode);
							rcodeServerMap.set(
								server.tag.startsWith('dns_')
									? server.tag.slice(4)
									: `dns_${server.tag}`,
								rcode
							);
						}
						continue;
					}

					if (parsedAddress) {
						delete server.address;
						Object.assign(server, parsedAddress);
					}
					if (
						server.address_resolver !== undefined &&
						server.domain_resolver === undefined
					)
						server.domain_resolver = server.address_resolver;
					if (
						server.address_strategy !== undefined &&
						server.domain_strategy === undefined
					)
						server.domain_strategy = server.address_strategy;
					delete server.address_resolver;
					delete server.address_strategy;
					if (server.detour === 'DIRECT') delete server.detour;

					if (server.type === 'fakeip') {
						hasFakeIPServer = true;
						if (legacyFakeIP) {
							for (const key of ['inet4_range', 'inet6_range']) {
								if (legacyFakeIP[key] !== undefined && server[key] === undefined)
									server[key] = legacyFakeIP[key];
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
					const DNSRouteOptionField = new Set([
						'outbound',
						'server',
						'action',
						'strategy',
						'disable_cache',
						'rewrite_ttl',
						'client_subnet',
						'timeout',
					]);
					const isOutboundAnyDNSRule =
						rule &&
						typeof rule === 'object' &&
						!Array.isArray(rule) &&
						rule.type !== 'logical' &&
						serverTag &&
						outbound.includes('any') &&
						Object.keys(rule).every((key) => DNSRouteOptionField.has(key));
					if (isOutboundAnyDNSRule) {
						const route = ensureRoute();
						if (route.default_domain_resolver === undefined) {
							const resolver = { server: serverTag };
							for (const key of [
								'strategy',
								'disable_cache',
								'rewrite_ttl',
								'client_subnet',
								'timeout',
							]) {
								if (rule[key] !== undefined) resolver[key] = rule[key];
							}
							route.default_domain_resolver =
								Object.keys(resolver).length === 1 ? resolver.server : resolver;
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
			const outboundTags = new Set(
				config.outbounds.map((outbound) => outbound?.tag).filter(Boolean)
			);
			const referenceREJECT = (value) =>
				value === 'REJECT' ||
				(value &&
					typeof value === 'object' &&
					(Array.isArray(value)
						? value.some(referenceREJECT)
						: Object.values(value).some(referenceREJECT)));
			if (
				!outboundTags.has('REJECT') &&
				referenceREJECT({ outbounds: config.outbounds, route: config.route })
			)
				config.outbounds.push({ type: 'block', tag: 'REJECT' });
		}

		// --- UUID matching node TLS hot patch (utls & ech) ---
		if (uuid) {
			config.outbounds?.forEach((outbound) => {
				// only process nodes containing uuid or password
				if (
					(outbound.uuid && outbound.uuid === uuid) ||
					(outbound.password && outbound.password === uuid)
				) {
					// ensure tls object exists
					if (!outbound.tls) {
						outbound.tls = { enabled: true };
					}

					// add/update utls config
					if (fingerprint) {
						outbound.tls.utls = {
							enabled: true,
							fingerprint: fingerprint,
						};
					}

					// if provided ech_config，add/update ech config
					if (ECHenable) {
						outbound.tls.ech = {
							enabled: true,
							query_server_name: ECH_SNI, // wait1.13.0+ version
							//config: `-----BEGIN ECH CONFIGS-----\n${ech_config}\n-----END ECH CONFIGS-----`
						};
					}
				}
			});
		}

		return JSON.stringify(config, null, 2);
	} catch (e) {
		console.error('Singboxhot patch execution failed:', e);
		return JSON.stringify(JSON.parse(sb_json_text), null, 2);
	}
}

export function surgeSubscriptionHotPatch(content, url, config_JSON) {
	const lineContent = content.includes('\r\n') ? content.split('\r\n') : content.split('\n');
	const fullNodePath = config_JSON.randomPath
		? randomPath(config_JSON.fullNodePath)
		: config_JSON.fullNodePath;
	let outputContent = '';
	for (let x of eachLine) {
		if (x.includes('= tro' + 'jan,') && !x.includes('ws=true') && !x.includes('ws-path=')) {
			const host = x.split('sni=')[1].split(',')[0];
			const oldContent = `sni=${host}, skip-cert-verify=${config_JSON.skipCertVerify}`;
			const newContent = `sni=${host}, skip-cert-verify=${config_JSON.skipCertVerify}, ws=true, ws-path=${fullNodePath.replace(/,/g, '%2C')}, ws-headers=Host:"${host}"`;
			outputContent +=
				x
					.replace(new RegExp(oldContent, 'g'), newContent)
					.replace('[', '')
					.replace(']', '') + '\n';
		} else {
			outputContent += x + '\n';
		}
	}

	outputContent =
		`#!MANAGED-CONFIG ${url} interval=${config_JSON.optSubGenerator.SUBUpdateTime * 60 * 60} strict=false` +
		outputContent.substring(outputContent.indexOf('\n'));
	return outputContent;
}

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
					const requestTime = new Date(logEntry.TIME).toLocaleString('zh-CN', {
						timeZone: 'Asia/Shanghai',
					});
					const requestURL = new URL(logEntry.URL);
					const msg =
						`<b>#${config_JSON.optSubGenerator.SUBNAME} log notification</b>\n\n` +
						`📌 <b>type：</b>#${logEntry.TYPE}\n` +
						`🌐 <b>IP：</b><code>${logEntry.IP}</code>\n` +
						`📍 <b>location：</b>${logEntry.CC}\n` +
						`🏢 <b>ASN：</b>${logEntry.ASN}\n` +
						`🔗 <b>domain：</b><code>${requestURL.host}</code>\n` +
						`🔍 <b>path：</b><code>${requestURL.pathname + requestURL.search}</code>\n` +
						`🤖 <b>UA：</b><code>${logEntry.UA}</code>\n` +
						`📅 <b>time：</b>${requestTime}\n` +
						`${config_JSON.CF.Usage.success ? `📊 <b>requestUsage：</b>${config_JSON.CF.Usage.total}/${config_JSON.CF.Usage.max} <b>${((config_JSON.CF.Usage.total / config_JSON.CF.Usage.max) * 100).toFixed(2)}%</b>\n` : ''}`;
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
			} catch (e) {
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
			TLSfragment: null,
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
			optimalSubscriptionGeneration: {
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
			subscriptionConversionconfig: {
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
		let configJSON = await env.KV.get('config.json');
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
