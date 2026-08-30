/**
 * src/subscription/singbox.js
 * Sing-box JSON subscription hot-patching and schema migration.
 */

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
					let parsedAddress = null;
					let parsedRCode = '';
					const rawAddress =
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
							} catch {}
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
				if (
					(outbound.uuid && outbound.uuid === uuid) ||
					(outbound.password && outbound.password === uuid)
				) {
					if (!outbound.tls) {
						outbound.tls = { enabled: true };
					}

					if (fingerprint) {
						outbound.tls.utls = {
							enabled: true,
							fingerprint: fingerprint,
						};
					}

					if (ECHenable) {
						outbound.tls.ech = {
							enabled: true,
							query_server_name: ECH_SNI,
						};
					}
				}
			});
		}

		return JSON.stringify(config, null, 2);
	} catch (e) {
		console.error('Singbox hot patch execution failed:', e);
		return JSON.stringify(JSON.parse(sb_json_text), null, 2);
	}
}
