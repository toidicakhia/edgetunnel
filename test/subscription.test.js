import test from 'node:test';
import assert from 'node:assert/strict';
import {
	generateVLESSLink,
	generateTrojanLink,
	generateVMessLink,
	generateShadowsocksLink,
	generateSocks5Link,
	buildBase64Subscription,
	clashSubscriptionHotPatch,
	singboxSubscriptionHotPatch,
	surgeSubscriptionHotPatch,
} from '../src/subscription/generator.js';

test('Protocol Link Generators generate valid URI schemes', () => {
	const uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4';

	// VLESS
	const vless = generateVLESSLink({
		uuid,
		host: '1.1.1.1',
		port: 443,
		sni: 'example.com',
		path: '/vl-ws',
		name: 'VLESS Node',
	});
	assert.equal(vless.startsWith('vless://'), true);
	assert.equal(vless.includes('type=ws'), true);
	assert.equal(vless.includes('security=tls'), true);
	assert.equal(vless.includes('sni=example.com'), true);
	assert.equal(vless.includes('path=%2Fvl-ws'), true);

	// Trojan
	const trojan = generateTrojanLink({
		password: 'mypassword',
		host: '1.1.1.1',
		port: 443,
		sni: 'example.com',
		path: '/tr-ws',
		name: 'Trojan Node',
	});
	assert.equal(trojan.startsWith('trojan://'), true);
	assert.equal(trojan.includes('mypassword@1.1.1.1:443'), true);
	assert.equal(trojan.includes('type=ws'), true);

	// Shadowsocks
	const ss = generateShadowsocksLink({
		method: 'aes-128-gcm',
		password: 'sspassword',
		host: '1.1.1.1',
		port: 443,
		name: 'SS Node',
	});
	assert.equal(ss.startsWith('ss://'), true);

	// SOCKS5
	const socks5 = generateSocks5Link({
		host: '1.1.1.1',
		port: 1080,
		username: 'user',
		password: 'pass',
		name: 'SOCKS5 Node',
	});
	assert.equal(socks5.startsWith('socks5://'), true);
	assert.equal(socks5.includes('user:pass@1.1.1.1:1080'), true);
});

test('buildBase64Subscription encodes multiple links in base64', () => {
	const links = ['vless://link1', 'trojan://link2', 'vmess://link3'];
	const b64 = buildBase64Subscription(links);
	const decoded = atob(b64);
	assert.equal(decoded, 'vless://link1\ntrojan://link2\nvmess://link3');
});

test('clashSubscriptionHotPatch modifies Clash YAML config paths', () => {
	const yamlContent = `
proxies:
  - name: test-vless
    type: vless
    server: 1.1.1.1
    port: 443
    ws-opts:
      path: /old-path
`;
	const configJSON = {
		WS: true,
		WSConfig: { Path: '/custom-ws-path' },
	};
	const patched = clashSubscriptionHotPatch(yamlContent, configJSON);
	assert.equal(typeof patched, 'string');
});

test('singboxSubscriptionHotPatch modifies Sing-box JSON config', async () => {
	const uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4';
	const singboxJson = JSON.stringify({
		dns: {
			servers: [
				{ tag: 'dns-cf', address: 'https://1.1.1.1/dns-query' },
			],
		},
		outbounds: [
			{
				type: 'vless',
				tag: 'vless-out',
				server: '1.1.1.1',
				server_port: 443,
				uuid: uuid,
				transport: {
					type: 'ws',
					path: '/my-path',
				},
			},
		],
	});
	const configJSON = {
		UUID: uuid,
		Fingerprint: 'chrome',
		ECH: true,
		ECHConfig: { SNI: 'cloudflare-ech.com' },
	};
	const patched = await singboxSubscriptionHotPatch(singboxJson, configJSON);
	const parsed = JSON.parse(patched);
	
	// Verifies uTLS and ECH are injected into the matching outbound
	assert.equal(parsed.outbounds[0].tls.enabled, true);
	assert.equal(parsed.outbounds[0].tls.utls.fingerprint, 'chrome');
	assert.equal(parsed.outbounds[0].tls.ech.query_server_name, 'cloudflare-ech.com');
	// Verifies DNS server IP replacement
	assert.equal(parsed.dns.servers[0].server, '8.8.8.8');
	assert.equal(parsed.dns.servers[0].type, 'https');
});
