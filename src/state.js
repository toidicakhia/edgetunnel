/**
 * src/state.js
 * Mutable global state (mirrors original _worker.js globals)
 * Auto-generated from _worker.js refactor
 */

export let config_JSON;
export let cachedSocks5Whitelist = null;
export let debugLogging = false;

export let socks5Whitelist = [
	'*tapecontent.net',
	'*cloudatacdn.com',
	'*loadshare.org',
	'*cdn-centaurus.com',
	'scholar.google.com',
];

export let TCP_CONCURRENT_DIAL_COUNT = 2;
export let PROXY_CONCURRENT_DIAL_COUNT = 1;
export let preloadRaceDial = false;

// Helpers to update mutable state (keeps live bindings)
export function setConfigJSON(v) {
	config_JSON = v;
}
export function setDebugLogging(v) {
	debugLogging = v;
}
export function setSocks5Whitelist(v) {
	socks5Whitelist = v;
}
export function setCachedSocks5Whitelist(v) {
	cachedSocks5Whitelist = v;
}
export function setTCPConcurrentDialCount(v) {
	TCP_CONCURRENT_DIAL_COUNT = v;
}
export function setProxyConcurrentDialCount(v) {
	PROXY_CONCURRENT_DIAL_COUNT = v;
}
export function setPreloadRaceDial(v) {
	preloadRaceDial = v;
}
