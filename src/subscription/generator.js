/**
 * src/subscription/generator.js
 * Unified subscription generator and dispatcher.
 */

import { clashSubscriptionHotPatch } from './clash.js';
import { singboxSubscriptionHotPatch } from './singbox.js';
import { surgeSubscriptionHotPatch } from './surge.js';
import {
	generateShadowsocksLink,
	generateSocks5Link,
	generateTrojanLink,
	generateVLESSLink,
	generateVMessLink,
} from './links.js';

import { safeBtoa } from '../utils/helpers.js';

export {
	clashSubscriptionHotPatch,
	singboxSubscriptionHotPatch,
	surgeSubscriptionHotPatch,
	generateVLESSLink,
	generateTrojanLink,
	generateVMessLink,
	generateShadowsocksLink,
	generateSocks5Link,
};

export function buildBase64Subscription(links = []) {
	const validLinks = Array.isArray(links) ? links.filter(Boolean) : [links];
	const joined = validLinks.join('\n');
	return safeBtoa(unescape(encodeURIComponent(joined)), safeBtoa(joined));
}
