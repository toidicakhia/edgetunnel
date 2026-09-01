/**
 * src/utils/helpers.js
 * Auto-generated from _worker.js refactor
 * Original: edgetunnel 2.1 (2026-08-11)
 */
import { debugLogging } from '../state.js';

export function toUint8Array(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data))
		return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data || 0);
}

export function concatByteData(...chunkList) {
	if (!chunkList || chunkList.length === 0) return new Uint8Array(0);
	if (chunkList.length === 1) return toUint8Array(chunkList[0]);
	let total = 0;
	const len = chunkList.length;
	const chunks = new Array(len);
	for (let i = 0; i < len; i++) {
		const c = toUint8Array(chunkList[i]);
		chunks[i] = c;
		total += c.byteLength;
	}
	const result = new Uint8Array(total);
	let offset = 0;
	for (let i = 0; i < len; i++) {
		result.set(chunks[i], offset);
		offset += chunks[i].byteLength;
	}
	return result;
}

export function log(...args) {
	if (debugLogging) console.log(...args);
}

export function safeClose(resource) {
	if (!resource) return;
	try {
		if (typeof resource.close === 'function') resource.close();
		else if (typeof resource.cancel === 'function') resource.cancel().catch?.(() => {});
	} catch {}
}

export function safeRelease(lockable) {
	if (!lockable) return;
	try {
		if (typeof lockable.releaseLock === 'function') lockable.releaseLock();
	} catch {}
}

export function safeCloseAll(...resources) {
	for (const r of resources) {
		if (!r) continue;
		safeRelease(r);
		safeClose(r);
	}
}

export function tryParseJSON(str, fallback = null) {
	if (typeof str !== 'string') return fallback;
	try {
		return JSON.parse(str);
	} catch {
		return fallback;
	}
}

export function tryParseURL(str, base = undefined) {
	if (!str || typeof str !== 'string') return null;
	try {
		return new URL(str, base);
	} catch {
		return null;
	}
}

export function safeAtob(str, fallback = '') {
	if (typeof str !== 'string') return fallback;
	try {
		return atob(str);
	} catch {
		return fallback;
	}
}

export function safeBtoa(str, fallback = '') {
	if (typeof str !== 'string') return fallback;
	try {
		return btoa(str);
	} catch {
		return fallback;
	}
}

export function randomPath(fullNodePath = '/') {
	const commonPathDirs = [
		'about',
		'account',
		'acg',
		'act',
		'activity',
		'ad',
		'ads',
		'ajax',
		'album',
		'albums',
		'anime',
		'api',
		'app',
		'apps',
		'archive',
		'archives',
		'article',
		'articles',
		'ask',
		'auth',
		'avatar',
		'bbs',
		'bd',
		'blog',
		'blogs',
		'book',
		'books',
		'bt',
		'buy',
		'cart',
		'category',
		'categories',
		'cb',
		'channel',
		'channels',
		'chat',
		'china',
		'city',
		'class',
		'classify',
		'clip',
		'clips',
		'club',
		'cn',
		'code',
		'collect',
		'collection',
		'comic',
		'comics',
		'community',
		'company',
		'config',
		'contact',
		'content',
		'course',
		'courses',
		'cp',
		'data',
		'detail',
		'details',
		'dh',
		'directory',
		'discount',
		'discuss',
		'dl',
		'dload',
		'doc',
		'docs',
		'document',
		'documents',
		'doujin',
		'download',
		'downloads',
		'drama',
		'edu',
		'en',
		'ep',
		'episode',
		'episodes',
		'event',
		'events',
		'f',
		'faq',
		'favorite',
		'favourites',
		'favs',
		'feedback',
		'file',
		'files',
		'film',
		'films',
		'forum',
		'forums',
		'friend',
		'friends',
		'game',
		'games',
		'gif',
		'go',
		'go.html',
		'go.php',
		'group',
		'groups',
		'help',
		'home',
		'hot',
		'htm',
		'html',
		'image',
		'images',
		'img',
		'index',
		'info',
		'intro',
		'item',
		'items',
		'ja',
		'jp',
		'jump',
		'jump.html',
		'jump.php',
		'jumping',
		'knowledge',
		'lang',
		'lesson',
		'lessons',
		'lib',
		'library',
		'link',
		'links',
		'list',
		'live',
		'lives',
		'm',
		'mag',
		'magnet',
		'mall',
		'manhua',
		'map',
		'member',
		'members',
		'message',
		'messages',
		'mobile',
		'movie',
		'movies',
		'music',
		'my',
		'new',
		'news',
		'note',
		'novel',
		'novels',
		'online',
		'order',
		'out',
		'out.html',
		'out.php',
		'outbound',
		'p',
		'page',
		'pages',
		'pay',
		'payment',
		'pdf',
		'photo',
		'photos',
		'pic',
		'pics',
		'picture',
		'pictures',
		'play',
		'player',
		'playlist',
		'post',
		'posts',
		'product',
		'products',
		'program',
		'programs',
		'project',
		'qa',
		'question',
		'rank',
		'ranking',
		'read',
		'readme',
		'redirect',
		'redirect.html',
		'redirect.php',
		'reg',
		'register',
		'res',
		'resource',
		'retrieve',
		'sale',
		'search',
		'season',
		'seasons',
		'section',
		'seller',
		'series',
		'service',
		'services',
		'setting',
		'settings',
		'share',
		'shop',
		'show',
		'shows',
		'site',
		'soft',
		'sort',
		'source',
		'special',
		'star',
		'stars',
		'static',
		'stock',
		'store',
		'stream',
		'streaming',
		'streams',
		'student',
		'study',
		'tag',
		'tags',
		'task',
		'teacher',
		'team',
		'tech',
		'temp',
		'test',
		'thread',
		'tool',
		'tools',
		'topic',
		'topics',
		'torrent',
		'trade',
		'travel',
		'tv',
		'txt',
		'type',
		'u',
		'upload',
		'uploads',
		'url',
		'urls',
		'user',
		'users',
		'v',
		'version',
		'videos',
		'view',
		'vip',
		'vod',
		'watch',
		'web',
		'wenku',
		'wiki',
		'work',
		'www',
		'zh',
		'zh-cn',
		'zh-tw',
		'zip',
	];
	const randomCount = Math.floor(Math.random() * 3 + 1);
	const len = commonPathDirs.length;
	// Fisher-Yates partial shuffle for random selection without full sort
	const indices = new Array(randomCount);
	for (let i = 0; i < randomCount; i++) {
		const j = Math.floor(Math.random() * len);
		indices[i] = commonPathDirs[j];
	}
	const randomSegment = indices.join('/');
	const pathStr = typeof fullNodePath === 'string' ? fullNodePath : '/';
	if (pathStr === '/') return `/${randomSegment}`;
	return `/${randomSegment + pathStr.replace('/?', '?')}`;
}

export function replaceWildcardWithRandomChars(content) {
	if (typeof content !== 'string' || !content.includes('*')) return content;
	const charset = 'abcdefghijklmnopqrstuvwxyz0123456789';
	return content.replace(/\*/g, () => {
		let s = '';
		for (let i = 0; i < Math.floor(Math.random() * 14) + 3; i++)
			s += charset[Math.floor(Math.random() * charset.length)];
		return s;
	});
}

export function getValidDataLength(data) {
	if (!data) return 0;
	if (data instanceof Uint8Array || data instanceof ArrayBuffer) return data.byteLength;
	if (ArrayBuffer.isView(data)) return data.byteLength;
	if (typeof data.length === 'number') return data.length;
	return 0;
}

export async function parseToArray(content) {
	if (!content) return [];
	if (Array.isArray(content)) return content.map((item) => String(item).trim()).filter(Boolean);
	if (typeof content !== 'string') return [];
	const cleanedContent = content.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');
	return cleanedContent
		.split(',')
		.map((s) => s.trim())
		.filter(Boolean);
}
