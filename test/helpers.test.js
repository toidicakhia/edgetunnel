import test from 'node:test';
import assert from 'node:assert/strict';
import {
	parseToArray,
	getValidDataLength,
	concatByteData,
	toUint8Array,
	randomPath,
	replaceWildcardWithRandomChars,
} from '../src/utils/helpers.js';

test('parseToArray splits strings and parses arrays correctly', async () => {
	assert.deepEqual(await parseToArray('1.1.1.1, 8.8.8.8, 9.9.9.9'), ['1.1.1.1', '8.8.8.8', '9.9.9.9']);
	assert.deepEqual(await parseToArray('node1\nnode2\nnode3'), ['node1', 'node2', 'node3']);
	assert.deepEqual(await parseToArray(['a', 'b', 'c']), ['a', 'b', 'c']);
	assert.deepEqual(await parseToArray(null), []);
});

test('getValidDataLength measures array buffers and views accurately', () => {
	assert.equal(getValidDataLength(new Uint8Array(10)), 10);
	assert.equal(getValidDataLength(new ArrayBuffer(32)), 32);
	assert.equal(getValidDataLength(null), 0);
	assert.equal(getValidDataLength(undefined), 0);
});

test('concatByteData merges byte chunks into a contiguous Uint8Array', () => {
	const a = new Uint8Array([1, 2, 3]);
	const b = new Uint8Array([4, 5]);
	const c = new Uint8Array([6]);

	const merged = concatByteData(a, b, c);
	assert.equal(merged.length, 6);
	assert.deepEqual(Array.from(merged), [1, 2, 3, 4, 5, 6]);
});

test('toUint8Array handles null, Uint8Array, ArrayBuffer and views safely', () => {
	const arr = new Uint8Array([10, 20]);
	assert.equal(toUint8Array(arr), arr);

	const buf = new ArrayBuffer(2);
	const converted = toUint8Array(buf);
	assert.equal(converted instanceof Uint8Array, true);
	assert.equal(converted.byteLength, 2);

	assert.equal(toUint8Array(null).byteLength, 0);
});

test('randomPath and replaceWildcardWithRandomChars produce correct format', () => {
	const path = randomPath('/subpath');
	assert.equal(typeof path, 'string');
	assert.equal(path.startsWith('/'), true);
	assert.equal(path.includes('subpath'), true);

	const replaced = replaceWildcardWithRandomChars('prefix-*-suffix');
	assert.equal(replaced.startsWith('prefix-'), true);
	assert.equal(replaced.endsWith('-suffix'), true);
	assert.equal(replaced.includes('*'), false);
});
