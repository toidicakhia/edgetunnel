/**
 * src/constants.js
 * Auto-generated from _worker.js refactor
 * Original: edgetunnel 2.1 (2026-08-11)
 */

export const Version = '2026-08-11 14:45:22';

export const pagesStaticPage = 'https://edt-pages.github.io';

// Global constants and tuning
export const wsMaxEarlyDataBytes = 8 * 1024;
export const wsMaxEarlyHeaderLength = Math.ceil((wsMaxEarlyDataBytes * 4) / 3) + 4;

export const uplinkBundleTargetBytes = 20 * 1024;
export const uplinkQueueMaxBytes = 16 * 1024 * 1024;
export const uplinkQueueMaxEntries = 4096;

export const downlinkGrainPacketBytes = 32 * 1024;
export const downlinkGrainTailThreshold = 512;
export const downlinkGrainLowWaterBytes = Math.max(4096, downlinkGrainTailThreshold * 12);
export const downlinkGrainMaxWaitRounds = 4;

export const featureCodeDict = [
	(Proxy.name + 'IP').toUpperCase(),
	(String.fromCharCode(67, 109) + URL.name[2] + 'i' + URL.name[0]).toLowerCase(),
	String(2407 * 300 - 10)
		.split('')
		.reverse()
		.join(''),
];
