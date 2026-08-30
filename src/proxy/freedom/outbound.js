/**
 * src/proxy/freedom/outbound.js
 * Freedom outbound — mirror of Xray-core proxy/freedom + current edgetunnel
 * direct-connect mechanics (preload race dial, concurrent dial, SSRF guard).
 *
 * dispatch(ctx, link): dial dest (resolve A/AAAA when PRELOAD_RACE_DIAL),
 * pump link.readable → socket and socket → link.writable.
 */

import { Handler } from '../../features/outbound.js';
import { dialTCP, pumpStream } from '../../transport/internet/tcp.js';
import { isDestinationSafe, isIPHostname, isIPv4 } from '../../utils/network.js';
import { doHQuery } from '../../utils/doh.js';
import { log } from '../../utils/helpers.js';
import { TCP_CONCURRENT_DIAL_COUNT, PRELOAD_RACE_DIAL } from '../../state.js';

export class FreedomHandler extends Handler {
	constructor(tag, { request = null, safeGuard = true } = {}) {
		super(tag);
		this.request = request;
		this.safeGuard = safeGuard;
		this._connector = null;
	}

	getConnector() {
		if (!this._connector) {
			const requestObj = /** @type {any} */ (this.request);
			const fetcher = requestObj?.fetcher;
			this._connector =
				fetcher && typeof fetcher.connect === 'function'
					? (options, init) =>
							init === undefined ? fetcher.connect(options) : fetcher.connect(options, init)
					: null;
		}
		return this._connector;
	}

	isSafe(dest) {
		return !this.safeGuard || isDestinationSafe(dest.address, dest.port);
	}

	/** Build preload-race candidates (A/AAAA) or plain concurrent copies. */
	async buildCandidateList(address, port) {
		if (PRELOAD_RACE_DIAL && !isIPHostname(address)) {
			log(`[freedom] preloadRaceDial enabled, query ${address} A/AAAA`);
			const [aRecords, aaaaRecords] = await Promise.all([
				doHQuery(address, 'A'),
				doHQuery(address, 'AAAA'),
			]);
			const ipv4List = [
				...new Set(
					aRecords.flatMap((r) =>
						r.type === 1 && typeof r.data === 'string' && isIPv4(r.data) ? [r.data] : []
					)
				),
			];
			const ipv6List = [
				...new Set(
					aaaaRecords.flatMap((r) =>
						r.type === 28 && typeof r.data === 'string' && isIPHostname(r.data)
							? [r.data]
							: []
					)
				),
			];
			const dialLimit = Math.max(1, TCP_CONCURRENT_DIAL_COUNT | 0);
			const ipList =
				ipv4List.length >= dialLimit
					? ipv4List.slice(0, dialLimit)
					: ipv4List.concat(ipv6List.slice(0, dialLimit - ipv4List.length));
			if (ipList.length === 0) {
				log(`[freedom] ${address} no valid A/AAAA, fallback to original hostname`);
				return Array.from({ length: dialLimit }, (_, attempt) => ({ hostname: address, port, attempt }));
			}
			log(`[freedom] ${address} race dial ${ipList.length}/${dialLimit}: ${ipList.join(', ')}`);
			return ipList.map((hostname, attempt) => ({ hostname, port, attempt, resolvedFrom: address }));
		}
		const dialLimit = Math.max(1, TCP_CONCURRENT_DIAL_COUNT | 0);
		return Array.from({ length: dialLimit }, (_, attempt) => ({ hostname: address, port, attempt }));
	}

	/** Open candidates concurrently; first-opened wins, losers closed. */
	async openConcurrent(candidateList) {
		if (candidateList.length === 1) {
			const c = candidateList[0];
			return { socket: await dialTCP(this.getConnector(), c), candidate: c };
		}
		const attempts = candidateList.map((candidate) =>
			dialTCP(this.getConnector(), candidate).then((socket) => ({ socket, candidate }))
		);
		let winner = null;
		try {
			winner = await Promise.any(attempts);
			return winner;
		} finally {
			if (winner) {
				for (const attempt of attempts) {
					attempt
						.then(({ socket }) => {
							if (socket !== winner.socket) {
								try {
									socket.close();
								} catch {
									/* ignore */
								}
							}
						})
						.catch(() => {});
				}
			}
		}
	}

	async dial(ctx, dest) {
		const connector = this.getConnector();
		if (!connector) throw new Error('freedom: no connector available');
		const candidateList = await this.buildCandidateList(dest.address, dest.port);
		const result = await this.openConcurrent(candidateList);
		if (result.candidate?.resolvedFrom) {
			log(
				`[freedom] preload race result: ${result.candidate.hostname}:${result.candidate.port} won, source: ${result.candidate.resolvedFrom}`
			);
		}
		return result.socket;
	}

	async dispatch(ctx, link) {
		if (!link || !link.readable || !link.writable) throw new Error('freedom: no link');
		const dest = ctx.outbound?.target;
		if (!dest) throw new Error('freedom: no target');
		if (!this.isSafe(dest)) {
			throw new Error(`freedom: unsafe destination ${dest.address}:${dest.port}`);
		}

		let socket;
		try {
			socket = await this.dial(ctx, dest);
		} catch (err) {
			log(`[freedom] dial ${dest.address}:${dest.port} failed: ${err?.message || err}`);
			throw err;
		}

		return new Promise((resolve, reject) => {
			let settled = false;
			const settle = (fn, arg) => {
				if (settled) return;
				settled = true;
				fn(arg);
			};

			const up = pumpStream(link.readable, socket.writable, {
				onClose: () => {
					try {
						socket.close();
					} catch {
						/* ignore */
					}
				},
				onError: (err) => settle(reject, err),
			});
			const down = pumpStream(socket.readable, link.writable, {
				onError: (err) => {
					up.close();
					settle(reject, err);
				},
			});

			socket.closed
				.catch(() => {})
				.then(() => {
					up.close();
					link.writable.close().catch(() => {});
					settle(resolve, undefined);
				});
		});
	}
}