/**
 * src/common/net.js
 * Network destination model + address (de)serialization —
 * mirror of Xray-core common/net + common/protocol/address.go.
 *
 * Address type bytes (common/protocol/payload.go AddressType):
 *   IPv4 = 1, Domain = 2, IPv6 = 3   (wire values used by Trojan/SOCKS)
 * VLESS/VMess/XUDP/mux use the same 0x01/0x02/0x03 family bytes (address.go).
 */

export const Network = Object.freeze({
	TCP: 0x01,
	UDP: 0x02,
	UNIX: 0x03,
});

/**
 * Destination — parsed target. Equivalent to net.Destination.
 * @param {string} address hostname or IP
 * @param {number} port port (0 allowed for domain rules)
 * @param {number} network Network.TCP | Network.UDP
 */
export class Destination {
	constructor(address, port, network = Network.TCP) {
		this.address = address;
		this.port = port;
		this.network = network;
	}

	isIPv4() {
		return /^\d{1,3}(\.\d{1,3}){3}$/.test(this.address);
	}

	isIPv6() {
		return this.address.includes(':');
	}

	isDomain() {
		return !this.isIPv4() && !this.isIPv6();
	}

	clone() {
		return new Destination(this.address, this.port, this.network);
	}
}
