# EdgeTunnel Architecture & Protocol Design

## 1. System Overview

```
src/worker.js (entrypoint) -> src/router.js (HTTP / Transport routing & Admin panel)
  ├── src/constants.js           (Pure constants & versioning)
  ├── src/state.js               (Shared state & explicit mutators)
  ├── src/utils/
  │   ├── crypto.js              (Pure MD5, MD5MD5, sha224, WebCrypto helpers, secret cipher)
  │   ├── helpers.js             (Byte array utilities, parseToArray, randomPath, formatting)
  │   ├── network.js             (IP parsing, IPv6 formatting, timeouts)
  │   ├── doh.js                 (DoH DNS resolution, ISP lookup, optimal API pooling)
  │   └── config.js              (KV config management, default configs, usage tracking)
  ├── src/core/
  │   ├── protocol.js            (VLESS, Trojan, Shadowsocks AEAD parsers & ciphers)
  │   ├── vmess.js               (VMess AEAD: KDF, CmdKey, AuthID, Header, Chunked body)
  │   ├── tcp.js                 (TCP/UDP forwarding, race dialing, connection lifecycle)
  │   ├── grain.js               (Uplink & Downlink chunk bundler, flow control queue)
  │   ├── proxy.js               (SOCKS5, HTTP CONNECT, HTTPS proxy TLS client)
  │   ├── tls.js                 (Pure JS TLS 1.2 / 1.3 Client & Handshake engine)
  │   ├── turn.js                (STUN / TURN allocation & relay)
  │   └── sstp.js                (SSTP / PPP packet framing & connection)
  ├── src/handlers/
  │   ├── ws.js                  (WebSocket bidirectional streaming & early-data)
  │   ├── grpc.js                (HTTP/2 gRPC bidirectional streaming bridge)
  │   └── xhttp.js               (XHTTP / HTTP POST streaming with HPACK padding)
  ├── src/subscription/
  │   ├── links.js               (Link generators for VLESS, Trojan, VMess, SS, SOCKS5)
  │   ├── clash.js               (Clash Meta & Standard Clash YAML hot-patching)
  │   ├── singbox.js             (Sing-box JSON format migration, rule-set & uTLS/ECH)
  │   ├── surge.js               (Surge profile configuration hot-patching)
  │   └── generator.js           (Unified subscription dispatcher & Base64 aggregator)
  └── src/html/
      ├── camouflage.js          (Camouflage HTTP 1101 & Nginx reverse proxy pages)
      ├── login.js               (Admin login page)
      ├── admin.js               (Web Admin UI)
      └── errorPages.js          (404 / NoKV error pages)
```

---

## 2. Layering & Dependency Hierarchy (Strict Top-Down)

```
        constants / state (leaf)
               ↑
            utils/*
               ↑
            core/*
          ↗        ↖
   handlers/*    subscription/*
          ↖        ↗
          router.js
              ↑
          worker.js
```

1. **`constants` & `state`**: Zero dependencies. Holds runtime flags and explicit setters (`setDebugLogging`, `setConfigJSON`, etc.).
2. **`utils/*`**: Low-level math, hashing (`crypto.js`), byte conversions (`helpers.js`), DNS (`doh.js`), and config reading (`config.js`). Never imports from `core`, `handlers`, or `subscription`.
3. **`core/*`**: Protocol parsing (VLESS, Trojan, VMess, Shadowsocks), TLS state machine (`tls.js`), and socket connection pipelines (`tcp.js`, `grain.js`, `proxy.js`). Never imports from `handlers`.
4. **`handlers/*` & `subscription/*`**: Transport adaptors (WS, gRPC, XHTTP) and subscription configuration builders (Clash, Sing-box, Surge).
5. **`router.js`**: Central dispatcher routing requests to WebSocket upgrades, gRPC, XHTTP, subscription endpoints, and admin panels.

---

## 3. Protocol Implementations

### VLESS
- **Handshake**: Version byte (0x00), 16-byte UUID matching with cached byte comparisons (`uuidBytesMatch`), add-on options length, command byte (0x01 = TCP, 0x02 = UDP), port (2 bytes BE), and address type (0x01 IPv4, 0x02 Domain, 0x03 IPv6).
- **Response**: 2-byte response header `[version, 0x00]`.

### Trojan
- **Handshake**: 56-byte hexadecimal SHA-224 hash matching token password + `\r\n` (0x0d 0x0a) delimiter.
- **Payload**: SOCKS5 destination header (Command: 0x01 TCP / 0x03 UDP, Address Type: 0x01 / 0x03 / 0x04) + `\r\n` + raw client stream.
- **UDP Framing**: 2-byte length-delimited DNS framing with `\r\n` delimiters.

### VMess AEAD
- **AuthID**: 16-byte AES-128-ECB encrypted block containing 8-byte Unix timestamp (BE), 4 random bytes, and 4-byte CRC32. Decryption validates timestamp drift (±120s) and CRC32.
- **KDF**: Nested HMAC-SHA256 key derivation (`vmessKDF` / `vmessKDF16`) deriving `HeaderPayloadLengthAEADKey`, `HeaderPayloadLengthAEADIV`, `HeaderPayloadAEADKey`, and `HeaderPayloadAEADIV`.
- **Outer Header**: 18-byte AEAD length prefix (2 bytes plaintext + 16 bytes Poly1305/GCM tag) + 8-byte nonce + length-delimited AEAD inner header.
- **Inner Header**: Decrypted command header containing Security type (AES-128-GCM, ChaCha20-Poly1305, None), BodyKey (16 bytes), BodyIV (16 bytes), Port (2 bytes BE), Address Type, and Hostname.
- **Body Chunks**: Length-prefixed AEAD chunks decrypted sequentially with incremental nonce generation (`generateChunkNonce`).

### Shadowsocks AEAD
- **Master Key**: EVP MD5 multi-round master key derivation (`SSDeriveMasterKey`) via pure JS MD5.
- **Session Key**: HKDF-SHA1 subkey derivation with 16-byte salt for `aes-128-gcm` or 32-byte salt for `aes-256-gcm`.
- **Framing**: 2-byte length AEAD chunk + length-prefixed payload AEAD chunk with incremental 12-byte nonce counter (`SSIncrementNonceCounter`).

---

## 4. Verification & Testing

```bash
# Run unit tests
bun run test

# Run ESLint (0 errors, 0 warnings)
bun run lint

# Run syntax verification
bun run check

# Run Wrangler dry-run build
bun run deploy:dry
```

All 23 automated unit tests cover:
- Cryptographic hashers and secret encoders (`test/crypto.test.js`)
- VLESS, Trojan, and Shadowsocks protocol decoders (`test/protocol.test.js`)
- VMess AEAD KDF, AuthID roundtrip, and link generation (`test/vmess.test.js`)
- Subscription links, Clash, Sing-box, Surge hot-patchers (`test/subscription.test.js`)
- Helper byte buffers and array parsing utilities (`test/helpers.test.js`)
