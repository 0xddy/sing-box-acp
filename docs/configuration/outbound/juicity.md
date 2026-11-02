# Juicity outbound

```json
{
  "type": "juicity",
  "tag": "juicity-out",
  "server": "proxy.example.com",
  "server_port": 443,
  "uuid": "059032a9-7d40-4a96-9bb1-36823d848068",
  "password": "replace-with-a-secret",
  "udp_mode": "auto",
  "tls": {
    "enabled": true,
    "server_name": "proxy.example.com"
  }
}
```

| `udp_mode` | Behavior |
| --- | --- |
| `auto` (default) | Uses stream UDP for every destination, including a port-zero hint, matching the Rust client's SOCKS and forwarding paths. |
| `stream` | Shares a reliable QUIC stream across UDP destinations. |
| `underlay` | Uses Underlay even for ordinary ports. An authenticated QUIC session registers a key and a fixed target for a separate encrypted UDP path. |

Use the system trust store or configure a TLS CA. To pin a chain, set the outbound's top-level `pinned_certchain_sha256` to the decoded fingerprint in the share link printed by `juicity-server export -c server.json --link --with-certchain-sha256`. The pin verifies the entire presented chain and needs updating when certificates rotate. TLS uses version 1.3 and ALPN `h3`. Congestion control defaults to `bbr`. Other options are `cubic` and `new_reno`.

**Interoperability.** The reference implementation for ACP is [juicity-rs v1.1.4](https://github.com/juicity/juicity-rs/releases/tag/v1.1.4). Linux tests cover TCP and stream UDP in both directions over IPv4, IPv6 and domain targets, including multiple UDP destinations on the same stream.

With Rust v1.1.4, use the default `auto` or select `stream`. Explicit `underlay` follows the Rust common library's `encrypt_udp` and `decrypt_udp`, which derive a fresh subkey for each packet. The v1.1.4 server caches the first subkey. As a result, the target receives the first ACP request, the second request fails authentication, and ACP cannot decrypt the reply. Go v0.5.0 is tested separately for historical compatibility. [Rust Underlay codec](https://github.com/juicity/juicity-rs/blob/v1.1.4/common/src/crypto.rs#L226-L259)
