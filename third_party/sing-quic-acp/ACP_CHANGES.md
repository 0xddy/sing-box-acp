# ACP sing-quic changes

This directory is based on `github.com/sagernet/sing-quic` commit
`7e0a5869a5f4` (`v0.7.2-0.20261020082049-7e0a5869a5f4`) and remains under the upstream
license in `LICENSE`.

ACP adds concurrency-safe Hysteria2 authentication snapshots and targeted
revocation of authenticated QUIC sessions. The public module path remains
`github.com/sagernet/sing-quic` so workspace modules can use it through a Go
`replace` directive.

The ACP Juicity package implements its wire protocol on the existing SagerNet
QUIC stack. It owns its user/session lifecycle and both UDP paths. The
sing-box protocol adapter supplies TLS, listeners, dialing and routing.

Run the Juicity wire and integration tests on Linux from the sing-box root.

```sh
go test -race -tags 'with_utls with_quic' github.com/sagernet/sing-quic/juicity ./protocol/juicity
```

The primary interoperability target is upstream **juicity-rs v1.1.4**.
Set `JUICITY_RUST_DIR` to the directory containing its executable
`juicity-client` and `juicity-server` binaries. The Linux x86_64 musl
release ZIP has SHA-256
`b8bdd4f4c5c5c5ecf62d2952e3165afede6faa747aa4e156c869075cfe744bcb`.
The Rust tests exercise both directions over IPv4, IPv6 and domain targets.
They also check that an initial port-zero hint still uses stream UDP in
default and automatic mode.

For explicit Underlay, the wire reference is the Rust common library's
[`encrypt_udp` and `decrypt_udp`](https://github.com/juicity/juicity-rs/blob/v1.1.4/common/src/crypto.rs#L226-L259).
The v1.1.4 server instead retains the cipher derived from the first packet.
Its pinned interoperability test checks the plaintext at the UDP target and
tests subsequent requests and replies separately. The Linux Juicity workflow
also builds `protocol/juicity/testdata/underlay_codec.rs` as an example of the
pinned upstream crate and passes its executable path as `JUICITY_RUST_CODEC`.
This exercises both Rust library encryption to the ACP inbound and decryption
of its actual response.

For optional historical compatibility tests, set `JUICITY_OFFICIAL_DIR`
to the Go v0.5.0 binaries. The Linux x86_64 release ZIP has SHA-256
`c0c11e8691e6a16b42de7c7a02d83a616fef79e574a88cc3765045c0b91b1e66`.
The Underlay vectors were generated with Rust v1.1.4's `encrypt_udp` and
checked with `decrypt_udp`. Go's codec at revision `c607702d1c85` emits
the same bytes for these vectors.
