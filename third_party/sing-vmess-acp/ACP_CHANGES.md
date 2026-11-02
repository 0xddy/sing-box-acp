# ACP sing-vmess changes

The source is based on `github.com/sagernet/sing-vmess` at
`v0.2.9-0.20261019223527-a0c58542bd9d`. See `LICENSE` for the upstream license.

Vision serializes TLS detection across both directions of each connection.
Writers take a consistent snapshot for padding and direct-mode decisions.
Once detection completes, both directions read an immutable result. The
detector lock never spans network I/O. The TLS buffer accessors retain a Go
pointer while computing field addresses, including when checkptr is enabled.

The companion uTLS fix is in `../utls-acp`. Run the core regression tests
with `go test -race -tags with_utls ./protocol/vless -run TestVision` on Linux.
