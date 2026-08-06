# ACP sing-quic changes

This directory is based on `github.com/sagernet/sing-quic` commit
`43cdc830d7cf` and remains under the upstream license in `LICENSE`.

ACP adds concurrency-safe Hysteria2 authentication snapshots and targeted
revocation of authenticated QUIC sessions. The public module path remains
`github.com/sagernet/sing-quic` so workspace modules can use it through a Go
`replace` directive.
