# ACP sing-quic changes

This directory is based on `github.com/sagernet/sing-quic` commit
`7e0a5869a5f4` (`v0.7.2-0.20261020082049-7e0a5869a5f4`) and remains under the upstream
license in `LICENSE`.

ACP adds concurrency-safe Hysteria2 authentication snapshots and targeted
revocation of authenticated QUIC sessions. The public module path remains
`github.com/sagernet/sing-quic` so workspace modules can use it through a Go
`replace` directive.
