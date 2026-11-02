# ACP uTLS changes

The source is based on `github.com/metacubex/utls v1.8.7`. See `LICENSE`
for the upstream license.

After the TLS 1.3 handshake, alerts use encrypted application-data records.
`Conn.Read` returns the last authenticated record before inspecting any
subsequent bytes. This lets Vision consume raw data already buffered at the
direct-mode boundary, including data starting with 0x15. TLS 1.2 retains
its existing close_notify handling. The core test `TestVisionTLS13DirectRead`
exercises this boundary.
