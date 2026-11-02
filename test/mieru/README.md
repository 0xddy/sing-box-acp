# Mieru interoperability

The Linux test uses real SOCKS clients, loopback TCP greeting/echo targets and UDP echo targets. The two reference programs must report version 3.39.0. CI builds both from [the unmodified upstream commit](https://github.com/enfein/mieru/tree/bcd14b88d0fb7e7707bb80e5d7f6c33675d26c06), separately from the embedded module.

```sh
go build -o /tmp/sing-box ./cmd/sing-box
go -C /path/to/upstream-mieru build -o /tmp/ ./cmd/mieru ./cmd/mita
python3 test/mieru/interop.py --box /tmp/sing-box --mieru /tmp/mieru --mita /tmp/mita
go test -race ./protocol/mieru
go -C third_party/mieru-acp test -race ./apis/... ./pkg/protocol/...
```

Verified on Linux/amd64 with Go 1.26.1:

| Direction | TCP transport | UDP transport |
| --- | --- | --- |
| Official mieru client → ACP inbound | TCP and UDP passed | TCP and UDP passed |
| ACP outbound → official mita server | TCP and UDP passed | TCP and UDP passed |

The positive cases compare TCP and UDP bytes, include a server-first greeting, and alternate IPv4, IPv6 and domain destinations in one UDP association. The inbound routes traffic by the authenticated name. The outbound resolves its server through the configured sing-box DNS transport. The matrix enables an upstream traffic-pattern seed and checks rejection of an incorrect password separately for each transport and direction.

Credential lifecycle tests operate below SOCKS. They race new streams against deletion, password changes and kicks, check that another user's session still echoes, and exercise deletion followed by re-adding the same credential.
