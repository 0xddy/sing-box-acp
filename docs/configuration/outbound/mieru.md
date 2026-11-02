# Mieru

## Configuration

```json
{
  "type": "mieru",
  "tag": "mieru-out",
  "server": "203.0.113.1",
  "server_port": 2027,
  "username": "alice",
  "password": "example-password",
  "transport": "tcp",
  "multiplexing": "low",
  "handshake_mode": "standard"
}
```

Mieru authenticates with a username and password. Keep both clocks synchronized. `transport` selects the connection between the client and server, either `tcp` (default) or `udp`. Both carry TCP and UDP traffic without TLS or QUIC.
Use the common dial options. `network` controls proxied traffic and allows both TCP and UDP by default. Set exactly one of `server_port` and `server_ports`. For example, `["2027", "3000:3010"]` selects from multiple listening ports on the server.

`multiplexing` accepts `off`, `low` (default), `middle`, or `high`. `handshake_mode` accepts `standard` (default, wait for the proxy response during dial) or `no_wait` (handshake on first I/O and combine the first write with the request).

`mtu` defaults to 1400 and accepts values from 1280 through 1500. Set `traffic_pattern` to an official Base64 traffic pattern, or omit it for upstream defaults. [Traffic patterns](https://github.com/enfein/mieru/blob/v3.39.0/docs/traffic-pattern.md)
