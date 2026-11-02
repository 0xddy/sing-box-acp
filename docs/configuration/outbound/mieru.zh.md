# Mieru

## 配置

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

Mieru 使用用户名和密码进行认证。两端时钟需同步。 `transport` 指客户端与服务器之间的底层连接，可选 `tcp`（默认）或 `udp`。两种方式均支持代理 TCP 和 UDP 业务，无需 TLS 或 QUIC。
复用公共拨号选项。`network` 限制代理的业务类型，省略时同时允许 TCP 和 UDP。`server_port` 和 `server_ports` 二选一，后者可写成 `["2027", "3000:3010"]`，服务器需在相应端口监听。

`multiplexing` 可选 `off`、`low`（默认）、`middle`、`high`。`handshake_mode` 可选 `standard`（默认，拨号时等待代理响应）或 `no_wait`（首次读写时握手，首次写入可合并业务数据）。

`mtu` 默认 1400，可设置为 1280–1500。`traffic_pattern` 可填写官方 Base64 流量特征，省略时采用官方默认行为。[官方流量特征文档](https://github.com/enfein/mieru/blob/v3.39.0/docs/traffic-pattern.zh_CN.md)
