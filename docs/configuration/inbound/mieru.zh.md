# Mieru

## 配置

```json
{
  "type": "mieru",
  "tag": "mieru-in",
  "listen": "::",
  "listen_port": 2027,
  "users": [
    {
      "name": "alice",
      "password": "example-password"
    }
  ],
  "transport": "tcp"
}
```

Mieru 使用用户名和密码进行认证。两端时钟需同步。 `transport` 指客户端与服务器之间的底层连接，可选 `tcp`（默认）或 `udp`。两种方式均支持代理 TCP 和 UDP 业务，无需 TLS 或 QUIC。
复用公共监听选项。每个用户的 `name` 必须唯一，用户名和密码均为 1–64 字节。空用户列表会立即绑定端口并拒绝认证。热更新时，删除用户或修改密码会关闭其旧会话，其他用户继续传输。路由规则可通过 `auth_user` 匹配认证用户名。

`user_hint_is_mandatory` 默认关闭。开启后要求客户端提供官方协议的用户名提示。

`mtu` 默认 1400，可设置为 1280–1500。`traffic_pattern` 可填写官方 Base64 流量特征，省略时采用官方默认行为。[官方流量特征文档](https://github.com/enfein/mieru/blob/v3.39.0/docs/traffic-pattern.zh_CN.md)

TCP 客户端等待 CONNECT 结果时，入站先拨号，并将目标的成功或拒连结果返回客户端。使用 `no_wait` 并在请求中携带首包时，该首包可用于路由嗅探。
