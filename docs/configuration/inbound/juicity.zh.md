# Juicity 入站

Juicity 在同一个 UDP 端口接收 TCP、标准 UDP 和 Underlay UDP。构建时需要启用 `with_quic`。

```json
{
  "type": "juicity",
  "tag": "juicity-in",
  "listen": "::",
  "listen_port": 443,
  "users": [
    {
      "name": "alice",
      "uuid": "059032a9-7d40-4a96-9bb1-36823d848068",
      "password": "replace-with-a-secret"
    }
  ],
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/sing-box/fullchain.pem",
    "key_path": "/etc/sing-box/key.pem"
  }
}
```

同一个入站下的 UUID 必须唯一，密码不能为空。`name` 是路由和统计使用的用户名。热更新时，移除用户或修改凭据会关闭该用户的会话和 Underlay 映射。

TLS 使用 1.3 和 ALPN `h3`。`congestion_control` 可选 `bbr`（默认）、`cubic` 或 `new_reno`。`auth_timeout` 默认 `10s`。若设置 `max_concurrent_streams`，至少为 30。
