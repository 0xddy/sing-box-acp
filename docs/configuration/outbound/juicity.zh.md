# Juicity 出站

```json
{
  "type": "juicity",
  "tag": "juicity-out",
  "server": "proxy.example.com",
  "server_port": 443,
  "uuid": "059032a9-7d40-4a96-9bb1-36823d848068",
  "password": "replace-with-a-secret",
  "udp_mode": "auto",
  "tls": {
    "enabled": true,
    "server_name": "proxy.example.com"
  }
}
```

| `udp_mode` | 行为 |
| --- | --- |
| `auto`（默认） | 所有目标均走 stream，包括初始目标端口为 0 的情况，与 Rust 客户端的 SOCKS 和端口转发行为一致。 |
| `stream` | 同一条可靠 QUIC 流承载多个目的地址的 UDP 数据报。 |
| `underlay` | 普通端口也走 Underlay。通过已认证的 QUIC 会话登记密钥和固定目标，再使用独立的加密 UDP 数据通道。 |

使用系统信任链或 TLS 的自定义 CA 验证服务器。要固定证书链，可用 Rust 的 `juicity-server export -c server.json --link --with-certchain-sha256` 导出分享链接，将链接中经 URL 解码的 `pinned_certchain_sha256` 填入出站顶层同名字段。指纹验证整条对端证书链，证书续期后需更新。TLS 使用 1.3 和 ALPN `h3`。拥塞控制默认 `bbr`，也支持 `cubic` 和 `new_reno`。

**互通。** ACP 以 [juicity-rs v1.1.4](https://github.com/juicity/juicity-rs/releases/tag/v1.1.4) 为参考实现。Linux 测试覆盖两个方向的 TCP 和标准 UDP，包括 IPv4、IPv6、域名，以及同一条 UDP 流访问多个目的地址。

对接 Rust v1.1.4 时使用默认的 `auto` 或显式 `stream`。显式 `underlay` 遵循 Rust 公共库的 `encrypt_udp` 和 `decrypt_udp`，每个包独立派生子密钥。v1.1.4 服务端会缓存首包子密钥，因此目标能收到第一个请求，第二个请求会被丢弃，本内核也无法解密回包。Go v0.5.0 单独作为历史兼容性测试对象。[Rust Underlay 编解码](https://github.com/juicity/juicity-rs/blob/v1.1.4/common/src/crypto.rs#L226-L259)
