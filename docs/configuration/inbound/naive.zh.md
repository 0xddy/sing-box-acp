!!! quote "sing-box 1.13.0 中的更改"

    :material-plus: [quic_congestion_control](#quic_congestion_control)

### 结构

```json
{
"type": "naive",
"tag": "naive-in",
"network": "udp",

... // 监听字段

"users": [
{
"username": "sekai",
"password": "password"
}
],
"quic_congestion_control": "",
"tls": {},
"web": {"type": "static", "content": "<h1>Website</h1>"}
}
```

### 监听字段

参阅 [监听字段](/zh/configuration/shared/listen/)。

### 字段

#### network

监听的网络协议，`tcp` `udp` 之一。

默认所有。

#### users

Naive 用户。允许空列表，此时网站仍可访问，代理认证全部拒绝。
用户名和密码不能为空，同一入站用户名不可重复。

#### quic_congestion_control

!!! question "Since sing-box 1.13.0"

QUIC 拥塞控制算法。

| 算法             | 描述                 |
|----------------|--------------------|
| `bbr`          | BBR                |
| `cubic`        | CUBIC              |
| `reno`         | New Reno           |

默认使用 `bbr`。

#### tls

TLS 配置, 参阅 [TLS](/zh/configuration/shared/tls/#入站)。

启用 QUIC 或 `web` 时必须启用 TLS。证书热更新不会重新绑定端口。

#### web（ACP）

可选网站配置，复用 AnyTLS 的 `WebOptions`：静态内容使用 `type: static`
和 `content`；反向代理使用 `type: proxy` 和管理员指定的 `url`。
普通请求、缺少 Padding 或认证失败的 CONNECT 进入网站规则，不发送代理认证挑战。
只有认证成功的 CONNECT 进入代理路由与计费。

网站的 30 秒请求期限不会作为已认证隧道的总寿命或空闲期限。
隧道保留单次写入两分钟无进展保护，写完即清除期限；用户撤销与服务关闭可取消阻塞。
HTTP/2、HTTP/3 按流执行认证与撤销，同一连接上的其他用户保持连接。
客户端自身、目标服务器和中间网络的超时仍可能结束连接。

每个入站最多 256 条 TCP/QUIC 传输连接、每连接 100 个并发流、4096 个已认证代理流。
这些是资源上限，不是已完成性能验收的容量承诺。HTTP/3 不启用 0-RTT。
Naive 的 HTTP/2 使用引擎默认调度器，保留其实际 SETTINGS；不宣称与 Apache 的
HTTP/2 优先级设置、TLS/QUIC 字节和时序完全一致。
