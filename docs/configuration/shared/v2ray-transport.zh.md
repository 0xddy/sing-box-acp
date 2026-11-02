V2Ray Transport 是 v2ray 发明的一组私有协议，并污染了其他协议的名称，如 clash 中的 `trojan-grpc`。

### 结构

```json
{
  "type": ""
}
```

可用的传输协议：

* HTTP
* WebSocket
* QUIC
* gRPC
* HTTPUpgrade
* XHTTP（ACP）

!!! warning "与 v2ray-core 的区别"

    * 没有 TCP 传输层, 纯 HTTP 已合并到 HTTP 传输层。
    * 没有 mKCP 传输层。
    * 没有 DomainSocket 传输层。

!!! note ""

    当内容只有一项时，可以忽略 JSON 数组 [] 标签。

### XHTTP（ACP）

```json
{
  "type": "xhttp",
  "mode": "auto",
  "host": "proxy.example.com",
  "path": "/proxy/",
  "headers": { "X-Site": "edge" },
  "x_padding_bytes": "100-1000"
}
```

ACP 的 XHTTP 入站和出站支持 TLS 或 REALITY 上的 HTTP/2。VLESS 的服务端用户和客户端均应留空 `flow`。使用 raw TCP + Vision 时省略整个 `transport` 对象。

| 模式 | 一条代理连接对应的 HTTP 请求 |
| --- | --- |
| `packet-up` | 多个带序号的上行请求，共用一个流式下载 GET。服务端在有限窗口内重排上行数据。 |
| `stream-up` | 一个流式上行请求和一个独立的下载 GET。 |
| `stream-one` | 一个双向流式请求，默认使用 POST。 |
| `auto`（默认） | 入站接受以上三种模式。普通 TLS 出站选择 `packet-up`，REALITY 出站选择 `stream-one`，指定独立下载设置时选择 `stream-up`。 |

| 配置项 | 行为 |
| --- | --- |
| `host`、`path`、`headers` | HTTP Host 可与 TLS SNI 分别指定。路径默认 `/`，支持查询字符串。自定义头用于客户端请求或服务端响应。 |
| `x_padding_bytes`、`x_padding_obfs_mode`、`x_padding_placement`、`x_padding_key`、`x_padding_header`、`x_padding_method` | 默认在 Referer 查询参数中填充 100–1000 字节。混淆模式支持 `header`、`cookie`、`query`、`queryInHeader`，填充方法支持 `repeat-x`、`tokenish`。两端应匹配。 |
| `session_placement`、`session_key`、`seq_placement`、`seq_key` | 会话 ID 与分包序号可分别放在路径（默认）、查询参数、请求头或 Cookie 中。`session_table` 和 `session_length` 一起指定客户端生成 ID 的字符表和长度。 |
| `uplink_http_method`、`uplink_data_placement`、`uplink_data_key`、`uplink_chunk_size` | 默认 POST。分包数据可通过请求体、编号请求头或 Cookie 发送。GET 上传需显式选择 `packet-up` 和请求头或 Cookie 数据。 |
| `sc_max_each_post_bytes`、`sc_min_posts_interval_ms`、`sc_max_buffered_posts` | 分包大小（默认 1,000,000 字节）、发送间隔（默认 30 毫秒）及乱序窗口（默认 30 包）。 |
| `sc_stream_up_server_secs`、`no_grpc_header`、`no_sse_header`、`server_max_header_bytes` | 流式上行心跳间隔（默认 20–80 秒）、可选内容类型头和入站请求头上限（默认 16 KiB）。 |
| `xmux`（出站） | 支持 `max_connections` 或 `max_concurrency`、`c_max_reuse_times`、`h_max_request_times`、`h_max_reusable_secs` 和 `h_keep_alive_period`（秒）。控制底层 HTTP 连接复用与轮换。 |
| `download_settings`（出站） | 在分离模式下可覆盖下载的 `host`、`path`。下载与上行共用服务器地址、拨号器和 TLS 配置。 |

范围值可写为单个数字、`"100-1000"` 形式的字符串或两个数字组成的数组。在 `stream-one` 中，下行半关闭后仍会接收上行尾部，下载方可能要等上传结束才收到 EOF。分离模式可单独结束下载。`packet-up` 的线上协议没有单独的上传 FIN。

### HTTP

```json
{
  "type": "http",
  "host": [],
  "path": "",
  "method": "",
  "headers": {},
  "idle_timeout": "15s",
  "ping_timeout": "15s"
}
```

!!! warning "与 v2ray-core 的区别"

    不强制执行 TLS。如果未配置 TLS，将使用纯 HTTP 1.1。

#### host

主机域名列表。

如果设置，客户端将随机选择，服务器将验证。

#### path

!!! warning

    V2Ray 文档称服务端和客户端的路径必须一致，但实际代码允许客户端向路径添加任何后缀。
    sing-box 使用与 V2Ray 相同的行为，但请注意，该行为在 `WebSocket` 和 `HTTPUpgrade` 传输层中不存在。

HTTP 请求路径

服务器将验证。

#### method

HTTP 请求方法

如果设置，服务器将验证。

#### headers

HTTP 请求的额外标头

如果设置，服务器将写入响应。

#### idle_timeout

在 HTTP2 服务器中：

指定闲置客户端应在多长时间内使用 GOAWAY 帧关闭。PING 帧不被视为活动。

在 HTTP2 客户端中：

如果连接上没有收到任何帧，指定一段时间后将使用 PING 帧执行健康检查。需要注意的是，PING 响应被视为已接收的帧，因此如果连接上没有其他流量，则健康检查将在每个间隔执行一次。如果值为零，则不会执行健康检查。

默认使用零。

#### ping_timeout

在 HTTP2 客户端中：

指定发送 PING 帧后，在指定的超时时间内必须接收到响应。如果在指定的超时时间内没有收到 PING 帧的响应，则连接将关闭。默认超时持续时间为 15 秒。

### WebSocket

```json
{
  "type": "ws",
  "path": "",
  "headers": {},
  "max_early_data": 0,
  "early_data_header_name": ""
}
```

#### path

HTTP 请求路径

服务器将验证。

#### headers

HTTP 请求的额外标头

如果设置，服务器将写入响应。

#### max_early_data

请求中允许的最大有效负载大小。默认启用。

#### early_data_header_name

默认情况下，早期数据在路径而不是标头中发送。

要与 Xray-core 兼容，请将其设置为 `Sec-WebSocket-Protocol`。

它需要与服务器保持一致。

### QUIC

```json
{
  "type": "quic"
}
```

!!! warning "与 v2ray-core 的区别"

    没有额外的加密支持：
    它基本上是重复加密。 并且 Xray-core 在这里与 v2ray-core 不兼容。

### gRPC

!!! note ""

    默认安装不包含标准 gRPC (兼容性好，但性能较差), 参阅 [安装](/zh/installation/build-from-source/#构建标记)。

```json
{
  "type": "grpc",
  "service_name": "TunService",
  "idle_timeout": "15s",
  "ping_timeout": "15s",
  "permit_without_stream": false
}
```

#### service_name

gRPC 服务名称。

#### idle_timeout

在标准 gRPC 服务器/客户端：

如果传输在此时间段后没有看到任何活动，它会向客户端发送 ping 请求以检查连接是否仍然活动。

在默认 gRPC 服务器/客户端：

它的行为与 HTTP 传输层中的相应设置相同。

#### ping_timeout

在标准 gRPC 服务器/客户端：

经过一段时间之后，客户端将执行 keepalive 检查并等待活动。如果没有检测到任何活动，则会关闭连接。

在默认 gRPC 服务器/客户端：

它的行为与 HTTP 传输层中的相应设置相同。

#### permit_without_stream

在标准 gRPC 客户端：

如果启用，客户端传输即使没有活动连接也会发送 keepalive ping。如果禁用，则在没有活动连接时，将忽略 `idle_timeout` 和 `ping_timeout`，并且不会发送 keepalive ping。

默认禁用。

### HTTPUpgrade

```json
{
  "type": "httpupgrade",
  "host": "",
  "path": "",
  "headers": {}
}
```

#### host

主机域名。

服务器将验证。

#### path

HTTP 请求路径

服务器将验证。

#### headers

HTTP 请求的额外标头。

如果设置，服务器将写入响应。
