---
icon: material/new-box
---

!!! question "自 sing-box 1.12.0 起"

### 结构

```json
{
  "type": "anytls",
  "tag": "anytls-in",

  ... // 监听字段

  "users": [
    {
      "name": "sekai",
      "password": "8JCsPssfgS8tiRwiMlhARg=="
    }
  ],
  "padding_scheme": [],
  "tls": {}
}
```

### 监听字段

参阅 [监听字段](/zh/configuration/shared/listen/)。

### 字段

#### users

==必填==

AnyTLS 用户。

#### padding_scheme

AnyTLS 填充方案行数组。

默认填充方案:

```json
[
  "stop=8",
  "0=30-30",
  "1=100-400",
  "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
  "3=9-9,500-1000",
  "4=500-1000",
  "5=500-1000",
  "6=500-1000",
  "7=500-1000"
]
```

#### tls

TLS 配置, 参阅 [TLS](/zh/configuration/shared/tls/#入站)。

#### web（ACP 扩展）

启用 TLS 时，可为普通浏览器访问配置固定响应或反向代理：

```json
{"type": "static", "content": "<h1>Welcome</h1>"}
```

```json
{"type": "proxy", "url": "https://www.example.com"}
```

固定响应保持所有路径返回配置内容。网站使用现有 TLS 端口，不额外监听 80。
网站访问不进入 AnyTLS 用户流量计费。

HTTP 响应采用 Apache 2.4 的 `ServerTokens Prod`、`ServerSignature Off`、
`TraceEnable Off` 风格：

- 网站响应包含单个 `Server: Apache`，不声明具体版本或操作系统。
- 固定响应的 ETag 使用十六进制的“字节数-微秒修改时间”；gzip 表示添加
  `-gzip` 后缀，使用 `Vary: Accept-Encoding`，不再强制缓存 300 秒。
  与 mod_deflate 一样，已知长度不超过 68 字节的响应不压缩。
- 支持 GET/HEAD/POST、条件请求、范围请求及 OPTIONS（包括 `OPTIONS *`）。
  固定响应的未知扩展方法返回 501，已知但不支持的方法返回 405。
- 本地生成的 405、412、416、501 和反代故障使用 Apache 风格 HTML 错误页。
  连接上游失败返回 503，等待上游响应超时返回 504，其他网关故障返回 502。
  HEAD 错误响应不发送正文；416 和 HEAD 417 按 Apache 的行为省略长度头。
- 反代统一 Server 头，移除本站不支持的 Alt-Svc；保留上游应用的状态、正文、
  Cookie、缓存语义和其他应用头。TRACE 和 CONNECT 不转发。
- HTTP/1 按 Apache 风格输出头顺序、`ETag` 大小写和状态行；Go 在进入
  Handler 前生成的常见解析错误也转换成 HTML，不暴露原来的纯文本原因后缀。
  请求行及单个请求头限制为 8190 字节，请求头最多 100 个；HTTP/1 空闲超时
  5 秒、每连接最多 100 个请求，显式请求 keep-alive 时才发送 Keep-Alive 头。
- HTTP/2 实际引擎设置为 100 个并发流、16384 字节最大帧、65535 字节流窗口、
  4096 字节头压缩表；只省略等于协议默认值及建议性头大小限制的初始 SETTINGS。
  初始连接窗口增量为 2147418112，与 Docker 中的 Apache 2.4.69 对照验证。
- HTTP/1 连接里格式完整且可解析的 `HTTP/2.0`、`HTTP/3.0` 文本请求行按
  HTTP/1.1 处理，与 Apache 的版本探测响应一致；这不代表提供 QUIC/HTTP/3。
  适配器只改版本标记，沿用 Go 请求解析确定正文边界，正文及 trailers 原样通过。
  真正的 HTTP/2 由 ALPN 协商，绕过此适配器，HTTP/2 前言也不会被改写。
- 417 回显经过 HTML 转义的 Expect 值，包括重复字段；416 不发送 Content-Range
  或 Content-Length，关闭连接时以 EOF 定界，持久 HTTP/1 使用 chunked，HTTP/2
  使用 END_STREAM。上游应用自己的 416 正文及范围元数据仍予保留。

这不是 Apache httpd 的完整替代实现。TLS 握手、HTTP/2 后续帧调度/HPACK、
压缩后的具体字节及请求解析仍使用 Go。版本适配只针对上述两种合法结构的文本
探测；其他异常版本、解析失败或无效正文定界继续由 Go 拒绝。
网站通过 ALPN 协商 HTTP/2，不声明 `Upgrade: h2`；SNI/Host 虚拟主机策略、
超时边界和畸形请求的所有组合没有完全复刻。固定内容的全路径响应也不等价于
Apache 的默认文件目录。
自签名证书、上游页面内容和应用头也可能提供额外特征，不能据此保证不可识别。

可复现的本地对照见 `common/webserver/testdata/apache/README.md`；测试会明确
区分匹配的响应与已知差异，不把 HTTP 外观接近当作完整指纹一致。

参考：[Apache 核心配置](https://httpd.apache.org/docs/2.4/mod/core.html)、
[mod_deflate](https://httpd.apache.org/docs/2.4/mod/mod_deflate.html)。
