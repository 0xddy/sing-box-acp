# 本地 Apache 指纹对照

生产节点仍使用 Go，不依赖 Apache 或 Docker。这里的 httpd 仅是测试参照，
绑定本机回环地址，不挂载项目目录、业务数据或生产证书。

已验证镜像：`httpd:2.4`，实际版本 Apache/2.4.69 (Unix)、OpenSSL/3.5.7，
镜像摘要 `sha256:a30cd4cd57f3f3c3be9b2d16384d2488839996bb14c67df2b51f1ecbb3e584a1`。
配置启用 TLS、HTTP/2、mod_deflate 和 FallbackResource，使用 ServerTokens Prod、
ServerSignature Off、TraceEnable Off。Allow 的方法顺序可能随 Apache 重启改变。

在此 Go 模块根目录运行（PowerShell；Docker Desktop 需要处于运行状态）：

```powershell
$apacheImage = 'httpd@sha256:a30cd4cd57f3f3c3be9b2d16384d2488839996bb14c67df2b51f1ecbb3e584a1'
$apacheName = 'acp-apache-reference-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
docker create --name $apacheName -p 127.0.0.1:0:443 --entrypoint sh $apacheImage -c 'openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/reference.key -out /tmp/reference.crt -days 2 -subj /CN=example.test >/dev/null 2>&1 && exec httpd-foreground'
docker cp common/webserver/testdata/apache/httpd.conf "${apacheName}:/usr/local/apache2/conf/httpd.conf"
docker cp common/webserver/testdata/apache/index.html "${apacheName}:/usr/local/apache2/htdocs/index.html"
docker start $apacheName
docker port $apacheName 443/tcp
# 将上一行的 127.0.0.1:端口填入下面的环境变量，等待 httpd 启动完成后执行。
$env:ACP_APACHE_REFERENCE_ADDR = '127.0.0.1:实际端口'
go test -tags with_utls ./common/webserver -run '^TestApacheReference$' -v -count=1
# 完成后清理本次创建的参照容器；镜像保留供下次使用。
docker rm -f $apacheName
Remove-Item Env:ACP_APACHE_REFERENCE_ADDR
```

对照测试只接受 loopback IP，忽略自签名证书验证。两端均无 SNI，以相同的默认
虚拟主机方式比较；Apache 对“带 SNI 却无 Host”的请求有额外拒绝策略，未复刻。

HTTP/1 对照发送 29 种请求，包括 GET/HEAD/POST/OPTIONS/TRACE、未知方法、
HTTP 版本探测、Host 和请求头错误、URL 转义错误、范围请求、长度和数量限制、
不支持的 Transfer-Encoding 与 Expect（含 HEAD、HTML 转义、重复字段和混合值）。

比较保留状态行、响应头顺序与大小写、正文，仅作以下明确处理：

- 日期必须能正确解析；文件 mtime 不同，比较 ETag 的 size-mtime 格式。
- Allow 按集合比较，避免 APR 的哈希遍历顺序导致重启后偶发失败。
- Apache 即使关闭 H2Upgrade 仍声明 Upgrade: h2。Go 仅通过 ALPN 协商，
  因此单独排除 Upgrade 和 Connection 的位置/Upgrade token；两端都必须关闭连接。

29 种请求均在上述通用归一化后断言一致，不再为以前的 4 项差异设置豁免：

- HTTP/1 连接里的文本 `HTTP/2.0`、`HTTP/3.0` 请求行，经完整头部的 Go 解析
  验证后只把版本标记改为 HTTP/1.1，再走正常网站/反代流程。不是直接把 505
  改成 200；Host、Content-Length、Transfer-Encoding 和正文验证继续生效。
- 417 按 Apache 的 HTML 转义规则回显 Expect 值；HEAD 不发正文或长度头。
- 本地 416 不带 Content-Length/Content-Range；关闭连接用 EOF，持久 HTTP/1
  用 chunked，HTTP/2 用 END_STREAM。不会改写反代上游自己的 416 应用响应。

另外 8 项对照分别在真实 HTTP/1.1 和 HTTP/2 上验证 GET/HEAD 的 416、417
状态、正文、长度、传输定界和内容类型。
HTTP/2 直接比较初始 SETTINGS（仅 MAX_CONCURRENT_STREAMS=100）及连接级
WINDOW_UPDATE（2147418112），不声称后续帧时序、HPACK 或 TLS 握手一致。
总计 38 个对照子测试；仍有上面明确排除的 Upgrade/Connection 差异，不能把
“以前的 4 项已修复”理解成所有网络层行为都相同。

普通单元测试无需 Docker：

```powershell
go test -tags with_utls ./common/webcontent ./common/webserver ./protocol/anytls
```

这些测试还验证真实连接上的 HEAD/GET 流水线、100 次请求关闭、分片写入、
103 Early Hints、SSE 实时刷新、chunk trailers、101 升级后的双向二进制传输，
以及 HTTP/2 多次 500000 字节请求/响应，检查窗口配置是否导致死锁或数据损坏。
AnyTLS 测试继续覆盖认证、撤销和网站访问不计入用户流量。

请求适配还验证 100-continue、固定长度/分块 POST、正文中含完整 HTTP 请求行、
单字节分片、带正文的流水线请求、只有下个请求首字节已到达、重复长度拒绝、
错误 chunk 定界和 HTTP/2 前言不改写。可独立运行正文隔离模糊测试：

```powershell
go test -tags with_utls ./common/webserver -run '^$' -fuzz '^FuzzRequestProfileBodyIsolation$' -fuzztime=10s -parallel=2
```

边界：此测试不覆盖所有请求组合、TLS/OpenSSL 服务端指纹、HTTP/2 后续调度、
压缩字节、TCP 行为或时序；不能用通过率推导“不可被识别”。
