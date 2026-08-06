# sing-box-acp

`sing-box-acp` 是为 ACP 节点运行时维护的 sing-box 定制分支，重点解决代理入站用户在运行期间更新、凭据轮换和会话撤销的问题。

本项目不是 SagerNet 官方发行版，也不代表或隶属于 SagerNet。仓库保留原项目的 Go 模块路径，以便 ACP 现有代码继续使用 `github.com/sagernet/sing-box` 包。

## 当前基线

| 组件 | 基线 |
| --- | --- |
| sing-box | `v1.13.16` |
| sing-quic | `d83826c306d7` |
| Go | `1.24.7` 或更高兼容版本 |

`go.mod` 使用本地替换，将 `github.com/sagernet/sing-quic` 指向 [`third_party/sing-quic-acp`](third_party/sing-quic-acp)。构建时不能删除该目录或移除对应的 `replace` 规则，否则 Hysteria2 的定向会话撤销能力会丢失。

## ACP 定制能力

### 无重启用户热更新

以下入站可以在监听器持续运行时替换认证用户：

| 协议 | 用户更新 | 按用户踢下线 | 撤销范围 |
| --- | --- | --- | --- |
| Trojan | `UpdateUsers` | `CloseUserSessions` | 认证完成但尚未交给路由器的连接 |
| VLESS | `UpdateUsers` | `CloseUserSessions` | 认证完成但尚未交给路由器的连接 |
| Hysteria2 | `UpdateUsers` | `CloseUserSessions` | 已认证的完整 QUIC 会话 |

更新过程使用不可变认证快照：先完整构建并校验新用户表，再通过一次原子操作发布。无效的用户列表不会覆盖正在使用的认证数据，并发握手不会观察到半更新状态。

Trojan 和 VLESS 会为用户身份绑定凭据指纹。删除用户、修改密码或修改 VLESS Flow 后，旧身份无法继续通过交接窗口。已经由路由器交给流量跟踪器的连接应由 ACP 上层控制器关闭。

Hysteria2 的认证和会话索引位于定制的 `sing-quic-acp` 中。更新用户表时，仅关闭被删除或凭据发生变化的用户会话；用户排序变化或新增其他用户不会中断仍然有效的连接。

### 运行时入站管理

入站管理器支持在进程运行期间创建、替换和删除入站。替换同名入站时会先启动新实例，再关闭旧实例，降低配置切换对服务可用性的影响。

### 连接生命周期保护

ACP 定制覆盖认证、路由交接和 QUIC 关闭过程中的竞态，包括：

- 更新发布期间仍在进行的握手；
- 用户凭据轮换后的旧连接；
- QUIC 主连接关闭后的 UDP 子会话清理；
- 重复、无效用户数据导致的更新回滚；
- 并发用户更新与认证检查。

## 使用边界

本分支没有新增 sing-box 配置字段。配置解析、命令行参数和常规代理行为继承自当前基线版本；ACP 功能通过 Go 运行时接口由节点控制层调用。

如果只把本项目当作普通 sing-box 可执行文件运行，现有配置仍可使用，但用户热更新和定向踢下线需要控制层主动调用对应入站方法。

## 构建

克隆仓库后，在根目录执行：

```bash
go build -trimpath ./cmd/sing-box
```

使用仓库默认功能标签构建：

```bash
make build
```

常用命令：

```bash
./sing-box version
./sing-box check -c config.json
./sing-box run -c config.json
```

Windows 下生成的程序名通常为 `sing-box.exe`。

## 测试

先运行 ACP 重点测试：

```bash
go test ./adapter/inbound ./protocol/hysteria2 ./protocol/trojan ./protocol/vless
go -C third_party/sing-quic-acp test ./...
```

再运行主模块完整测试：

```bash
go test ./...
```

`dns/transport/hosts` 的测试会读取操作系统 hosts 文件，并要求其中存在有效的 `localhost` 映射；精简过的 Windows hosts 文件可能导致该环境测试失败。

## 目录说明

```text
adapter/inbound/                 运行时入站创建、替换和删除
protocol/trojan/                 Trojan 认证快照与交接窗口撤销
protocol/vless/                  VLESS 认证快照与交接窗口撤销
protocol/hysteria2/              Hysteria2 用户更新入口
third_party/sing-quic-acp/       QUIC 会话索引、定向撤销及相关测试
```

## 与上游同步

- `upstream` 指向 `https://github.com/SagerNet/sing-box.git`；
- `origin` 指向 ACP 维护仓库；
- 升级 sing-box 基线时，同时核对其要求的 sing-quic 版本；
- 先移植上游 sing-quic 变化，再重新应用并测试 ACP 会话撤销逻辑；
- 不直接编辑生成文件或用上游模块覆盖 `third_party/sing-quic-acp`。

## 许可证

本项目基于 sing-box，并继续遵循仓库 [`LICENSE`](LICENSE) 中的许可与附加条款。`third_party/sing-quic-acp` 保留其上游许可证，详见该目录内的 `LICENSE` 和 `ACP_CHANGES.md`。
