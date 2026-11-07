# dsh-lan-peers

局域网内 DSH 节点互相发现 + 互发文本消息的最小插件。每个装了它的 DSH 实例都会在局域网里自动广播自己、维护一份对端表；agent 通过 4 个工具就能看到对端、发消息、收消息。

零外部依赖（只用 `node:dgram` / `node:http`），不依赖任何云端服务。

> 跨互联网（不同网络、NAT 后、没有公网 IP）请用姊妹插件 [`dsh-wan-peers`](../dsh-wan-peers)。两个是**独立插件**，可以同时装，互不影响。

## 工作原理

- **发现**：UDP 广播（默认端口 `48901`），每 7 秒向本机各网卡的广播地址 + `255.255.255.255` 发一个 JSON announce：
  `{ v, kind:'announce', id, name, version, httpPort, address, tools, ts }`。
  收到陌生对端的 announce 会立刻回一个，双向确认。30 秒没消息就算离线。
- **投递**：每个实例自建 HTTP 服务，监听 `0.0.0.0:48902`（DSH 自带的 webServer 只绑 127.0.0.1，局域网内不可达，所以另起一个）：
  - `GET  /lan/hello` — 自身信息
  - `POST /lan/message` — 收消息 `{ from, fromName, version, httpPort, text }`
  - `GET  /lan/messages?limit=N` — 拉收件箱
  - `POST /lan/ack` — `{ ids: [...] }` 标记已读
- **落盘**：状态目录默认 `~/.dsh/lan-peers`（可用环境变量 `DSH_LAN_PEERS_HOME` 覆盖），里面是
  `identity.json`（本机 id，持久）、`peers.json`、`inbox.jsonl`、`status.json`、`boot.log`、`lan-peers.log`。

## Agent 工具

| 工具 | 作用 |
| --- | --- |
| `lan_peers` | 列出局域网内所有对端（在线/离线、名字、IP:端口） |
| `lan_send` | 给某个对端发文本，`peer` 支持 id、名字、IP 或名字片段 |
| `lan_inbox` | 拉收件箱（`limit`、`mark_read`） |
| `lan_ping` | 立刻广播一次并探测所有对端 |

## 安装

```powershell
# 本地开发目录（推荐，可随时改代码）
dsh plugin --profile desktop add "link:D:\99-DP-D\01-代码项目\dsh-lan-peers"

# 或者先用 npm pack 打成 tgz，再装文件
npm pack .
dsh plugin --profile desktop add "file:D:\99-DP-D\01-代码项目\dsh-lan-peers\dsh-lan-peers-0.2.0.tgz"
```

装完重启一次 DSH。检查是否生效：

```powershell
Get-NetTCPConnection -State Listen -LocalPort 48902   # 应看到 0.0.0.0:48902
Get-Content ~\.dsh\lan-peers\boot.log -Tail 5        # 应看到 runtime started / tools registered
```

## 跨机器验证

```powershell
# 在 A 上
(Invoke-WebRequest http://<B的IP>:48902/lan/hello -UseBasicParsing).Content
```

返回 `{"ok":true,...,"peers":1}` 说明 B 能看到 A。若不通，先查 B 的 Windows 防火墙：
这台机器上曾经存在名为 `DeepSeek Harness` 的**入站阻止规则**（Public 配置），会让 48902 从外面连不进来。处理方式：

```powershell
Get-NetFirewallRule -Direction Inbound | Where-Object { $_.Action -eq 'Block' -and $_.DisplayName -like '*DeepSeek*' } | Disable-NetFirewallRule
New-NetFirewallRule -DisplayName 'DSH LAN peers TCP' -Direction Inbound -Protocol TCP -LocalPort 48902 -Action Allow -Profile Any
New-NetFirewallRule -DisplayName 'DSH LAN peers UDP' -Direction Inbound -Protocol UDP -LocalPort 48901 -Action Allow -Profile Any
```

## 配置（可选）

在 profile 补丁层写 `config:`，也可以不写用默认值：

```yaml
- id: dsh-lan-peers
  name: dsh-lan-peers
  config:
    discoveryPort: 48901
    httpPort: 48902
    intervalMs: 7000
    ttlMs: 30000
    name: LMM-1          # 不填取 hostname
    maxTextChars: 8000
    maxInbox: 500
```

## 测试

```powershell
node test\smoke.mjs        # 假 ctx + 两个 mock 对端，覆盖发现/发送/收件箱/已读/ping
node test\live-probe.mjs   # 对运行中的宿主做真实探测（需要宿主里已加载插件）
```

## 安全边界

- 明文 HTTP，**只适合可信内网**；不要把这个端口暴露到公网。
- 没有鉴权：同一广播域内任何装了本插件的机器都能给你发消息、也能看到你的节点名。
- 消息原文落盘在 `inbox.jsonl`，不在加密范围内。

## 兼容性

- 已在 DSH 0.2.2-rc.1（cordis 4.1.0）与 0.2.1-rc.5（cordis 4.0.5）上验证。
- 插件用 `export default { name, apply }` 导出，同时保留具名导出，两种宿主都能识别。
- 不声明 `inject`，apply 里自行按需等 `tools` 服务，所以宿主启动早期就能起服务，工具随后补齐。

## License

MIT
