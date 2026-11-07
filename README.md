# dsh-lan-peers

局域网内 DSH 节点互相发现、**一次性配对**、然后互发**加密**文本消息的插件。每个装了它的 DSH 实例都会在局域网里自动广播自己、维护一份对端表；agent 通过 5 个工具就能看到对端、配对、发消息、收消息。

零外部依赖（只用 `node:dgram` / `node:http` / `node:crypto`），不依赖任何云端服务。

> 跨互联网（不同网络、NAT 后、没有公网 IP）请用姊妹插件 [`dsh-wan-peers`](../dsh-wan-peers)。两个是**独立插件**，可以同时装，互不影响。

## 版本 0.3.0 的变化（重要）

- **默认开启安全信道**：发现仍然开放（任何人能看到节点名），但**未配对的对端不能发消息**，明文端点一律返回 `426`。
- 新增 `lan_pair` 工具与 `POST /lan/v2/pair/start`：6 位一次性配对码，10 分钟有效、只存哈希、单次使用、每分钟最多尝试 5 次。
- 配对用 **X25519 ECDH** 协商共享密钥，密钥**从不传输**；之后每条消息 **AES-256-GCM 加密** 并带 **HMAC-SHA256 签名**（含时间戳 ±60 秒与 nonce 防重放）。
- 想回到旧的明文行为：`config: { secure: false }`（仅限完全可信的内网）。

## 配对：A 发现 B 之后怎么配上

配对只需要**一次人工交换**，之后两台机器自动记住彼此。

1. **B 侧生成码**（在 B 的会话里让 agent 执行，或直接调用工具）：

   ```
   lan_pair action=show
   → pairing code 481920 (valid until 2026-11-07T06:30:00.000Z)
   ```

2. **A 侧导入**（`peer` 可以写 B 的节点名、id 或局域网 IP）：

   ```
   lan_pair action=import peer=LMM code=481920
   → paired with LMM; lan_send now works over the encrypted channel
   ```

3. 握手过程（自动完成，人工只做上面两步）：

   ```
   A → B  POST /lan/v2/pair/start   { v:2, from, fromName, httpPort, code, pk }
   B 校验码（单次 + 限速）→ 生成临时密钥对 → shared = ECDH(skB, pkA)
   B → A  { ok, from, name, httpPort, pk, proof = HMAC(proofKey, "pair|B|A|pkB|pkA") }
   A       shared = ECDH(skA, pkB) → 用同一个 proofKey 校验 proof
   双方各自落盘 peers.d/<peerId>.json（权限 0600）
   ```

4. 之后 A 调 `lan_send peer=B text=...`：请求头带 `X-Lan-From / X-Lan-Ts / X-Lan-Nonce / X-Lan-Sig`，签名串为 `METHOD\nPATH\nTS\nNONCE\nsha256(body)`，载荷用 `msgKey` 加密（AAD = `from|to|path`）。B 收下解密后写进收件箱。

几个要点：

- 码在哪里「显示」取决于你想让谁发起：谁拿到码谁就调 `action=import`。**两边都配对一次也可以**（各自 show 一次），互不冲突。
- `lan_pair action=list` 看已配对的对端；`action=forget peer=X` 删掉单个密钥；`action=reset` 清空全部（之后都要重新配对）。
- 配对信息落盘在 `~/.dsh/lan-peers/peers.d/`，重启后仍然有效，不需要重新配对。
- 如果对端换了 IP：发现会更新它的地址，密钥不受影响；密钥是**按节点 id**绑定的，不是按 IP。

## 工作原理

- **发现**：UDP 广播（默认端口 `48901`），每 7 秒向本机各网卡的广播地址 + `255.255.255.255` 发一个 JSON announce：
  `{ v, kind:'announce', id, name, version, httpPort, secure, pairing, ts }`。
  收到陌生对端的 announce 会立刻回一个，双向确认。30 秒没消息就算离线。发现是**开放**的，用来让人类知道有哪些节点、谁正在展示配对码。
- **投递**：每个实例自建 HTTP 服务，监听 `0.0.0.0:48902`（DSH 自带的 webServer 只绑 127.0.0.1，局域网内不可达，所以另起一个）：
  - `GET  /lan/v2/hello` — 自身信息（`secure: true`、当前是否有配对码）
  - `POST /lan/v2/pair/start` — 配对握手（唯一无需签名的写端点）
  - `POST /lan/v2/message` — 加密消息（需签名）
  - `GET  /lan/hello`、`POST /lan/message`、`GET /lan/messages?limit=N`、`POST /lan/ack` — **仅在 `secure: false` 时可用**，否则返回 426
- **落盘**：状态目录默认 `~/.dsh/lan-peers`（可用环境变量 `DSH_LAN_PEERS_HOME` 覆盖），里面是
  `identity.json`（本机 id，持久）、`peers.json`、`peers.d/*.json`（配对密钥，0600）、`inbox.jsonl`（明文消息）、`status.json`、`boot.log`、`lan-peers.log`。

## Agent 工具

| 工具 | 作用 |
| --- | --- |
| `lan_peers` | 列出局域网内所有对端（在线/离线、名字、IP:端口、是否已配对） |
| `lan_pair` | `show` 出配对码 / `import` 导入对方的码 / `list` / `forget` / `reset` |
| `lan_send` | 给已配对的对端发加密文本，`peer` 支持 id、名字、IP 或名字片段 |
| `lan_inbox` | 拉收件箱（`limit`、`mark_read`） |
| `lan_ping` | 立刻广播一次并探测所有对端（探测的是 `/lan/v2/hello`，不会往对方收件箱塞消息） |

## 安装

```powershell
# 从 GitHub 直接装（推荐）
dsh plugin --profile desktop add github:Myco-Lee/dsh-lan-peers

# 本地开发目录（可随时改代码，改配置行即可热重载）
dsh plugin --profile desktop add "link:D:\99-DP-D\01-代码项目\dsh-lan-peers"

# 或者用 npm pack 打成 tgz，再装文件
npm pack .
dsh plugin --profile desktop add "file:D:\99-DP-D\01-代码项目\dsh-lan-peers\dsh-lan-peers-0.3.0.tgz"
```

装完重启一次 DSH。检查是否生效：

```powershell
Get-NetTCPConnection -State Listen -LocalPort 48902   # 应看到 0.0.0.0:48902
Get-Content ~\.dsh\lan-peers\boot.log -Tail 5        # 应看到 runtime started / tools registered
Get-Content ~\.dsh\lan-peers\status.json             # 应看到 "secure": true、"tools": [...]
```

## 跨机器验证

```powershell
# 在 A 上探测 B（只读，不需要配对）
(Invoke-WebRequest http://<B的IP>:48902/lan/v2/hello -UseBasicParsing).Content
```

返回 `{"ok":true,...,"secure":true,"peers":1}` 说明 B 能看到 A。若不通，先查 B 的 Windows 防火墙：
这台机器上曾经存在名为 `DeepSeek Harness` 的**入站阻止规则**（Public 配置），会让 48902 从外面连不进来（Windows 上 Block 优先于 Allow）。处理方式：

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
    name: LMM-1                 # 不填取 hostname
    maxTextChars: 8000
    maxInbox: 500
    secure: true                # 默认 true；false 才允许明文端点
    pairingCodeLength: 6        # 4..12
    pairingCodeTtlMs: 600000    # 码有效期，默认 10 分钟
    maxPairAttemptsPerMinute: 5 # 每个来源 IP 每分钟最多试错次数
    clockSkewMs: 60000          # 允许的时钟偏差，超过则拒绝签名请求
```

## 测试

```powershell
node test\crypto.test.mjs    # ECDH/HKDF/AES-GCM/签名 的单元测试
node test\pairing.test.mjs   # 配对码单次/过期/限速 + 密钥库读写
node test\smoke.mjs          # 假 ctx + 两个 mock 节点：发现→配对→加密双向通信→未配对被拒
node test\live-probe.mjs     # 对运行中的宿主做真实探测（需要宿主里已加载插件）
```

## 安全边界

- **发现是开放的**：同一广播域内任何人都能看到你的节点名、端口、是否已配对。这是设计取舍（没有它就无法零配置发现）。
- **通信需要配对**：未配对的对端调用 `/lan/v2/message` 会被拒绝（401），明文端点在 `secure: true` 时返回 426。
- 保护范围：传输中加密（AES-256-GCM）、请求认证与防重放（HMAC + 时间戳 + nonce）、配对码单次 + 限速 + 只存哈希。
- **不在保护范围内**：消息正文在 `inbox.jsonl` 里是明文（本机磁盘）；`identity.json` 是可读的节点 id；对端可以拒收但无法阻止你发。
- 密钥文件权限 0600（Windows 上依赖目录 ACL，不保证严格）。不要把 `~/.dsh/lan-peers` 同步到别处。
- 别把 48902 暴露到公网；跨网段/公网请用 `dsh-wan-peers`（会合服务 + E2E 加密）。

## 兼容性

- 已在 DSH 0.2.2-rc.1（cordis 4.1.0）与 0.2.1-rc.5（cordis 4.0.5）上验证。
- 插件用 `export default { name, apply }` 导出，同时保留具名导出，两种宿主都能识别。
- 不声明 `inject`，apply 里自行按需等 `tools` 服务（旧版 cordis 在未 inject 时读 `ctx.tools` 会直接抛错，所以探测都包在 try/catch 里），宿主启动早期就能起服务，工具随后补齐。
- **升级注意**：0.2.x ↔ 0.3.0 不互通（0.2.x 只会说明文 v1）。两台机器都要升到 0.3.0，或者都设 `secure: false`。

## License

MIT
