# AVE keyless Wallet — SSS 技术方案

---

## 一、方案定位与技术选型背景

### 1.1 当前行业痛点

| 钱包类型 | 痛点 |
|---------|------|
| Bot 钱包（单私钥加密托管） | 钱包服务单点风险，KMS单点账户风险 |
| EOA 本地钱包 | 私钥/助记词难备份，丢失即永久失去资产 |
| Smart Account (4337) | 土狗/Meme/anti-bot token 兼容性差，合约钱包被合约检测拦截 |

**新方向：Keyless 分片钱包（SSS + 设备 TEE）**

### 1.2 为什么不用 EIP-4337 / EIP-7702

| 方案 | 问题 |
|------|------|
| ERC-4337 | tx.origin != msg.sender，无法通过 bot 检测；isContract() 会被标记；Gas 更高 |
| EIP-7702 | 用户不信任"把钱包控制权交给合约"；目前 Ethereum 仍在推进，尚未成熟 |

**结论：维持 EOA 兼容性，使用 SSS + TEE 方案实现无私钥体验。**

### 1.3 竞品分析

| 平台 | 技术判断 | 依据 |
|------|---------|------|
| Binance Web3 Wallet | SSS（2-of-3） | 支持私钥导出 + 毫秒级签名，明确不是 TSS |
| OKX Web3 Wallet | SSS（2-of-3） | 同上 |
| Bitget Wallet | 曾用 TSS（GG20） | 2023 年因性能/兼容性问题关闭无私钥功能 |

**行业共识：S1 存服务端（仅备份），S2+S3 在用户设备（本地签名）；Agent 签名 = 用户托管一份分片给服务端 TEE。**

### 1.4 TSS vs SSS 对比

| 维度 | TSS (GG20/GG18) | SSS + TEE（本方案） |
|------|----------------|-------------------|
| 签名时私钥是否聚合 | 永不聚合 | 设备 TEE 内短暂聚合后立即销毁 |
| Keygen 性能 | 桌面 ~5s，手机 1–5 min | 毫秒级 |
| 签名性能 | 桌面 ~1s，手机 2–15s | 毫秒级 |
| 多链支持 | 需按曲线分别实现 | 天然支持（私钥通用） |
| BTC Taproot | 不支持 | 支持（标准私钥） |
| 工程复杂度 | 高（Relay Server、状态机、gomobile） | 低 |
| 导入/导出助记词 | 不支持 | 支持 |
| 安全信任根 | 无需信任任何单一方 | 信任设备 TEE + 服务端 Nitro Enclave（PCR 绑定代码度量）|

**结论：SSS + TEE 在性能、兼容性、工程复杂度上全面优于 TSS，满足当前 AI Agent 钱包场景。**

---

## 二、整体架构

### 2.1 模块架构图

```
╔════════════════════════════════════════════════════════╗   ╔══════════════════════════════╗
║                       客户端层                          ║   ║    三方 Cloud（用户私有）     ║
║                                                        ║   ║                              ║
║  ┌──────────────────────────────────────────────────┐  ║   ║  ┌──────────┐ ┌───────────┐  ║
║  │              Android / iOS App                   │  ║   ║  │  iCloud  │ │  G Drive  │  ║
║  │                                                  │  ║   ║  └──────────┘ └───────────┘  ║
║  │  ┌────────────────────────────────────────────┐  │  ║   ║  PIN 加密的 Share B 备份      ║
║  │  │             Device TEE                     │  │  ║   ║  用户自管，平台不可访问       ║
║  │  │  StrongBox (Android) / Secure Enclave      │  │  ║   ╚══════════════════════════════╝
║  │  │  - Share A（SSS 分片，x=1 或 x=n）         │  │  ║            ↑ ④ OS API
║  │  │  - 各链派生私钥（BIP44，只读签名用）        │  │  ║        上传 / 下载
║  │  └────────────────────────────────────────────┘  │  ║
║  │                                                  │  ║
║  │  本地能力模块：                                  │  ║
║  │  ・SSS 分片 / Lagrange 合并运算                  │  ║
║  │  ・ECDH 密钥协商 / AES-256-GCM 加解密           │  ║
║  │  ・Passkey / FaceID / TouchID 认证              │  ║
║  │  ・本地直签（从 TEE 取派生私钥，毫秒级）         │  ║
║  └──────────────────────────────────────────────────┘  ║
╚════════════════════════════════════════════════════════╝
        │                    │                    │
        │ ① 账号 / 钱包       │ ② Agent交易          │ ③ Share B
        │   业务 HTTPS        │   结果 HTTPS        │   上传/下载
        ▼                    ▼                    ▼
╔═══════════════════════════════════════╗   ╔══════════════════════╗
║             后端服务层                 ║   ║     平台云服务         ║
║                                       ║   ║   （AWS 独立账号 B）   ║
║  ┌─────────────────┐ ┌─────────────┐  ║   ║                      ║
║  │   用户服务       │ │   交易服务   │  ║   ║  ┌────────────────┐  ║
║  │  (User Service) │ │ (Tx Service)│  ║   ║  │  宿主服务进程   │  ║
║  │                 │ │             │  ║   ║  │                │  ║
║  │ - AVE 账号登录  │ │ - AI Agent  │  ║   ║  │ App 接口：     │  ║
║  │ - Passkey/2FA   │ │   订单接收  │  ║   ║  │ - AVE Token 验证│  ║
║  │ - 钱包业务前置  │ │ - 风控预检  │  ║   ║  │ - Master Key 签│  ║
║  │   校验          │ │ - 调钱包服  │  ║   ║  │   名校验        │  ║
║  │ - 钱包操作记录  │ │   务签名    │  ║   ║  │ - 2FA（下载）   │  ║
║  │ - 限频 / 审计   │ │ - 交易广播  │  ║   ║  │ - 限频/审计日志│  ║
║  └────────┬────────┘ └──────┬──────┘  ║   ║  │                │  ║
║           │ ⑤ 钱包操作      │ ⑥ 签名   ║   ║  Wallet Enclave  │  ║
║           │   (内网 RPC)    │   请求   ║   ║  接口：           │  ║
╚═══════════│═════════════════│══════════╝   ║  │ - PrivateLink  │  ║
            │                │             ║  │   来源校验     │  ║
            ▼                ▼             ║  │ - NSM Attest.  │  ║
╔═══════════════════════════════════════╗   ║  │   PCR 白名单   │  ║
║         钱包服务（AWS 账号 A）         ║   ║  │ - credit_id 校 │  ║
║                                       ║   ║  │   验           │  ║
║  ┌─────────────────────────────────┐  ║   ║  │ - KMS 加解密   │  ║
║  │       Wallet Service 宿主进程    │  ║   ║  │   Share B      │  ║
║  │                                 │  ║   ║  └────────────────┘  ║
║  │  ┌───────────────────────────┐  │  ║   ║                      ║
║  │  │  API 接入层               │  │  ║   ║  ┌────────────────┐  ║
║  │  │  - User Svc / Tx Svc 路由 │  │  ║   ║  │  AWS KMS       │  ║
║  │  └───────────────────────────┘  │  ║   ║  │  (账号 B)      │  ║
║  │                                 │  ║   ║  │  Share B       │  ║
║  │  ┌───────────────────────────┐  │  ║   ║  │  加密存储      │  ║
║  │  │  风控模块（进程内 lib）    │  │  ║   ║  └────────────────┘  ║
║  │  │  - 通用限频 / 防篡改      │  │  ║   ╚══════════════════════╝
║  │  │  - Session 校验 / 防重放  │  │  ║          ↑
║  │  │  - 签发 ApprovedToken     │  │  ║          │ ⑦ TLS（经宿主 TCP relay）
║  │  └───────────────────────────┘  │  ║          │   AWS PrivateLink 私网
║  │                                 │  ║          │
║  │  ┌───────────────────────────┐  │  ║          │
║  │  │  vsock IPC + TCP relay    │  │  ║          │
║  │  │  （哑代理，不终止 TLS）   │  │  ║          │
║  │  └───────────────────────────┘  │  ║          │
║  └──────────────┬──────────────────┘  ║          │
║                 │ vsock               ║          │
║  ┌──────────────▼──────────────────┐  ║          │
║  │      Nitro Enclave（签名 TEE）  │  ║          │
║  │                                 │  ║          │
║  │  ① 验证 ApprovedToken           │  ║          │
║  │  ② TLS ──TCP relay──PrivateLink─╫──╫──────────┘
║  │     → 平台云取 Share B          │  ║
║  │     （附 NSM Attestation）      │  ║
║  │  ③ KMS API（PCR 绑定）          │  ║
║  │     → 取 Share C                │  ║
║  │  ④ Lagrange(B,C) → Master Seed │  ║
║  │  ⑤ BIP44 派生目标链私钥         │  ║
║  │  ⑥ 签名交易                     │  ║
║  │  ⑦ memzero 全部密钥材料         │  ║
║  │  ← 私钥全程不出此内存边界 →     │  ║
║  └──────────────┬──────────────────┘  ║
║                 │ KMS API（PCR 绑定） ║
║  ┌──────────────▼──────────────────┐  ║
║  │       AWS KMS（账号 A）         │  ║
║  │       Share C 加密存储          │  ║
║  └─────────────────────────────────┘  ║
╚═══════════════════════════════════════╝
```

**模块交互索引：**

| 编号 | 交互方向 | 内容 | 协议 / 通道 |
|------|---------|------|-----------|
| ① | App → 用户服务 | 登录、2FA、钱包业务操作（创建/恢复/导出）| HTTPS |
| ② | App → 交易服务 | Agent 授权开通、Agent交易订单提交，交易状态查询 | HTTPS |
| ③ | App ↔ 平台云 | Share B 备份上传（钱包创建）/ 下载（恢复）| HTTPS |
| ③' | App → 钱包服务 → 平台云 | Share B 上传（Agent 激活）：App 提交至钱包服务，钱包服务校验 master_sig / credit_json 后转存平台云 | HTTPS + 内网 |
| ④ | App ↔ 三方 Cloud | Share B 备份（PIN加密）/ 恢复下载 | OS API |
| ⑤ | 用户服务 → 钱包服务 | 通过业务前置校验后的钱包操作（创建/恢复/Share C写入）| 内网 RPC |
| ⑥ | 交易服务 → 钱包服务 | Agent 签名请求（附 credit_id + 交易数据）| 内网 RPC |
| ⑦ | Wallet Enclave → 平台云 | 签名时取 Share B（附 NSM Attestation）| TLS over PrivateLink |
| ⑧ | Wallet Enclave → KMS(A) | 取 Share C（PCR 绑定 key policy）| KMS API via vsock |

### 2.2 各模块职责简述

**App（Android / iOS）**
本地完成 BIP39 助记词生成与 SSS 分片。Device TEE（StrongBox / Secure Enclave）持久化存储 Share A 和 BIP44 派生私钥，日常签名直接从 TEE 读取私钥，毫秒级完成，无需网络。Passkey / FaceID / TouchID 负责身份认证，ECDH 负责分片传输加密。

**三方 Cloud（iCloud / Google Drive）**
存储用户 PIN 加密的 Share B 备份，平台完全不可访问。作为钱包恢复的辅助渠道，适用于设备丢失或 Share A 损坏场景。

**用户服务（User Service）**
AVE 账号体系的统一入口：登录、Passkey / 2FA 验证、Session 管理。执行钱包操作的业务前置校验（身份合法性、频率限制、钱包归属），记录钱包操作审计日志，之后将密钥相关请求转发至钱包服务。

**交易服务（Transaction Service）**
接收 AI Agent 的交易请求，完成订单层面的风控预检和 Session Credit 校验，调用钱包服务签名，最终广播已签名交易上链。

**钱包服务（Wallet Service，AWS 账号 A）**
宿主进程内嵌风控模块（进程内 lib），负责 API 接入、请求鉴权、限频、ApprovedToken 签发及 vsock 哑代理。
Nitro Enclave 承担签名热路径：B + C → Lagrange → Master Seed → BIP44 → 私钥 → 签名 → memzero，私钥全程不出 Enclave 内存，宿主即使被完全入侵也无法读取密钥材料。
Share C 由 AWS KMS（账号 A）加密存储，key policy 绑定 Enclave PCR，仅当前镜像可解密。

**平台云服务（Platform Cloud，AWS 账号 B）**
独立 AWS 账号，与钱包服务账号完全隔离。宿主进程对外暴露两类接口：App 接口（Share B 上传/下载，含身份认证和限频）和 Wallet Enclave 接口（验证 NSM Attestation PCR，通过 PrivateLink 私网返回 Share B）。Share B 由本账号 AWS KMS 加密存储，单独泄露无法还原私钥。

**关键安全边界：**

```
╔══════════════════════════════════════════════════════╗
║               Share B / Share C 分离存储              ║
║  账号 B 仅有 Share B → 单片，无法还原私钥             ║
║  账号 A 仅有 Share C → 单片，无法还原私钥             ║
║  两片在 Nitro Enclave 内存中短暂汇合 → 签名后立即销毁  ║
║  宿主进程永远接触不到汇合后的 Master Seed 或私钥       ║
╚══════════════════════════════════════════════════════╝
```

> 各流程的详细步骤见对应章节：钱包创建（§六）、钱包恢复（§七）、Agent 签名（§十）、钱包删除（§7.5）。

---

## 三、密钥体系

### 3.1 助记词与分片

| 属性 | 说明 |
|------|------|
| 类型 | BIP39 助记词（128 或 256 bit 熵，对应 12 / 24 词） |
| 生成 | 仅在设备本地生成，不可导出（非导出流程） |
| SSS 分片对象 | **助记词本身（BIP39 熵字节）**，而非各链私钥 |
| 分片恢复 | 任意 2 份助记词分片 → Lagrange 插值 → 还原完整助记词 → 重新派生所有链私钥 |

**SSS 分片的是助记词（BIP39 熵），恢复一次即还原所有链。**

> **BIP39 熵与助记词的关系：**
> - 128 bit 熵 → 12 个助记词；256 bit 熵 → 24 个助记词
> - 生成流程：随机熵 → 附加 SHA256 校验位 → 按 11 bit 切割 → 每组映射 BIP39 词表（2048 词）→ 得到助记词
> - SSS 实际分片的是**原始熵字节**（16 / 32 字节），助记词是它的人类可读编码，两者可互转
> - 恢复时：SSS 还原熵字节 → 重新编码即得完整助记词

### 3.2 本地设备存储

设备 TEE（Secure Enclave / StrongBox）中持久化存储两样东西：

| 存储内容 | 用途 |
|---------|------|
| **Share A**（助记词分片） | 换机恢复 / 重建助记词时使用 |
| **各链派生私钥**（BIP44 派生结果） | 日常签名直接使用，无需每次重建助记词 |

> 存储派生私钥的好处：本地签名直接取私钥即可，省去每次「重建助记词 → BIP44 派生」的开销。

### 3.3 多链密钥派生策略（BIP44）

```
助记词 (BIP39 熵, 128/256 bit)
    │  钱包创建时一次性派生，结果存入设备 TEE
    │
    ├── m/44'/60'/0'/0/0   → EVM 私钥（ETH/BNB/Polygon...）
    ├── m/44'/0'/0'/0/0    → BTC Legacy 私钥
    ├── m/84'/0'/0'/0/0    → BTC SegWit 私钥 (P2WPKH)
    ├── m/86'/0'/0'/0/0    → BTC Taproot 私钥 (P2TR)
    ├── m/44'/501'/0'/0'   → Solana 私钥 (Ed25519)
    ├── m/44'/784'/0'/0'   → Sui 私钥 (Ed25519)
    ├── m/44'/607'/0'/0'   → TON 私钥 (Ed25519)
    ├── m/44'/397'/0'/0'   → Near 私钥 (Ed25519)
    └── m/44'/637'/0'/0'   → Aptos 私钥 (Ed25519)
```

### 3.4 本地签名（日常使用）

```
用户发起交易 / dApp 签名请求
    ↓
从设备 TEE 直接读取对应链的派生私钥
    ↓
签名 → 广播
```

无需重建助记词，签名延迟极低（毫秒级）。

### 3.5 Agent 签名（自动交易）

```
用户开启 Agent 交易时
    ↓
将 Share B（助记词分片）上传至钱包服务（ECDH 加密，见第十章）
    ↓
钱包服务转存 Share B 至平台云服务（不在钱包服务本地持久化，不存储派生私钥）：
    每次 Agent 签名：
      钱包服务风控模块校验通过 → 签发 ApprovedToken（短生命周期，防 Enclave 伪造）
      → vsock 传入 Nitro Enclave
      → Enclave 内：取 Share B（平台云）+ 取 Share C（KMS，PCR 绑定解密）
      → Enclave 内：Lagrange 插值 → Master Seed → BIP44 派生目标链私钥 → 签名
      → Enclave 内：Master Seed、私钥、Share B 明文立即销毁（私钥全程不出 Enclave 内存）
      → 返回签名 via vsock
    → Session Credit 到期或关闭后通知平台云服务删除 Share B
```

**设计决策：服务端为何不持久化存储派生私钥**

Agent 签名有两种可行策略：

| 维度 | 方案A：每次现场重建（当前方案） | 方案B：上传时预派生存储 |
|------|----------------------------|--------------------|
| 每次签名流程 | KMS 取 B + C → Lagrange → BIP44 → 签名 | KMS 取派生私钥 → 解密 → 签名 |
| 签名额外延迟 | 实测纯加密 ≈9.9ms + 网络I/O，端到端预计 12–15ms | <5ms（1次KMS解密） |
| 服务端存储内容 | **仅 Share B**（分片，单独无用） | Share B + 各链派生私钥 |
| 服务端单点攻击面 | 低：泄露 Share B 单份分片无法还原私钥 | **高：泄露即可直接签名** |
| KMS 调用/次签名 | 2次（取 B、取 C） | 1次（取派生私钥） |

**性能分析：**
- 链上交易广播延迟通常在 **100ms–2s** 量级，Lagrange + BIP44 计算本身耗时极短
- 方案A 的实际延迟主要来自两次网络调用（平台云服务取 Share B + KMS 取 Share C），与部署架构强相关
- 本地设备端（TEE）可缓存派生私钥（见 §3.2），单点风险小，本地签名无需重建
- 服务端是多用户共享节点，单点泄露影响所有用户，不持久化私钥是首要安全原则

> **实测数据（开发机 benchmark，100 次迭代均值，见 `demo_sss/`）**：
>
> | 步骤 | 耗时 |
> |------|------|
> | SSS 重建 B+C → seed（GF-256 Lagrange） | 0.015 ms |
> | BIP44 密钥派生（m/44'/60'/0'/0/0，5 层） | 9.776 ms |
> | ECDSA secp256k1 签名 | 0.070 ms |
> | **纯加密热路径合计** | **≈ 9.9 ms** |
>
> 加上同机房网络 I/O（取 ShareB + ShareC 各约 1–5 ms），**预计端到端 12–15 ms，满足 <20 ms 目标** ✓。
> BIP44 派生是主要瓶颈（HMAC-SHA512 × 5 层）；SSS 重建本身极快（0.015 ms），方案A 现场重建完全可行。
> 若高频场景仍不达标，可缓存至 `m/44'/60'/0'` 层的父公钥（xpub）加速非硬化索引派生，无需持久化私钥。
> 生产压测还需在真实环境（平台云服务 + KMS 同区域/跨区域）下验证网络 I/O 部分。

> **并发压测数据（开发机 8 核，GOMAXPROCS=8，见 `demo_sss/loadtest/`）**：
>
> | 并发数 | 吞吐量 (tps) | p50 延迟 | p99 延迟 | CPU 占用估算 |
> |--------|-------------|---------|---------|------------|
> | 1 | 435 | 8.4 ms | 8.4 ms | 38%（单核） |
> | 10 | 731 | 37.7 ms | 40.5 ms | ≈4.3 核 |
> | 100 | 651 | 419 ms | 481 ms | ≈8 核满载 |
> | 500 | 558 | 2,298 ms | 2,935 ms | 8 核满载 + 排队 |
> | 1,000 | 514 | 5,047 ms | 6,042 ms | 8 核满载 + 大量排队 |
>
> **关键结论：**
> - 瓶颈是 **CPU**（BIP44 每请求 ~10ms HMAC-SHA512），不是 SSS 本身
> - 单机 8 核有效吞吐上限约 **700 tps**；并发 >10 时延迟快速劣化
> - 吞吐与 CPU 核数近似线性扩展；要支持 1,000 并发且 p99 <100ms，需约 **40–50 核**（或 5–6 台 8 核实例水平扩展）
>
> **生产容量规划建议（待用真实服务器压测验证）：**
> - 签名服务须**水平扩展**，按业务峰值并发配置实例数
> - 每实例建议最大并发 ≤ 20（8 核机），超出部分走请求队列 + 限流，避免 p99 爆炸
> - 高频优化选项：缓存 `m/44'/60'/0'` xpub（省去 3 层硬化推导），可将每请求 BIP44 耗时从 ~10ms 降至 ~2ms，单机吞吐提升约 5×，但需评估安全影响

**结论：服务端选择方案A**，接受额外延迟换取私钥永不落地服务端的安全保证。本地设备端维持预派生私钥缓存（方案B逻辑），两端策略不同。

> **Nitro Enclave 部署说明：** 服务端签名热路径（Lagrange + BIP44 + 签名）运行于 Nitro Enclave 内，宿主进程仅做风控校验与请求调度，不接触任何私钥材料。Enclave 无网络访问能力，所有外部调用（KMS、平台云）经由宿主 vsock proxy 转发；KMS key policy 绑定 Enclave PCR 值，只有运行精确镜像的 Enclave 才能解密 Share C（见 §10.1）。
> 每签名一次约增加 2–4ms vsock 往返开销，纳入 §3.5 性能预算后端到端仍满足 <20ms 目标。

---

## 四、SSS 分片设计

### 4.1 分片方案

| 参数 | 值 |
|------|-----|
| 算法 | Shamir Secret Sharing，一次多项式 f(x) = S + a₁·x |
| 门限 | **2-of-3**（任意 2 份即可恢复） |
| 分片对象 | **BIP39 助记词熵**（16/32 字节），而非各链私钥 |
| 坐标分配 | Share A: x=设备坐标（规则见下）；Share B: x=2（固定）；Share C: x=3（固定） |
| Share A 坐标规则 | 初始创建时 x=1；换机恢复时使用**自增序列**：钱包服务为该钱包维护一个从 4 开始的计数器，每次换机 +1（即第一次换机 x=4，第二次 x=5，以此类推），避免碰撞且无需额外去重逻辑 |

### 4.2 三份分片分布

| 分片 | 存储位置 | 加密方式 | 用途 |
|------|---------|---------|------|
| Share A (x=1 初始 / x=n 换机后) | 设备 TEE（Secure Enclave / StrongBox） | TEE 硬件保护，不可导出 | 换机恢复 / 助记词重建 |
| Share B (x=2) | 用户云存储（iCloud / Google Drive / 平台云） | AES-256-GCM，密钥由 Passkey 派生 | 换机 / 设备丢失恢复；Agent 签名时上传服务端 |
| Share C (x=3) | 钱包服务 KMS | KMS 加密，**永不离开服务端** | 辅助恢复；与 B 合并重建助记词用于 Agent 签名 |

### 4.3 Share B 加密方案

按备份渠道不同，加密方式不同：

#### 平台云备份（推荐，全自动恢复）

```
上传时：
  App 生成临时 ECDH 密钥对 (ePub_app, ePriv_app)
  与平台云公钥协商 shared_secret
      ↓
  AES-256-GCM(Share B, HKDF(shared_secret)) → 加密传输
      ↓
  平台云解密后，Share B 明文加密存入平台云存储（独立于钱包服务）

恢复时（全自动，用户无感知）：
  账号登录 + 2FA 验证
      ↓
  平台云取出 Share B，ECDH 加密后下发客户端
```

- 传输安全由 ECDH 保证，静态安全由平台云加密存储保证
- 用户无需记忆任何内容，全自动恢复

#### iCloud / Google Drive 备份

```
上传时：
  用户自行设置 PIN 码（建议 6 位以上，支持字母数字混合）
      ↓
  随机生成 16 字节 salt
      ↓
  Argon2id(PIN, salt, m=65536, t=1, p=1) → 32 字节 AES Key
      ↓
  AES-256-GCM(Share B, key, random_nonce) → 密文
      ↓
  将 { salt, nonce, 密文 } 打包上传到 iCloud / Google Drive（用户私有空间）

恢复时：
  用户输入 PIN 码
      ↓
  从云存储读取 { salt, nonce, 密文 }
      ↓
  Argon2id(PIN, salt, m=65536, t=1, p=1) → 32 字节 AES Key
      ↓
  AES-256-GCM 解密 → Share B 明文 → 进入恢复流程
```

- PIN 由用户自己保管，平台不持有
- 忘记 PIN 则该备份不可用，需通过其他渠道恢复
- **为什么用 Argon2id 而非 HKDF**：HKDF 是快速 KDF，GPU 每秒可枚举数十亿次；Argon2id 强制消耗 64 MB 内存 + 计算时间，使暴力枚举代价极高（攻击者枚举 1 次 ≈ 用户正常验证 1 次的成本）

**Argon2id 参数说明：**

| 参数 | 值 | 说明 |
|------|-----|------|
| `m`（内存） | 65536 KB（64 MB） | 每次运算须占用 64 MB 内存，抗 GPU 并行 |
| `t`（迭代） | 1 | 配合 64 MB 内存，中端手机约 150–300 ms |
| `p`（并行） | 1 | 单线程，避免高并发场景资源争用 |
| 输出长度 | 32 字节 | 直接用作 AES-256 密钥 |
| salt | 随机 16 字节 | 每次加密独立生成，防彩虹表 |

**各端库选型：**

| 平台 | 推荐库 | 说明 |
|------|-------|------|
| Android | `org.bouncycastle:bcpkix` (BC 1.78+) 或 `com.lambdapioneer.argon2kt` | BC 通常已在依赖树中 |
| iOS | `swift-sodium`（LibSodium Swift 封装） | 同时提供 box/sign 等原语，可复用 |
| Go（后端） | `golang.org/x/crypto/argon2` | 官方标准库，直接可用 |

#### 本地二维码备份

```
用户自行设置 PIN 码 → Argon2id(PIN, salt, m=65536, t=1, p=1) → AES-256-GCM 加密 Share B → 将 {salt, nonce, 密文} 编码为二维码
恢复时：扫码 + 输入 PIN → Argon2id 派生密钥 → AES-256-GCM 解密 → Share B 明文
```

### 4.4 Share C 加密（钱包服务）方案

**核心原则：Share C 永不离开钱包服务**

```
钱包服务 职责：
  1. 存储 Share C（KMS 加密存储，不落库明文，永不离开服务端）

  2. 恢复请求处理（生成新 Share A）：
     - 客户端上传加密 Share B（ECDH 信道）
     - 钱包服务：B + C → Lagrange → 计算新 A（新 x 坐标）
         a₁ = C - B
         S  = 3B - 2C
         新 A = f(new_x) = S + a₁ * new_x
     - 用 ePub_client 加密 A'，存入服务端短期缓存（5 分钟，绑定 recovery_token）
     - B 明文、Master Seed、A' 明文在钱包服务内立即销毁（memzero）
     - App 端通过 POST /recovery/claim 主动拉取加密的 A'（而非服务端主动回传）
     - C 不出钱包服务，Share C 本身不下发

  3. Agent 签名（激活期间）：
     - 接收用户上传的 Share B（ECDH 加密传输），转存至平台云服务（不在钱包服务本地持久化）
     - 每次签名：风控模块校验通过 → 签发 ApprovedToken → 经 vsock 传入 Nitro Enclave
       → Enclave 内从平台云取 Share B + 从 KMS 读取 Share C（PCR 绑定，Enclave 专属解密权限）
       → Enclave 内：Lagrange → Master Seed → BIP44 派生目标链私钥 → 签名
       → Enclave 内：Master Seed、私钥及 Share B 明文立即销毁（私钥全程不出 Enclave 内存）
     - Session Credit 到期或用户关闭后，通知平台云服务删除 Share B

  4. 对所有 Share C 访问记录不可篡改审计日志
  5. 不存储、不记录 Share A
```

### 4.5 SSS 数学参考

2-of-3 一次多项式，任意两份分片可确定性还原全部：

```
坐标约定：Share A x=1（初始）/ x=n（换机，n 从 4 开始自增）；Share B x=2；Share C x=3

给定 B = f(2), C = f(3)：
  a₁ = C - B
  S  = 3B - 2C              ← BIP39 熵（16/32 字节）
  A  = f(1) = 2B - C        ← 初始设备 Share A（x=1）
  A' = f(n) = S + a₁ * n   ← 新设备 Share A（x=n，n 由钱包服务自增分配）

给定 A = f(x_a), B = f(2)：
  a₁ = (B - A) / (2 - x_a)
  S  = A - a₁ * x_a         ← BIP39 熵（16/32 字节）
```

> **新设备坐标 n 的分配规则：**
> - 坐标 1/2/3 固定保留给初始 Share A / B / C，不可复用
> - 换机时钱包服务为该钱包维护一个自增计数器（初始值 4），每次换机取当前值后 +1
> - 第 1 次换机 x=4，第 2 次 x=5，以此类推，天然无碰撞，无需额外去重逻辑
> - 当前坐标 n 与 Share A 密文一起记录在钱包表中，恢复流程读取使用

## 五、SSS 库选型建议

三端须使用**相同有限域（GF(256) 或同一素数域）和相同多项式约定**，确保任意两端的分片可互相重建，不能各用一套不兼容的实现。

### 5.1 Go（后端 / 钱包服务）

| 库 | 特点 | 推荐度 |
|----|------|--------|
| `hashicorp/vault/shamir` | 生产级，Vault 在用，GF(256)，常数时间实现 | ★★★ 推荐 |
| `corvus-ch/sss` | 轻量，标准 Shamir，GF(256) | ★★ 备选 |
| `tss-lib/crypto/vss` | 本项目已有，含 Lagrange 插值 | ★★ 可复用 |

**推荐：** `hashicorp/vault/shamir`，生产验证充分，GF(256) 与主流移动端库兼容。

### 5.2 Java / Kotlin（Android）

| 库 | 特点 | 推荐度 |
|----|------|--------|
| `codahale/shamir` | Java 实现，GF(256)，与 `hashicorp/vault/shamir` 域一致，轻量 | ★★★ 推荐 |
| gomobile 封装 Go 库 | 直接复用后端同一份代码，零兼容风险，但 gomobile 维护成本较高 | ★★ 备选 |

**推荐：** `codahale/shamir`，GF(256) 域与后端对齐，Java 原生无需跨语言绑定；如对一致性要求极高可改用 gomobile。

### 5.3 Swift（iOS）

| 库 / 方案 | 特点 | 推荐度 |
|----------|------|--------|
| `dsprenkels/sss`（C 库 + Swift 桥接） | C 实现，GF(256)，经过安全审计，Swift 通过 `bridging header` 调用 | ★★★ 推荐 |
| 自实现 Swift SSS | 基于 Apple CryptoKit 做底层随机数，手写 GF(256) 多项式，灵活但需自行审计 | ★★ 可行 |
| gomobile 封装 Go 库 | 复用后端代码，兼容性最佳，但 gomobile iOS 打包体积和维护成本较高 | ★ 备选 |

**推荐：** `dsprenkels/sss` C 库桥接，GF(256) 与后端一致，已有安全审计报告；若团队 Swift 能力强且愿意自行审计，自实现方案可控性更好。

### 5.4 三端对齐要求

| 对齐项 | 要求 |
|--------|------|
| 有限域 | 统一使用 **GF(256)**（即 GF(2⁸)，特征多项式需一致） |
| 分片坐标约定 | Share A x=1（初始创建）/ x=n（换机，n 从 4 开始自增）；Share B x=2（固定）；Share C x=3（固定）；三端定义相同 |
| 字节序 | 分片字节数组的大小端表示需明确约定 |
| 输入格式 | 分片对象为 BIP39 熵字节（16 或 32 字节），不含校验位 |
| 互操作测试 | 上线前必须做跨端验证：Go 分片 → Swift 重建、Java 分片 → Go 重建等组合全覆盖 |
---

## 六、钱包创建流程

```
━━━━━━━━━━━━━━━━━━━━━━  创建钱包  ━━━━━━━━━━━━━━━━━━━━━━━━

          登录 AVE 账户 + Passkey / FaceID / TouchID 认证
                               ↓
              设备本地生成 BIP39 随机熵（128/256 bit）
                               ↓
                  SSS 分片运算：f(x) = 熵 + a₁·x
         ┌─────────────────────┼──────────────────────┐
         ↓                     ↓                      ↓
  Share A（x=1）          Share B（x=2）          Share C（x=3）
  写入 Device TEE         用户选择备份渠道          ECDH 加密上传
                     (平台云 / iCloud / 二维码)     钱包服务 KMS
                                ↓
                 BIP44 派生各链私钥 → 写入 Device TEE
                                ↓
                        助记词明文从内存清除
                                ↓
            ┌─────────────────────────────────────────┐
            │              Device TEE                 │
            │  Share A（SSS 分片）   ← 换机恢复用      │
            │  各链派生私钥（BIP44） ← 本地签名直接使用 │
            └─────────────────────────────────────────┘
```

---

```
步骤1：生成助记词
  ├─ 设备本地生成 128/256 bit 随机熵
  ├─ 按 BIP39 编码为 12/24 个助记词
  └─ 可选：展示助记词给用户

步骤2：SSS 分片（对 BIP39 熵字节做分片）
  ├─ 设备本地 SSS 运算：f(x) = S + a₁·x（a₁ 随机，S = 熵字节）
  ├─ Share A = f(1) → 存入设备 TEE（Secure Enclave / StrongBox）
  ├─ Share B = f(2) → 待上传云备份（见步骤3）
  └─ Share C = f(3) → ECDH 加密后上传钱包服务 KMS

步骤3：Share B 备份（用户选择备份方式）
  ├─ 平台云备份（推荐）：ECDH 加密上传，平台云加密存储，全自动恢复
  ├─ iCloud / Google Drive：用户设置 PIN，Argon2id(PIN, salt) 派生密钥后 AES-256-GCM 加密上传
  └─ 本地二维码：用户设置 PIN，Argon2id(PIN, salt) 派生密钥后 AES-256-GCM 加密生成二维码离线保存

步骤4：Share C 上传
  ├─ 上传成功 → 标记 keyless 功能完整
  └─ 上传失败 → 标记 pending，App 下次启动自动重试
     （期间 A+B 仍可本地签名，只是服务端辅助恢复能力受限）

步骤5：BIP44 派生各链私钥
  ├─ 助记词 → BIP44 派生各链私钥
  ├─ 各链派生私钥存入设备 TEE（用于本地签名，无需每次重建助记词）
  └─ 助记词明文从内存清除（Share A 和派生私钥留存 TEE）

步骤6：生成各链地址
  └─ 根据各链私钥计算公钥和地址，展示给用户

约束：
  - Keyless 钱包首期仅支持随机生成助记词，不支持导入已有助记词（EOA 钱包支持导入，见第十三章）
  - 每个账号限创建 N 个钱包地址（避免滥用，由产品业务定义，比如最多10个）
```

---

### 6.1 Share C 加密上传详细交互流程（ECDH + AES-256-GCM）

> **设计原则：** 钱包服务 Nitro Enclave 持有加密密钥对，用户服务全程不参与解密，仅做鉴权和透明路由；Share C 明文仅在 Enclave 内存中短暂存在后即销毁。

**密钥归属：**

| 密钥 | 持有方 | 说明 |
|------|-------|------|
| `sPriv`（服务端临时 ECDH 私钥） | Nitro Enclave 内存 | 每次上传请求动态生成，用完即销毁，永不离开 Enclave |
| `sPub`（服务端临时 ECDH 公钥） | 由钱包服务宿主经 vsock 转发给用户服务再下发 App | 公钥可公开，无安全风险 |
| `ePriv_app`（App 端临时 ECDH 私钥） | App 内存 | 完成加密后立即销毁 |

```
── 阶段一：获取服务端临时公钥 ──

  App → POST /wallet/share_c/init（附 JWT + Passkey assertion）
    ↓
  用户服务：
    ├─ 校验 JWT、Passkey assertion、账号状态
    └─ 转发至钱包服务宿主（内网 RPC）
    ↓
  钱包服务宿主 → vsock → Nitro Enclave：
    ├─ 生成本次请求专属临时 ECDH 密钥对 (sPub, sPriv)
    ├─ sPriv 仅存 Enclave 内存，绑定 upload_ticket（短期令牌，5 分钟有效）
    └─ 返回 { sPub, upload_ticket }
    ↓
  App 接收 { sPub, upload_ticket }

── 阶段二：App 本地加密 Share C ──

  App 生成临时 ECDH 密钥对 (ePub_app, ePriv_app)
    ↓
  ECDH(ePriv_app, sPub) → raw_shared_secret
    ↓
  HKDF-SHA256(raw_shared_secret, salt=ePub_app, info="share_c_upload") → 32 字节 AES 密钥
    ↓
  AES-256-GCM(Share_C明文, aes_key, random_nonce) → enc_C
    ↓
  ePriv_app、aes_key 立即销毁（内存清除）

── 阶段三：提交加密 Share C ──

  App → POST /wallet/share_c/upload（附 JWT）
    Body: { wallet_addr, enc_C, ePub_app, nonce, upload_ticket }
    ↓
  用户服务：
    ├─ 校验 JWT、wallet_addr 归属当前账号
    └─ 将 { enc_C, ePub_app, nonce, upload_ticket } 原样透传至钱包服务
       （用户服务不解密，不持有任何密钥）
    ↓
  钱包服务宿主 → vsock → Nitro Enclave：
    ├─ 验证 upload_ticket（有效期、未使用、绑定 sPriv）
    ├─ ECDH(sPriv, ePub_app) → raw_shared_secret
    ├─ HKDF-SHA256(raw_shared_secret, salt=ePub_app, info="share_c_upload") → AES 密钥
    ├─ AES-256-GCM 解密 → Share C 明文
    ├─ 调用 KMS 加密存储 Share C（PCR 绑定的 KMS key，仅当前 Enclave 镜像可解密）
    ├─ sPriv、Share C 明文、AES key 立即销毁（memzero）
    └─ 返回 { success }
    ↓
  用户服务透传结果给 App
  App 标记 keyless 功能就绪
```

**安全要点：**

| 关注点 | 保障措施 |
|-------|---------|
| 用户服务能否看到 Share C | 不能，enc_C 经 App 加密，用户服务仅做透明路由 |
| 钱包服务宿主能否看到 Share C | 不能，vsock 传输，明文解密仅在 Enclave 内存中 |
| 重放攻击 | upload_ticket 单次使用 + 5 分钟有效期，绑定具体 sPriv |
| 中间人替换 sPub | App 可结合 NSM Attestation 验证 sPub 来自合法 Enclave（可选强化） |
| sPriv 泄露 | sPriv 随 Enclave 请求生命周期，请求结束即 memzero |

---

## 七、钱包恢复流程

```
━━━━━━━━━━━━━━━━━━━━━━  恢复钱包  ━━━━━━━━━━━━━━━━━━━━━━━━

      登录 AVE 账户 + 2FA 验证（Passkey 或 Email + 谷歌验证器）
                               ↓
                    获取 Share B（三选一）
         ┌─────────────────────┼─────────────────────┐
         ↓                     ↓                     ↓
    平台云自动下发         iCloud / GDrive          扫描二维码
    （账号验证即可）        用户输入 PIN 解密         用户输入 PIN 解密
         └─────────────────────┼─────────────────────┘
                               ↓
         ── 第一步：POST /recovery/submit ──
           App 生成临时 ECDH 密钥对，加密 Share B 上传钱包服务
                               ↓
      钱包服务 Nitro Enclave：B + C → Lagrange → 计算新 A'(x=new_x)
                 → ePub_client 加密 A'，存入短期缓存（5 分钟）
                 → B 明文、Master Seed 立即销毁
                 → 返回 recovery_token（单次可用）
                               ↓
         ── 第二步：POST /recovery/claim ──
              Passkey 生物识别二次确认
                               ↓
           App 提交 recovery_token → 钱包服务返回 enc_A'
                               → token 立即失效
                               ↓
          ┌─────────────────────────────────────────┐
          │              新设备本地                  │
          │  ePriv_client 解密得 A'(x=new_x)        │
          │  A' + B → Lagrange → BIP39 熵           │
          │  → BIP44 派生各链私钥 → 写入设备 TEE    │
          │  → 熵、ePriv_client 立即销毁             │
          └─────────────────────────────────────────┘
                               ↓
              恢复完成（Share C 全程不出服务端）
```

---

### 7.1 SSS 数学保证

在 2-of-3 SSS 方案中，任意两份分片可**确定性**还原助记词熵（BIP39 entropy），
同时也可确定性计算第三份分片（因一次多项式由任意两点唯一确定）。

### 7.2 触发恢复的场景

| 场景 | Share A 状态 | 恢复路径 |
|------|------------|---------|
| 换新设备 / 应用卸载 / 数据清除 | A 丢失 | Share B（任意来源）+ 钱包服务 Share C → 计算新 A，重新派生私钥 |
| 设备被盗 / 分片疑似泄露 | 可能泄露 | **紧急冻结 → 新设备恢复资产 → 创建新钱包迁移 → 销毁旧钱包**（见 §7.5） |
| A 丢失 + iCloud/GDrive 备份也丢失 | A 丢失 | 本地二维码扫码 + PIN → 恢复 B → 再走标准流程；若二维码也丢失则**不可恢复** |
| A 丢失 + Share B 所有备份均丢失 | A 丢失 | **不可恢复**（平台云备份不会主动丢失，强烈建议开启） |

### 7.3 Share B 备份方式与丢失风险

| 优先级 | 备份方式 | 丢失风险 | 说明 |
|--------|---------|---------|------|
| **必选** | 平台云备份 | 极低，账号可登录即可恢复 | 跨平台（Android ↔ iOS），全自动恢复，无需用户操作 |
| 辅助 | iCloud / Google Drive | 中，依赖用户账号安全，存在误删、账号丢失、跨平台不兼容风险 | 需用户输入 PIN，建议作为平台云的冗余 |
| 兜底 | 本地二维码 | 高，设备损坏/丢失即丢失 | 完全离线，PIN 加密，截图/打印保存，仅作最后应急手段 |

**强烈建议：必须开启平台云备份；其余方式作为额外冗余，多一份保障。**

**本地二维码说明：**
- 创建钱包时可选择生成恢复二维码
- 二维码内容 = Argon2id(PIN, salt) 派生密钥后 AES-256-GCM 加密的 Share B
- 保存形式：截图 / 打印 / 存安全 App
- 恢复时：扫码 + 输入 PIN → 解得 Share B → 走标准恢复流程

### 7.4 标准恢复流程（Share C 不出钱包服务）

恢复接口拆为**两步**，将 Share B 上行和 Share A 下行分离到独立请求，避免单次传输同时携带两片可还原密钥的材料。攻击者若只截获其中一步，得到的数据单独无法还原主种子。

**安全校验分层（详见 §10.5 服务间信任模型）：**

| 层次 | 执行方 | 校验内容 |
|------|-------|---------|
| 第一层 | 用户服务 | Passkey / 2FA 验证、账号状态、钱包归属，签发 OperationToken（`verified_methods` 标记本次使用的验证方式） |
| 第二层 | 钱包服务（独立） | 独立验证 OperationToken 签名；**Passkey 路径**额外独立 re-verify assertion；**Email+TOTP 路径**信任 token 但限频更严（30 天 ≤ 2 次）；均写入独立审计日志 |
| 第三层 | Nitro Enclave | 验证 ApprovedToken（防宿主伪造）、B+C 重建、memzero |

```
━━━━━━━━━━━━━━━━━  第一步：提交 Share B  ━━━━━━━━━━━━━━━━━

步骤1：身份验证（用户服务 — 第一层）
  ├─ 登录账号（JWT 校验）
  ├─ 2FA 验证（Passkey 优先，Email + 谷歌验证器备用）
  │    收集原始 passkey assertion，随请求透传至钱包服务
  ├─ 校验账号历史中存在该钱包
  └─ 签发 OperationToken（operation=recover_wallet, verified_methods, exp=15min）
       > 恢复操作有效期设为 15 分钟，确保用户有足够时间完成
       > iCloud/GDrive 下载 + PIN 输入等本地操作，不会因超时被迫重新 2FA。

步骤2：客户端获取 Share B（本地解锁）
  ├─ 平台云：账号验证通过后平台云取出 Share B，ECDH 加密下发
  ├─ iCloud / GDrive：本地下载 + 用户输入 PIN 解密
  └─ 二维码：扫码 + 用户输入 PIN 解密

步骤3：客户端提交 Share B（API 1：submit）
  ├─ 客户端生成临时 ECDH 密钥对 (ePub_client, ePriv_client)
  │    ePriv_client 仅存内存，用于后续解密 A'
  ├─ 用钱包服务公钥 ECDH 加密 Share B
  └─ POST /recovery/submit
       { enc_B, ePub_client, wallet_address, operation_token,
         passkey_assertion(如有) }  // Passkey 路径随 token 透传 assertion；Email+TOTP 路径此字段为空

步骤4：钱包服务处理
  │ ── 宿主风控（第二层独立校验）──
  ├─ 验证 OperationToken 签名（inter-service key，KMS 管理）
  ├─ 校验 operation=recover_wallet 与请求匹配，exp 未过期
  ├─ 按 verified_methods 分路径处理：
  │    [Passkey 路径]   独立 re-verify passkey assertion（不依赖用户服务声明）
  │                     限频：单账号 30 天 ≤ 3 次
  │    [Email+TOTP 路径] OTP 已消费，无法独立再验证；信任 inter-service signed token
  │                     限频更严：单账号 30 天 ≤ 2 次
  ├─ 写入独立审计日志（记录 verified_methods，事后可区分两条路径）
  ├─ 校验通过 → 签发 ApprovedToken → vsock → Nitro Enclave
  │ ── Nitro Enclave 内 ──
  ├─ 验证 ApprovedToken
  ├─ 解密得到 B 明文
  ├─ 从 KMS 取出 Share C
  ├─ B + C → Lagrange → 还原助记词熵 S
  ├─ 分配新坐标 new_x（自增，从 4 开始），计算 A' = S + a₁ * new_x
  ├─ 用 ePub_client 加密 A'，存入服务端短期缓存（绑定 recovery_token）
  ├─ B 明文、S、a₁、A' 明文立即销毁，new_x 记录至钱包表
  └─ 返回 { recovery_token }（短生命周期，5 分钟过期，单次可用）

━━━━━━━━━━━━━━━━━  第二步：领取 Share A  ━━━━━━━━━━━━━━━━━

步骤5：客户端二次身份确认后领取 A'（API 2：claim）
  ├─ 对用户做轻量二次确认（如 Passkey 生物识别确认弹窗）
  └─ POST /recovery/claim
       { recovery_token, account_token }

步骤6：钱包服务返回 A'
  ├─ 验证 recovery_token 有效、未过期、未被使用
  ├─ 验证 account_token 与提交步骤为同一账号
  ├─ 从缓存取出 enc_A'（已用 ePub_client 加密，服务端无法解密）
  ├─ recovery_token 标记已消费（单次使用，立即失效）
  └─ 返回 { enc_A', new_x }

步骤7：客户端本地
  ├─ 用 ePriv_client 解密得到 A' 明文 → 写入新设备 TEE（记录坐标 new_x）
  ├─ A'(x=new_x) + B(x=2) → Lagrange → 还原助记词熵 S
  ├─ BIP44 重新派生各链私钥 → 存入设备 TEE
  └─ A'、S、ePriv_client 从内存清除（TEE 中仅留 A' 和各链私钥）
```

**两步拆分的安全收益：**

| 攻击场景 | 拆分前 | 拆分后 |
|---------|--------|--------|
| 截获上行请求 | 得到 Share B | 得到 Share B（仍需第二步） |
| 截获下行响应 | 得到加密 A'，需 ePriv_client 解密 | 同左，但还需 recovery_token 和二次确认 |
| 同时截获上下行 | B + A'，两片齐全，可还原 | 两步时间分离，需在 5 分钟窗口内同时截获两步 + 通过二次确认 |
| recovery_token 泄露 | 不存在此凭证 | 单独无用，还需同账号 Token + 二次确认才能领取 |

### 7.5 删除钱包流程

```
━━━━━━━━━━━━━━━━━━━━━━  删除钱包  ━━━━━━━━━━━━━━━━━━━━━━━━

  场景一：用户主动删除
  ─────────────────────────────────────────────────────────
  Passkey 验证 → 确认余额已转出
         ↓
  删除 Device TEE（Share A + 各链派生私钥）
         ↓
  通知钱包服务：
    撤销所有 Agent Session Credit
    → 软删除平台云 Share B（30 天后物理删除）
    → 软删除 Share C（30 天缓冲期后物理删除）

  场景二：设备被盗 / 分片疑似泄露
  ─────────────────────────────────────────────────────────
  任意设备登录账号 → 触发紧急冻结
         ↓
  钱包服务立即：撤销所有 Agent Session Credit + 冻结平台云 Share B（禁止访问）
         ↓
  走恢复流程（§7.4，新设备重建旧钱包）→ 取回资产
         ↓
  创建全新钱包 → 迁移资产
         ↓
  销毁旧钱包：删除 Device TEE + 软删除平台云 Share B + 软删除 KMS Share C（30 天后物理删除）
```

---

**安全校验分层（详见 §10.5 服务间信任模型）：**

| 层次 | 执行方 | 校验内容 |
|------|-------|---------|
| 第一层 | 用户服务 | Passkey / 2FA 验证、账号状态，签发 OperationToken（含 passkey assertion 指纹） |
| 第二层 | 钱包服务（独立） | 独立验证 OperationToken、独立再验证 passkey assertion、写入独立审计日志 |

#### 场景一：用户主动删除钱包

适用于：用户不再使用该钱包，主动发起删除。

> **前提：App 应在删除前展示当前余额，提醒用户先将资产全部转出；如需保留私钥，应先走导出流程（见第八章）。**

```
步骤1：强身份验证（用户服务 — 第一层）
  ├─ Passkey 验证（或 Email + 谷歌验证器）
  │    收集原始 passkey assertion，随请求透传至钱包服务
  ├─ 弹出确认提示：展示当前余额，用户明确确认
  └─ 签发 OperationToken（operation=delete_wallet, verified_methods, exp=5min）

步骤2：客户端本地清除
  ├─ 删除设备 TEE 中的 Share A
  └─ 删除设备 TEE 中的各链派生私钥

步骤3：通知钱包服务（第二层独立校验）
  ├─ 验证 OperationToken 签名、operation=delete_wallet、exp 未过期
  ├─ 独立再验证 passkey assertion
  ├─ 写入独立审计日志
  └─ 校验通过后：
       ├─ 撤销该钱包所有 Agent Session Credit，停止自动交易
       ├─ 软删除平台云 Share B（如有，30 天后物理删除）
       └─ 软删除 Share C（30 天缓冲期后物理删除）

步骤4：完成
  └─ 钱包在 App 内标记为"已删除"，不再展示
```

#### 场景二：设备被盗 / 分片疑似泄露（安全处置）

适用于：设备丢失/被盗，或怀疑 Share A 已遭泄露，**核心目标：立即切断风险、转移资产、弃用旧地址**。

> **为什么不做分片刷新而是直接弃用？**
> 旧设备上已泄露的 Share A 在刷新前依然有效，继续使用该地址存在不可控风险。
> 正确做法是彻底放弃旧地址，将资产迁移到全新钱包。

```
步骤1：紧急冻结（可在任意设备登录账号触发）
  ├─ 登录账号 → 安全设置 → 触发紧急冻结
  ├─ 用户服务（第一层）：验证账号登录态 + 2FA，签发 OperationToken（operation=emergency_freeze, exp=5min）
  └─ 钱包服务（第二层独立校验）：验证 OperationToken 后立即执行：
       - 若 Agent 会话激活中：立即删除内存中的 Share B
       - 撤销所有 Agent Session Credit，停止自动交易
       - 冻结 Share C 读取权限（仅允许本次资产恢复流程使用）
       - 写入独立审计日志

步骤2：在新设备上恢复资产访问权
  ├─ 走标准恢复流程（§7.4），在新设备上重建旧钱包
  └─ 目的仅是取回资产，不继续使用这个地址

步骤3：创建全新钱包
  └─ 生成全新助记词 → 全套新分片 → 新地址

步骤4：迁移资产
  └─ 将旧钱包所有资产转移到新钱包地址

步骤5：销毁旧钱包
  ├─ 删除设备 TEE 中的旧 Share A 和旧派生私钥
  ├─ 软删除平台云 Share B（30 天后物理删除）
  └─ 软删除 KMS 中的 Share C（30 天后物理删除）
```

---

**删除策略说明：**
- 所有场景（包括安全事件）统一采用**软删除 → 30 天缓冲 → 物理删除**
- 软删除期间分片标记为不可用，系统拒绝任何访问请求，安全性等价于物理删除
- 30 天缓冲期的价值：误操作可恢复、安全事件可取证、监管合规留存
- 缓冲期内如需撤销，须经人工客服审核后恢复软删除标记

### 7.6 频率与风控

- 完整恢复（B 上传服务端 → 获得新 A）：**30 天内最多 3 次**
- 超限后：冻结恢复功能，需人工客服审核

---

## 八、私钥导出（Keyless → 标准私钥钱包）

**设计原则：重建必须在客户端本地完成，服务端只接收状态通知，不参与重建。**

### 8.1 导出流程

**安全校验分层（详见 §10.5 服务间信任模型）：**

| 层次 | 执行方 | 校验内容 |
|------|-------|---------|
| 第一层 | 用户服务 | Passkey 或 Email+TOTP（二选一）、账号状态，签发 OperationToken（`verified_methods` 标记使用方式） |
| 第二层 | 钱包服务（独立） | 独立验证 OperationToken；**Passkey 路径**独立 re-verify assertion；**Email+TOTP 路径**信任 token；校验导出次数 ≤ 1 次（硬限制）；写入独立审计日志 |

```
步骤1：身份验证（用户服务 — 第一层）
  ├─ 用户服务（第一层）
  │    ├─ 2FA 验证（Passkey 优先，Email + 谷歌验证器备用）
  │    │    Passkey 路径：收集原始 passkey assertion，随请求透传至钱包服务
  │    └─ 签发 OperationToken（operation=export_wallet, verified_methods, exp=5min）
  └─ 弹出明确风险提示：
       "导出后，钱包将转为普通私钥钱包，
        无密钥丢失保护。30 天内可撤销导出，
        30 天后平台将永久删除备份分片，操作不可逆。"

步骤2：客户端本地重建助记词
  ├─ 客户端 TEE 持有 Share A
  ├─ 从云备份下载 Share B（平台云自动获取 / iCloud/GDrive 需 PIN 解密）
  ├─ 本地 Lagrange 插值：A(x_a) + B(x=2) → 助记词熵 S
  ├─ S 即为 BIP39 助记词熵（可编码为 12/24 词助记词，或直接派生各链私钥）
  └─ 重建过程全程在客户端内存，不经过网络

步骤3：通知钱包服务（第二层独立校验）
  ├─ 客户端向钱包服务发送"导出确认"请求（附 operation_token + passkey_assertion）
  ├─ 钱包服务独立校验：
  │    ├─ 验证 OperationToken 签名、operation=export_wallet、exp 未过期
  │    ├─ 按 verified_methods 分路径：
  │    │    [Passkey 路径]   独立 re-verify passkey assertion
  │    │    [Email+TOTP 路径] 信任 inter-service signed token
  │    ├─ 校验该钱包导出次数 ≤ 1 次（硬限制，独立计数，不依赖上游传入）
  │    └─ 写入独立审计日志（记录 verified_methods）
  └─ 校验通过后：
       ├─ 撤销所有 Agent 会话
       ├─ 平台云 Share B 软删除（标记"待删除"，30 天后物理删除）
       ├─ Share C 软删除（标记"待删除"，30 天后物理删除）
       └─ 钱包标记为"已导出/普通私钥模式"

步骤4：交付与清理
  ├─ 将助记词熵 S 编码为 BIP39 助记词（12/24 词）展示给用户
  ├─ 用户确认后，内存中的 S / 助记词立即清除
  └─ 设备 TEE 中的 Share A 和派生私钥由用户自行选择是否清除
```

### 8.2 导出后状态

- 该地址脱离 Keyless 保护，App 中显示"普通钱包"标识
- **30 天缓冲期内**：Share B（平台云）和 Share C 均处于软删除状态，用户可申请撤销导出、恢复 Keyless 保护
- **30 天后**：Share B、Share C 物理删除，无法再通过 SSS 恢复，操作不可逆
- 如需重新享受 Keyless 保护：需创建新钱包地址

### 8.3 导出限制

- 每个钱包仅允许导出 1 次（Share C 物理删除后无法再导出）
- 导出操作及撤销操作均记录在不可篡改审计日志中

---

## 九、本地签名流程

> 适用场景：用户主动发起的转账、合约交互、dApp 签名请求。
> 前提：设备 TEE 中已存有各链派生私钥（钱包创建或恢复时写入，见 §3.2）。

### 9.1 签名流程

```
用户发起交易 / dApp 发起签名请求
        ↓
从设备 TEE 直接读取目标链派生私钥
        → 签名（secp256k1 或 Ed25519）
        → 私钥读取后不离开 TEE 保护边界
        ↓
返回签名结果
        ↓
广播交易 / 返回给 dApp
```

> 本地签名无需重建 Master Seed，直接取 TEE 中预存的派生私钥，延迟极低（毫秒级）。
> 设备端私钥单点风险小（仅影响单用户），可安全缓存；服务端不做同样的预存（见 §3.5）。

### 9.2 支持的签名类型

| 类型 | 说明 |
|------|------|
| 链上交易 | 转账、合约调用（EVM / Solana / BTC 等） |
| EIP-712 结构化签名 | dApp 授权、订单签名 |
| Personal Sign | dApp 登录、消息验签 |

### 9.3 关键约束

- **仅用于用户主动操作**，不用于 Agent 自动签名（Agent 签名走服务端现场重建，见第十章）
- 设备 TEE 中的派生私钥在以下情况需重新写入：换机恢复后、钱包导出后

---

## 十、Agent 自动签名

```
━━━━━━━━━━━━━━━━━━━  开启 Agent 自动交易  ━━━━━━━━━━━━━━━━━━

          用户开启 Agent Trading（App 内授权）
                               ↓
               Passkey 验证 + 填写 Session Credit 策略
                               ↓
           App ECDH 加密 Share B，上传至钱包服务（§10.3）
                               ↓
       钱包服务：验证身份 + Session Credit 合法性 + master_sig
                               ↓ 验证通过，分别写入
         ┌─────────────────────┴─────────────────────┐
         ↓                                           ↓
┌─────────────────┐                     ┌───────────────────────┐
│   平台云服务     │                     │      钱包服务          │
│  （AWS 账号 B） │                     │    （AWS 账号 A）      │
│  Share B（加密） │                     │  Share C（KMS 加密）   │
│  独立于钱包服务  │                     │  Session Credit Policy│
└─────────────────┘                     └───────────────────────┘
         └─────────────────────┬─────────────────────┘
                               ↓ 自动交易执行时
         AI Agent → 风控校验 → ApprovedToken → Nitro Enclave
                               ↓
         Enclave：取 B（PrivateLink → 平台云，附 NSM Attestation）
                + 取 C（KMS，PCR 绑定）
                               ↓
              Lagrange → Master Seed → BIP44 派生目标链私钥
                               ↓
                    签名 → memzero 全部密钥材料 → 广播
```

---

### 10.1 钱包服务模块

Agent 自动签名能力由**钱包服务（Wallet Service）**统一承载。**风控模块以进程内 library 形式内嵌于钱包服务宿主进程**，签名代码路径必须经过风控，无法通过 API 跳过。**私钥重建与签名运算下沉至 Nitro Enclave**，宿主进程永远接触不到私钥明文。

```
┌──────────────────────────────────────────────────────────────┐
│                      EC2 宿主实例                             │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                  Wallet Service 进程                  │   │
│  │                                                      │   │
│  │  ┌──────────────┐   ┌──────────────────────────┐    │   │
│  │  │   API 接入层  │   │       密钥管理模块         │    │   │
│  │  │  - 请求路由   │   │  - 创建 / 删除助记词       │    │   │
│  │  │  - 认证鉴权   │   │  - 管理 Share C 写入 KMS   │    │   │
│  │  └──────┬───────┘   │  - 恢复 / 导出流程协调      │    │   │
│  │         │ 必经路径   └──────────────────────────┘    │   │
│  │         ↓                                           │   │
│  │  ┌──────────────────────────────────────────────┐   │   │
│  │  │          风控模块（进程内 library）            │   │   │
│  │  │  - 通用基础校验（Token / 限频 / 防篡改）       │   │   │
│  │  │  - Agent 签名校验（Session / 金额 / 防重放）   │   │   │
│  │  │  - 恢复 / 导出 / 删除流程校验                 │   │   │
│  │  │  - 异常检测与告警                             │   │   │
│  │  │  - 校验通过后签发 ApprovedToken               │   │   │
│  │  └──────────────────────┬───────────────────────┘   │   │
│  │                         │ ApprovedToken + 签名请求   │   │
│  │  ┌──────────────────────▼───────────────────────┐   │   │
│  │  │       vsock IPC 层 + 哑代理（TCP relay）      │   │   │
│  │  │  - 转发 ApprovedToken + 签名请求至 Enclave    │   │   │
│  │  │  - 透明转发 Enclave 发出的加密字节流          │   │   │
│  │  │    （宿主只做 TCP relay，无法解密 TLS 内容）  │   │   │
│  │  └──────────────────────────────────────────────┘   │   │
│  └──────────────────────────────────────────────────┘   │
│                    │ vsock（唯一通道）                        │
│  ┌─────────────────▼────────────────────────────────────┐   │
│  │                Nitro Enclave（签名 TEE）               │   │
│  │  - 验证 ApprovedToken（防宿主伪造）                   │   │
│  │  - 生成临时 TLS 密钥对（私钥不出 Enclave）            │   │
│  │  - 取 NSM Attestation Document（含 PCR 度量值）       │   │
│  │  - E2E TLS → 宿主 TCP relay → PrivateLink            │   │
│  │    → 平台云宿主（验证 NSM Attestation，返回 Share B） │   │
│  │  - E2E TLS → 宿主 TCP relay → KMS                    │   │
│  │    （KMS key policy 验证 PCR，返回 Share C）          │   │
│  │  - Lagrange → Master Seed → BIP44 → 私钥 → 签名      │   │
│  │  - memzero 全部密钥材料，返回 signature               │   │
│  │  ← 宿主仅见密文字节流，无法解密或篡改 →              │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
     ↓ E2E TLS（经宿主 TCP relay）      ↓ TLS（经宿主 TCP relay）
KMS（Share C，PCR 绑定 key policy）  平台云服务（Share B，NSM Attestation 鉴权）
                                     ← AWS PrivateLink 跨账号私网通道 →
```

### 10.2 开通 Agent 交易

用户首次开启 Agent 自动交易时，需完成一次显式授权：

```
用户在 App 开启「Agent 自动交易」
        ↓
填写 Session 授权许可
  - 允许的订单类型（限价单/止盈止损/跟单）
  - 有效期（默认 30 天，7/15/30天）
        ↓
App 用 Master Key 对 Session Credit 内容签名
        ↓
ECDH 加密 Share B 后上传钱包服务（详见 §10.3）
        ↓
钱包服务验证通过 → 开启 Agent 交易
```

### 10.3 Share B 上传流程

Share B 上传必须满足三个要求：**身份真实（Master Key 签名）+ 传输安全（ECDH 加密）+ 权限绑定（Session Credit）**。

> **存储位置说明：** Agent 激活期间的 Share B 存储于**平台云服务**，而非钱包服务本地。
> 这样即使钱包服务被攻破，攻击者也只能拿到 Share C，无法独立还原 Master Seed；
> 同理平台云服务只有 Share B，同样无法还原。两个系统需同时被攻破才构成威胁。

```
步骤1：App 准备上传材料
  ├─ credit_json：§11 定义的授权许可（含 allowed_order_types + expire_at）
  ├─ master_sig：App 用 Master Key 对 hash(credit_json + share_b) 的签名
  └─ 用于证明：这份 B 和这份许可，确实来自该钱包的合法持有者

步骤2：ECDH 加密 Share B（以钱包服务临时公钥加密）
  ├─ App 请求钱包服务的临时公钥 ePub_server
  ├─ App 生成临时密钥对 (ePub_app, ePriv_app)
  ├─ shared_secret = ECDH(ePriv_app, ePub_server)
  ├─ enc_B = AES-256-GCM(Share B, HKDF(shared_secret))
  └─ 上传至钱包服务：{ enc_B, ePub_app, credit_json, master_sig }

步骤3：钱包服务验证
  ├─ 用 wallet_address 对应的公钥验证 master_sig
  ├─ 解析 credit_json，校验 expire_at 未过期
  └─ ECDH 解密得到 Share B 明文

步骤4：转存至平台云服务
  ├─ 钱包服务用平台云服务公钥重新加密 Share B
  ├─ 将加密后的 Share B 推送至平台云服务（绑定 credit_id + wallet_address）
  ├─ 平台云服务存储成功后，钱包服务内 Share B 明文立即销毁
  └─ 返回 { credit_id, expire_at }
```

### 10.4 Agent 签名执行流程

```
AI Agent 提交订单请求
  { credit_id, order_type, chain, token, amount, ... }
        ↓
钱包服务风控模块校验（见 §10.5）
        ↓ 通过，签发 ApprovedToken
        ↓ vsock
┌──────────────────────────────────────────────────────┐
│                  Nitro Enclave                       │
│                                                      │
│  ① 验证 ApprovedToken（HMAC + 有效期 + nonce 唯一性） │
│  ② TLS → 宿主 TCP relay → PrivateLink → 平台云宿主  │
│     附 NSM Attestation，平台云验证 PCR 后返回 Share B │
│  ③ E2E TLS → 宿主 TCP relay → KMS                   │
│     （KMS key policy 验证 PCR Attestation，返回 C）   │
│  ④ Share B + Share C → Lagrange 插值 → Master Seed  │
│  ⑤ BIP44 派生目标链私钥                              │
│  ⑥ 签名交易                                          │
│  ⑦ memzero：Master Seed、私钥、Share B 全部销毁      │
│  ⑧ 返回 signature via vsock                         │
└──────────────────────────────────────────────────────┘
        ↓ 返回签名
广播交易
        ↓
更新活跃度计时（刷新 7 天窗口）
```

> 每次签名均现场重建私钥，不在服务端持久化存储派生私钥。设计原理见 §3.5。
> Share B 存于平台云服务，Share C 存于钱包服务 KMS，两者分离，需同时攻破才能还原密钥。
> Nitro Enclave 保证即使钱包服务宿主进程被完全入侵，攻击者也无法从内存中读取私钥材料。

### 10.5 风控模块

**架构决策：风控以进程内 library 内嵌，而非独立服务。**

若风控作为独立微服务，钱包服务通过内部 API 调用它，则存在以下风险：
- 内部 API 被攻破或绕过后，签名请求可直接到达密钥操作层，风控形同虚设
- 网络层中间人可以在钱包服务与风控服务之间篡改校验结果

内嵌为 library 后：
- 风控代码与签名请求调度在同一进程内，是同一调用链上的强制路径，无法绕过
- 无跨进程通信，无额外信任边界
- 规则更新需重新部署钱包服务（可接受，规则变更本身也需要审计）

#### 服务间信任模型与高危操作凭证

**同 VPC 不等于同信任级别。** 钱包服务是系统的最后一道防线，不能因上游是内部服务就完全信任其请求。若用户服务 / 交易服务被攻破或存在内鬼，攻击者只需持有 inter-service signing key，即可跳过 Passkey / 2FA 直接向钱包服务发起恢复、导出、删除请求。因此，钱包服务必须具备独立验证能力，而非仅凭 inter-service token 就执行密钥操作。

**OperationToken（服务间操作凭证）**

上游服务完成自身校验后，为本次操作签发结构化短生命周期凭证，随请求传至钱包服务：

| 字段 | 说明 |
|------|------|
| `operation` | 操作类型（`recover_wallet` / `export_wallet` / `delete_wallet` / `agent_activate` 等），钱包服务核对与实际请求一致 |
| `user_id` / `wallet_address` | 操作主体，防止跨用户伪造 |
| `verified_methods` | 本次已完成的验证方式列表（如 `["passkey", "email_otp"]`） |
| `verified_at` / `exp` | 签发时间 + 过期时长；一般操作 5 分钟，恢复操作 15 分钟（用户需时完成 iCloud/QR PIN 输入） |
| `request_hash` | SHA256(请求体)，防中间人替换请求内容 |

钱包服务逐项独立验证：Token 签名合法、`operation` 与请求匹配、`verified_methods` 满足本操作的最低要求、`exp` 未超期、`request_hash` 一致。任一不符则拒绝，记录审计日志。

**高危操作（恢复 / 导出 / 删除）：两条验证路径**

用户使用的 2FA 方式不同，钱包服务的独立验证能力也不同：

**路径一：Passkey 认证（推荐，安全等级更高）**

Passkey assertion 由设备硬件私钥（Secure Enclave / StrongBox）签名，任何持有用户公钥的服务均可独立验证，不依赖用户服务的声明。App 将原始 assertion 透传至钱包服务：

```
App（设备硬件签名）──→ 用户服务（校验 + 签发 OperationToken）──→ 钱包服务
raw passkey assertion ─────────────────────────────────────────→ 钱包服务独立 re-verify
```

即使用户服务整个被控制，钱包服务也能独立判断请求是否来自真实用户设备，从而识别内鬼伪造的请求。

**路径二：Email + TOTP 认证（降级路径）**

OTP 是一次性凭证，由用户服务消费后即失效，钱包服务无法取得原始凭证重新验证。此路径钱包服务只能信任 inter-service signed OperationToken，信任根从「设备硬件」退化为「用户服务诚信 + inter-service key 安全性」。

| 维度 | Passkey 路径 | Email + TOTP 路径 |
|------|------------|-----------------|
| 钱包服务能否独立验证凭证 | 能（re-verify assertion） | 不能（OTP 已消费） |
| 用户服务被攻陷的影响 | 钱包服务仍可识别伪造请求 | 攻击者可伪造合法 token |
| 信任根 | 用户设备硬件 + 密码学 | 用户服务 + inter-service key |
| 恢复操作限频 | 30 天 ≤ 3 次 | 30 天 ≤ 2 次（更严） |

两条路径的安全等级差异是 OTP 类认证的固有局限，行业普遍接受。补偿措施：Email+TOTP 路径限频更严，且 `verified_methods` 在 OperationToken 和审计日志中均明确记录，便于事后区分。

> **关于导出操作：** §八的导出（Keyless → 标准私钥钱包）是客户端本地用 A+B 重建助记词，服务端只接收"已导出"通知并软删除分片，私钥/助记词全程不经过服务端，因此导出通知接口接受 Email+TOTP 路径。Bot 钱包升级（B+C → A）本质是恢复操作的变体，同样接受 Email+TOTP。若将来出现**服务端直接下发完整私钥或助记词**的场景，则该场景必须强制 Passkey。

**Inter-service Signing Key 管理**

| 权限 | 持有方 |
|------|-------|
| 签发 OperationToken（KMS Sign 调用权） | 用户服务 / 交易服务运行时 IAM 角色 |
| 验证 OperationToken（KMS Verify 调用权） | 钱包服务运行时 IAM 角色 |
| 密钥管理 / 轮换 | 独立安全团队，两个业务团队均无法单独访问私钥原文 |

两个团队分别只有"签发"或"验证"权限，任何一方单独都无法伪造合法 Token，也无法静默修改验证逻辑。

**钱包服务独立审计日志**

钱包服务维护独立的不可篡改审计日志（只有钱包服务进程可写），每笔密钥操作记录：操作类型、user_id、wallet_address、OperationToken 摘要、passkey assertion 指纹、时间戳、调用来源。不依赖上游服务日志。出现纠纷时，各方日志独立作证，权责清晰——用户服务的日志说明"谁做了验证"，钱包服务的日志说明"谁触发了密钥操作"。

#### ApprovedToken：风控与 Enclave 的信任桥接

风控在宿主进程校验通过后，向 Nitro Enclave 签发一个**短生命周期的一次性凭证**，防止宿主进程在被入侵时伪造签名请求绕过风控。具体数据结构待实现阶段确定。

Enclave 收到请求后先验证凭证合法性（完整性 + 有效期 + 防重放），任一验证失败则拒绝所有密钥操作，不返回任何错误细节（防探测）。

风控模块按业务流程分层校验，拦截非法请求并记录不可篡改审计日志。

#### 通用基础校验（所有接口）

| 校验项 | 规则 | 失败处理 |
|--------|------|---------|
| 账号 Token 有效性 | JWT 未过期、签名合法 | 拒绝，返回 401 |
| 账号状态 | 账号未封禁、未处于冻结状态 | 拒绝，返回 403 |
| DDoS 粗粒度防护 | 同一 IP 每分钟超过 500 次请求视为洪泛 | 封禁 IP，返回 429 |
| 请求防篡改 | 关键接口校验请求体 HMAC 签名 | 拒绝，记录告警 |

#### 分级限频策略

不同风险等级的接口使用独立限频规则，不混用同一配额：

| 接口类别 | 风险等级 | 限频维度 | 限制规则 | 超限处理 |
|---------|---------|---------|---------|---------|
| Agent 开通（Share B 上传） | 中 | 单钱包 / 24h | ≤ 5 次 | 拒绝，记录告警 |
| 密钥恢复 / Bot 升级（B 上传服务端取新 A） | 高 | 单账号 / 30天 | Passkey 路径 ≤ 3 次；Email+TOTP 路径 ≤ 2 次 | 冻结账号恢复功能，需人工审核 |
| Keyless 导出（§八，状态转换通知） | 中 | 单钱包 / 生命周期 | ≤ 1 次（硬限制，导出后 B/C 进入软删除） | 拒绝 |
| 导出请求（含失败） | 中 | 单账号 / 24h | ≤ 3 次 | 拒绝，记录告警 |
| 删除 / 紧急冻结 | 高 | 单账号 / 24h | ≤ 5 次 | 拒绝，记录告警 |

> 高风险接口的限频计数在失败请求时同样递增，防止通过反复失败试探绕过限制。

#### Agent 开通校验（Share B 上传时，§10.3）

| 校验项 | 规则 | 失败处理 |
|--------|------|---------|
| master_sig 验证 | 用 wallet_address 公钥验证 hash(credit_json + share_b) 签名 | 拒绝 |
| credit_json 格式 | 字段完整、allowed_order_types 枚举值合法 | 拒绝 |
| expire_at 合法性 | 未过期，且有效期 ≤ 30 天（防止设置超长授权） | 拒绝 |
| 账号下钱包归属 | wallet_address 必须属于当前登录账号 | 拒绝 |
| 开通频率限制 | 见分级限频策略（单钱包 / 24h ≤ 3 次） | 拒绝，记录告警 |
| Share B 尺寸合法性 | 分片字节长度符合预期（16 或 32 字节） | 拒绝 |

#### Agent 签名校验（每次自动签名，§10.4）

| 校验项 | 规则 | 失败处理 |
|--------|------|---------|
| Session Credit 有效性 | credit_id 存在、未过期、未被撤销 | 拒绝，通知 App |
| 订单类型许可 | order_type ∈ credit.allowed_order_types | 拒绝 |
| 请求签名验证 | 校验 AI Agent 请求携带的 credit_id + 请求体签名 | 拒绝 |
| 异常检测（告警） | 短时高频、金额突变、目标地址首次出现等触发告警 | 仅告警，不自动拒绝，人工介入 |

#### 恢复流程校验（§7.4，Bot 升级同）

> Bot 钱包升级（B+C → A）与标准恢复走相同接口和风控规则，不另建独立校验。

| 校验项 | 规则 | 失败处理 |
|--------|------|---------|
| OperationToken 验证 | Token 签名合法（inter-service key）、operation=recover_wallet、exp 未超期、request_hash 一致 | 拒绝 |
| 身份凭证验证 | **Passkey 路径**：独立 re-verify passkey assertion（不依赖用户服务声明）；**Email+TOTP 路径**：OTP 已消费，信任 inter-service signed token | 拒绝 |
| 钱包归属验证 | 该 wallet_address 必须在账号历史记录中存在 | 拒绝 |
| 恢复频率限制 | Passkey 路径：单账号 / 30天 ≤ 3 次；Email+TOTP 路径：单账号 / 30天 ≤ 2 次 | 超限冻结，需人工客服审核 |
| Share B 有效性 | 上传的 B 能与 C 完成 Lagrange 插值（快速验证，不暴露 C） | 拒绝，记录告警 |

#### 导出流程校验（§8.1，Keyless → 标准私钥钱包状态转换通知）

> 助记词重建在客户端本地完成（A+B Lagrange），服务端仅接收状态转换通知并软删除分片，无私钥/助记词经过服务端。

| 校验项 | 规则 | 失败处理 |
|--------|------|---------|
| 身份验证 | OperationToken 验证；**Passkey 路径**独立 re-verify assertion；**Email+TOTP 路径**信任 token | 拒绝 |
| 导出次数限制 | 同一钱包仅允许导出 1 次（Share C 软删除后不可再导出） | 拒绝 |
| Share C 状态 | Share C 必须处于正常状态（未软删除、未物理删除） | 拒绝 |
| 导出频率限制 | 见分级限频策略（单账号 / 24h ≤ 3 次，含失败） | 超限拒绝，记录告警 |
| 操作审计 | 导出确认、撤销导出均写入不可篡改审计日志 | — |

#### 删除流程校验（§7.5）

| 校验项 | 规则 | 失败处理 |
|--------|------|---------|
| 身份验证 | OperationToken 验证；Passkey 路径独立 re-verify assertion；Email+TOTP 路径信任 token | 拒绝 |
| 紧急冻结验证 | 账号登录态有效 + 2FA（场景二被盗场景） | 拒绝 |
| 钱包归属验证 | 待删除钱包属于当前账号 | 拒绝 |
| 操作审计 | 删除操作写入不可篡改审计日志 | — |

### 10.6 关闭 Agent 签名流程

Agent 授权关闭有三种触发方式，但核心处理逻辑相同：删除平台云 Share B、撤销 Session Credit。

**触发方式：**

| 触发条件 | 触发方 | 说明 |
|---------|-------|------|
| 用户在 App 手动关闭 | 用户主动 | 最常见路径，需 Passkey 验证 |
| 连续 7 天无 Agent 交易 | 系统自动 | 活跃度检测，静默关闭 |
| Session Credit 到期未续签 | 系统自动 | Credit 过期后 Agent 无法再签名 |

注：连续 7 天无 Agent 交易关闭和Session固定时长关闭需要用户来二选一（需产品确定）

**关闭执行流程（以用户主动关闭为例）：**

```
用户在 App 点击"关闭 Agent 交易"
    │
    ├─ 1. 身份验证
    │       └─ Passkey 验证（生物识别）
    │
    ├─ 2. Share B 处理（按平台云备份状态分两种情况）
    │
    │   情况一：用户已开启平台云助记词备份
    │       └─ Share B 由备份流程管理，此处【不删除】
    │          （用户助记词已备份至平台云，Share B 作为备份分片保留）
    │
    │   情况二：用户未开启平台云助记词备份
    │       └─ 钱包服务通知平台云服务【软删除 Share B】（30 天后物理删除）
    │          （软删除期间系统拒绝访问，安全性等价于立即删除）
    │
    ├─ 3. 撤销所有 Session Credit
    │       ├─ 当前所有有效 credit_id 标记为已撤销
    │       └─ AI Agent 持有的 Credit 立即失效，后续签名请求全部拒绝
    │
    ├─ 4. 状态更新
    │       └─ 钱包记录：agent_enabled = false
    │
    └─ 5. 写入审计日志（操作人、时间、触发方式）

> ⚠️ **Share C 不在此处删除**。Share C 是钱包服务的长期恢复分片，钱包恢复流程（§7.4）依赖 B+C 重建 Master Seed。
> 关闭 Agent 只是停止自动交易授权，钱包本身仍存在，Share C 需跟随钱包生命周期管理：
> 删除钱包（§7.5）或导出私钥（§8.1）时才软删除 Share C。

关闭后本地 TEE 仍保有 Share A 及预派生私钥，本地签名功能（见 §九）不受影响。
如需重新开启 Agent，须重走 §10.2–§10.3 授权 + 上传流程。
```

**系统自动关闭（活跃度 / Credit 到期）：**

```
系统检测触发条件满足
    ├─ 执行步骤 2–4（同上，跳过 Passkey 验证）
    └─ 推送通知用户："Agent 交易已因长期不活跃/授权过期自动关闭"
```

### 10.7 紧急安全响应

> 若检测到 Share B 存储可能遭受泄露或攻击，由**后端安全团队手动触发**紧急处置。

```
自动检测（报警）：
  监控异常访问模式 → 触发告警通知安全团队

安全团队人工确认后执行：
  ├─ 一次性软删除所有用户的 Share B（立即禁止访问，30 天后物理删除）
  ├─ 关闭全平台 Agent 自动交易
  ├─ 通知所有受影响用户
  └─ 事后审查，修复漏洞后方可重新开放

注：自动检测只做报警，不自动删除，避免误触发影响正常用户。
注：软删除后 Share B 即不可被访问，安全性等同物理删除；30 天缓冲期允许事后审计和必要时的数据取证。
```

---

### 10.8 Enclave 跨账号访问平台云的网络与认证方案

#### 核心问题

Nitro Enclave **没有网络接口**，vsock 只能连接到宿主 EC2，无法直接访问其他服务器。平台云运行在另一个 AWS 账号，Enclave 必须借道宿主才能访问。宿主是不可信的，因此需要一套机制保证：**宿主无法伪造平台云的响应，也无法拦截 Share B 明文**。

```
Enclave → vsock → 宿主 EC2（TCP relay）→ 网络 → 平台云服务
          ↑
     唯一出口，宿主可见流量，但不可解密
```

#### 两层安全保证

**第一层：E2E TLS（传输层保密）**

TLS 在 Enclave 内部发起和终止，宿主只做透明 TCP 字节转发：

```
┌──────────────────────────────────────────────────────────────┐
│  Nitro Enclave                                               │
│  - 生成临时 TLS 密钥对（私钥永不出 Enclave）                 │
│  - 验证平台云服务器证书（内置平台云 CA 公钥）                │
│  - TLS 握手、加密传输 → 宿主只看到密文字节流                │
└──────────────────────────────────────────────────────────────┘
              ↕ 加密字节（宿主无法解密）
┌──────────────────────────────────────────────────────────────┐
│  宿主 EC2（TCP relay，仅转发字节，不终止 TLS）               │
└──────────────────────────────────────────────────────────────┘
              ↕ 加密字节（与 Enclave 侧完全一致）
┌──────────────────────────────────────────────────────────────┐
│  平台云服务（TLS 终止端）                                    │
│  - 持有服务器私钥，解密 TLS → 读取请求内容                   │
│  - 返回 Share B（加密在 TLS 内）                             │
└──────────────────────────────────────────────────────────────┘
```

宿主即使被完全入侵，也只能看到密文，无法得到 Share B 明文。

**第二层：NSM Attestation（身份认证）**

仅靠 TLS 还不够——平台云需要验证"发出请求的确实是合法 Enclave，而非伪装的宿主进程"。Enclave 在每次请求中附带 **NSM Attestation Document**：

```
NSM Attestation Document（由 AWS Nitro Security Module 签发）：
  - PCR0：Enclave 镜像哈希（代码度量值）
  - PCR1：内核 + 启动配置哈希
  - PCR2：应用层哈希
  - AWS 根 CA 签名（不可伪造）
```

平台云服务收到请求后：

```
① 验证 Attestation Document 的 AWS 签名（Nitro 根证书链）
② 检查 PCR0/1/2 与预期镜像哈希一致（防止运行非法镜像）
③ 验证通过 → 按 credit_id 返回对应 Share B
④ 任一验证失败 → 拒绝，不返回任何分片内容
```

宿主进程拿不到 NSM 签发的 Attestation Document（NSM 只响应 Enclave 内部调用），因此无法伪造合法请求。

#### 网络通道：AWS PrivateLink 跨账号私网

平台云（另一 AWS 账号）通过 **AWS PrivateLink** 暴露私有服务端点，钱包服务所在 VPC 创建对应的 Interface Endpoint，流量全程走 AWS 内部私网，不经过公网：

```
钱包服务 VPC（账号 A）                    平台云 VPC（账号 B）
┌─────────────────────────┐              ┌──────────────────────────┐
│                         │              │                          │
│  EC2 宿主               │              │  平台云服务               │
│  └─ Nitro Enclave       │              │  (Share B 存储)           │
│       ↓ vsock           │              │       ↑                  │
│  TCP relay              │              │  NLB（Network LB）        │
│       ↓                 │              │       ↑                  │
│  Interface Endpoint ────┼──PrivateLink─┼── Endpoint Service       │
│  (VPC Endpoint)         │   私网通道   │                          │
└─────────────────────────┘              └──────────────────────────┘
```

| 属性 | 说明 |
|------|------|
| 网络路径 | 全程 AWS 内部私网，不走公网，无公网 IP 暴露 |
| 跨账号授权 | 平台云账号在 Endpoint Service 配置中白名单钱包服务账号 |
| 流量方向 | 单向：钱包服务 VPC → 平台云，平台云无需访问钱包服务 VPC |
| 与 TLS 叠加 | PrivateLink 保证网络层隔离，TLS + Attestation 保证应用层身份可信 |

#### 平台云侧访问控制

平台云对每次 Share B 请求做以下校验（独立于钱包服务的风控，形成双重防线）：

| 校验项 | 说明 |
|--------|------|
| Attestation 签名合法性 | AWS Nitro 根 CA 签名验证，防伪造 |
| PCR 值白名单 | 仅接受已登记镜像哈希，Enclave 代码变更需重新登记 |
| credit_id 有效性 | 对应 Session Credit 未过期、未撤销 |
| 请求频率限制 | 同一 credit_id 单位时间内请求次数上限，防 Enclave 被滥用重复取 B |
| PrivateLink 来源限制 | 仅接受来自白名单 VPC Endpoint 的请求，拒绝公网访问 |

---

## 十一、Session Credit 授权许可设计

### 11.1 Session Credit 是什么

Session Credit 是用户提交给后端的一份**授权许可**，许可后端在持有 Share B + Share C 的情况下，代替用户执行特定范围内的 Agent 自动交易签名。

Session Credit 本身不是密钥，也不是网络会话连接，它是一份**有范围、有时效的权限凭证**：
- **许可什么**：允许后端做哪类订单（限价单、止盈止损、跟单……）
- **许可多久**：有效期到期后后端必须删除 Share B，不得再签名

### 11.2 Session Credit 数据结构

```json
{
  "credit_id": "uuid",
  "wallet_address": "0x...",
  "created_at": 1735689600,
  "expire_at":  1735776000,

  "allowed_order_types": [
    "limit_order",
    "take_profit",
    "stop_loss",
    "copy_trade"
  ],

  "user_signature": "0x..."
}
```

| 字段 | 说明 |
|------|------|
| `credit_id` | 唯一标识，用于后端查找对应的 Share B |
| `wallet_address` | 授权的钱包地址（对应 Master Key） |
| `created_at / expire_at` | Unix 时间戳；到期后后端软删除 Share B（30 天后物理删除）,如果不限制expire_at, 则启动7天不活跃自动删除 |
| `allowed_order_types` | 允许执行的订单类型枚举，后端不得执行列表之外的操作 |
| `user_signature` | 用户用 Master Key 对 `credit_id + expire_at + allowed_order_types` 的签名，后端验证授权真实性 |

### 11.3 有效期规则

- 默认有效期：**7天**（用户可在 App 自定义，最长 30 天）
- 到期后后端 **必须通知平台云服务软删除 Share B**（30 天后物理删除），不得自动续期，延长续期需用户重新授权上传新 Share B
- 用户可随时主动撤销（发送 revoke 请求，后端立即通知平台云服务软删除 Share B，30 天后物理删除）

---

## 十二、Bot 钱包升级方案（完整私钥托管 → SSS 分片）

### 12.1 现有 Bot 钱包架构与痛点

Bot 钱包目前以**完整助记词加密存储于钱包服务 KMS**，无分片，存在以下风险：

| 问题 | 说明 |
|------|------|
| 钱包服务单点故障 | 钱包服务数据丢失即永久失去所有 Bot 钱包密钥 |
| KMS 账号单点风险 | KMS 账号密码泄露或账号被盗，所有密钥面临暴露 |
| 无法安全导出助记词 | 完整私钥传输链路风险极高，一旦传输即有泄露窗口 |
| 无冗余恢复路径 | 单一存储无备份，KMS 故障无兜底方案 |

### 12.2 升级目标与设计原则

**核心思路：** 将 Bot 钱包助记词改为 **2-of-2 SSS 分片存储**，分别托管于平台云服务（Share B）和钱包服务 KMS（Share C），与无私钥钱包的 Agent 签名存储和签名逻辑保持一致，消除单点风险。

**与无私钥钱包（Keyless SSS）的差异：**

| 维度 | Keyless SSS 钱包 | Bot 钱包（升级后） |
|------|----------------|----------------|
| 分片数量 | 2-of-3（A/B/C） | **2-of-2（B/C）** |
| Share A | 存用户设备 TEE | **不存在**（无本地设备） |
| 本地签名 | 支持（设备 TEE 直接签） | **不支持**，仅远程签名 |
| Agent/Bot 签名 | B（平台云）+ C（KMS）→ 现场重建 | 同左，逻辑完全复用 |
| 助记词导出 | 本地 A + B → 重建 | 需先由服务端 B + C → 生成 A，下发用户后本地导出（见 §12.6） |
| 导出后状态 | 转为普通 EOA 钱包 | 同左，不再作为 Bot 钱包使用 |

**设计原则：**
- 签名链路与无私钥钱包 Agent 签名完全复用（§10.3 / §10.4），不引入新的签名逻辑
- 两份分片分离存储于独立系统，需同时攻破才能还原助记词
- 导出路径通过 Keyless 恢复逻辑生成 Share A 下发用户，服务端不做明文传输

### 12.3 SSS 分片方案设计

#### 分片参数

| 参数 | 值 |
|------|-----|
| 算法 | Shamir Secret Sharing，一次多项式 f(x) = S + a₁·x |
| 门限 | **2-of-2**（两份分片均需参与重建，无 Share A） |
| 分片对象 | BIP39 助记词熵（16 / 32 字节），与 Keyless 钱包一致 |
| Share B (x=2) | 平台云服务（KMS 加密存储） |
| Share C (x=3) | 钱包服务 KMS |

#### 分片运算（迁移时执行一次）

```
步骤1：钱包服务从 KMS 解密当前完整助记词熵 S（在进程内存中）

步骤2：SSS 分片运算（进程内执行）
  ├─ 随机生成 a₁
  ├─ Share B = f(2) = S + 2·a₁  （x=2，与 Keyless 钱包 Share B 坐标一致）
  └─ Share C = f(3) = S + 3·a₁  （x=3，与 Keyless 钱包 Share C 坐标一致）

步骤3：验证分片正确性（删除原始密钥前必须验证）
  ├─ 用 Share B + Share C 做 Lagrange 插值还原 S'
  └─ 断言 S' == S，验证失败则中止迁移，不删除原始密钥

步骤4：分片落地存储
  ├─ Share B → 用平台云服务公钥加密 → 推送至平台云 KMS 存储
  └─ Share C → 写入钱包服务 KMS（替换原完整密钥条目）

步骤5：清理
  ├─ 从钱包服务 KMS 删除原完整助记词熵记录
  └─ 内存中的 S、a₁、Share B、Share C 明文立即销毁
```

> 整个分片过程在钱包服务进程内完成，助记词熵明文不经过任何网络传输。
> 步骤3 的验证是强制步骤，确保分片可用后才销毁原始密钥。

#### 重建运算（每次 Bot 签名时执行）

与无私钥钱包 Agent 签名完全复用（§10.4），无新增逻辑，同样经由 Nitro Enclave 执行：

```
钱包服务风控通过 → 签发 ApprovedToken → vsock → Nitro Enclave
    ↓ Enclave 内
取 Share B（x=2，平台云）+ 取 Share C（x=3，KMS，PCR 绑定）
    ↓
Lagrange 插值（GF-256，与 Keyless 钱包 §10.4 代码完全复用）：
  a₁ = Share C ⊕ Share B          （GF-256 减法 = 异或；分母 3⊕2=1 可约）
  S  = Share B ⊕ (a₁ ⊗ 2)        （即 3·Share_B ⊕ 2·Share_C，GF 乘法）
    ↓
BIP44 派生目标链私钥 → 签名 → 私钥与 S 立即销毁（全程在 Enclave 内存中）
```

### 12.4 存量私钥迁移方案

迁移分两条并行轨道：**存量迁移**（历史数据）+ **增量同步**（迁移期间新增数据），两者同时运行直至全量完成。

#### 存量迁移

```
离线迁移任务（批量扫描钱包表）：

步骤1：按钱包表自增 ID 分批读取未迁移记录
  ├─ 每批 N 条（待定，根据 KMS 吞吐限制调整）
  ├─ 记录当前处理的最大 ID（断点续跑）
  └─ 跳过已完成分片的记录（status = migrated）

步骤2：对每条记录执行 §12.3 分片运算
  ├─ KMS 解密 → SSS 分片 → 验证 → B 存平台云 / C 存钱包服务 KMS
  └─ 成功后：钱包表该记录状态置为 migrated，原完整密钥标记 pending_delete

步骤3：失败处理
  ├─ 单条失败：记录错误日志，跳过，继续下一条
  └─ 连续失败超阈值：暂停任务，告警通知，人工介入
```

#### 增量同步服务

迁移存量期间，新创建的 Bot 钱包仍以完整密钥写入 KMS（保持现有逻辑不变），由独立**增量同步服务**持续追赶：

```
增量同步服务（持续运行）：

  轮询逻辑：
  ├─ 记录上次同步的最大钱包 ID（watermark）
  ├─ 定期查询钱包表：id > watermark AND status != migrated
  ├─ 对新增记录执行与存量相同的分片流程（§12.3）
  └─ 更新 watermark

  与存量迁移任务的协作：
  ├─ 存量任务负责 id ≤ 存量截止 ID 的记录
  ├─ 增量服务负责 id > 存量截止 ID 的新增记录
  └─ 两者通过 status 字段互不干扰
```

#### 完整密钥保留与延迟清除

| 阶段 | 说明 |
|------|------|
| 迁移中 | 原完整密钥保持可用，分片完成后标记 `pending_delete` |
| 全量迁移完成后 | 进入**观察期（至少 60 天）**，完整密钥保留，分片签名正式上线，灰度验证 |
| 观察期内发现问题 | 可随时回滚：切回读取完整密钥签名，分片记录保留不删 |
| 观察期结束、验证无问题 | 执行物理删除原完整密钥，迁移完成 |

> **原完整密钥至少保留 60 天后再物理删除**，为分片签名提供充足的灰度验证窗口和回滚缓冲期。

#### 回滚方案

```
触发条件：分片签名失败率超阈值，或平台云服务出现故障

回滚步骤：
  1. 关闭分片签名开关（feature flag），切回读完整密钥签名
  2. 完整密钥在 pending_delete 状态下仍可读取，业务无感知
  3. 排查分片问题，修复后重新灰度验证
  4. 无需重新迁移（分片数据保留），修复后直接重新开启开关
```

### 12.5 用户侧变化与操作流程

#### 整体过渡策略

Bot 钱包不做强制下线，采用**渐进式共存**策略，分三个阶段：

```
阶段一：无私钥钱包上线（Bot 钱包保持现状）
  ├─ 新用户引导优先创建无私钥钱包（Keyless SSS）
  ├─ 老用户可选择性开通无私钥钱包
  └─ Bot 钱包继续正常运行，用户无感知变化

阶段二：Bot 钱包完成分片迁移（§12.4），双跑观察
  ├─ Bot 钱包底层切换为分片签名，用户功能不变，产品侧名称显示不变
  ├─ 无私钥钱包与 Bot 钱包同时可用
  └─ 双跑观察期（建议 60 天以上），监控分片签名稳定性

阶段三：由产品决策（以下两条路二选一）

  路线 A：保持存量 Bot 钱包长期共存
  ├─ Bot 钱包继续正常展示和使用，不强制下线
  ├─ 停止新建 Bot 钱包入口（新用户只能创建无私钥钱包）
  └─ 用户可自主选择升级路径（见下方升级方案），平台不施压

  路线 B：引导存量 Bot 钱包统一升级
  ├─ 给予足够迁移缓冲期（建议 3 个月），在 App 内公告
  ├─ 提供一键升级入口（Bot → Keyless 或 Bot → EOA），详见下方升级方案
  └─ 缓冲期结束后关闭 Bot 钱包签名服务
```

> **产品决策点：** 路线 A/B 的选择取决于存量用户规模、运营成本以及风险偏好，技术上两条路线均已支持。

---

#### Bot 钱包升级路径

Bot 钱包完成分片迁移后，支持两种升级目标。**升级不涉及资产转移，链上地址和私钥完全不变，仅改变钱包管理模式。**

---

**升级路径一：Bot 钱包 → 无私钥钱包（Keyless SSS）**（推荐）

Bot 钱包已有 Share B（x=2，平台云）和 Share C（x=3，钱包服务 KMS），只需服务端从现有多项式计算出 Share A 并下发设备即可完成升级，**无需重新分片，无需链上操作**。

复用 §7.4 两步恢复接口，流程一致：

```
步骤1：强身份验证
  └─ Passkey 验证 + 二次确认

步骤2：客户端提交升级请求（API 1：submit）
  ├─ 客户端生成临时 ECDH 密钥对 (ePub_client, ePriv_client)
  └─ 服务端：
       ├─ 从平台云取 Share B（x=2），从 KMS 读取 Share C（x=3）
       ├─ Lagrange 插值恢复 S 及系数 a₁
       ├─ 生成新坐标 x=n，计算 A = f(n)（GF-256）
       ├─ 用 ePub_client 加密 A，存入短期缓存
       ├─ S、a₁ 及中间值立即销毁
       └─ 返回 { recovery_token }（5 分钟有效，单次可用）

步骤3：客户端二次确认后领取 Share A（API 2：claim）
  ├─ Passkey 生物识别确认弹窗
  └─ 服务端返回 { enc_A, new_x }，recovery_token 立即失效

步骤4：设备本地存储 Share A
  ├─ 用 ePriv_client 解密得到 Share A 明文
  ├─ Share A 写入设备 TEE
  └─ 内存中明文立即清除

步骤5：钱包类型切换
  ├─ 服务端将该钱包标记为 Keyless SSS 模式
  ├─ Share B（x=2）、Share C（x=3）原地保留，无需替换
  └─ 用户从此可用设备 TEE 本地签名，也可继续使用 Agent 远程签名
```

> 升级后 Bot 签名链路（B+C）与 Keyless Agent 签名链路完全相同，**服务端无新增逻辑**。

---

**升级路径二：Bot 钱包 → 本地 EOA 钱包**

适合希望完整自主掌握私钥、不再使用平台 Agent 功能的用户，流程见 §12.7。

升级后：Agent 自动交易功能关闭，平台软删除 Share B / C（30 天缓冲期后物理删除），钱包转为标准本地助记词钱包。

---

#### 用户操作说明

| 用户类型 | 可选操作 | 平台侧支持 |
|---------|---------|---------|
| 新用户 | 直接创建无私钥钱包 | 新建入口不再提供 Bot 钱包选项 |
| 存量用户（想保留 Agent 能力） | 一键升级为无私钥钱包（路径一） | 提供升级入口；升级后 Agent 签名 + 本地签名均可用 |
| 存量用户（想自主掌控私钥） | 导出为本地 EOA 钱包（路径二，§12.7） | 提供导出入口；导出后 Agent 功能关闭 |
| 不操作的用户 | 继续使用 Bot 钱包（仅路线 A 下长期有效） | 存量展示和 Agent 签名保持可用 |

> 无论选择哪条升级路径，钱包地址均不变，链上资产无需移动。

### 12.6 风险评估与应急预案

#### 迁移过程风险

| 风险 | 描述 | 严重程度 |
|------|------|---------|
| 分片验证失败 | SSS 分片后重建结果与原始密钥不一致，迁移中止 | 高 |
| KMS 读写失败 | KMS 接口异常，导致原始密钥无法解密或 Share C 无法写入 | 高 |
| 平台云写入失败 | Share B 未能成功存入平台云，分片不完整 | 高 |
| 状态不一致 | 分片写入成功但 status 字段未更新，重复迁移覆盖已有分片 | 中 |
| 增量同步延迟 | 新建 Bot 钱包长时间未完成分片，仍以完整密钥签名 | 低 |

**应急预案：迁移写入失败**

```
步骤1：暂停迁移任务，停止新的分片写入

步骤2：签名模式回退（防止分片不完整导致签名失败）
  ├─ 将签名开关（feature flag）全局切回"完整密钥签名"模式
  ├─ 已完成迁移的钱包也暂时走回完整密钥签名
  └─ 用户签名业务不中断，无感知

步骤3：清理分片存储
  ├─ 清除平台云中本次迁移写入的 Share B 记录
  ├─ 清除钱包服务 KMS 中本次迁移写入的 Share C 记录
  └─ 将钱包表相关记录 status 重置为 pending

步骤4：排查失败原因，修复后重新运行迁移任务
  ├─ 存量迁移从上次 watermark 断点重跑
  └─ 增量同步服务随之重新追赶

步骤5：迁移全量完成并验证后，逐步切回分片签名模式
  ├─ 灰度放量：先切 5% → 20% → 100%
  └─ 每阶段观察签名成功率，无异常再继续放量
```

> 核心原则：完整密钥在观察期内始终保留且可用，签名模式回退随时可执行，迁移失败不影响用户业务连续性。

#### 存储安全风险

分片存储延续现有 KMS 加密方案，平台云与钱包服务 KMS 各持一片，单独泄露均无法还原密钥，安全性优于原有完整密钥单点存储。只要维持好 KMS 访问控制和密钥轮换策略，整体风险可控。

#### 签名可用性风险

平台云或 KMS 任一故障均会影响签名，与原有方案的 KMS 单点依赖性质相同。应对措施：做好服务健康检查与报警，出现异常及时介入修复；观察期内完整密钥保留，必要时快速回退签名模式。

#### 完整密钥清理风险

60 天观察期结束后执行删除时，若分片签名存在潜在问题尚未暴露，物理删除后将无法回滚。

应对措施：采用**两阶段删除**，在 60 天观察期结束后不直接物理删除，先执行软删除（标记 `deleted`，停止读取），再经过 60 天确认无问题后，才执行物理清理。

```
完整密钥删除时间轴：

  分片迁移完成
       ↓
  [观察期 60 天] 分片签名灰度验证，完整密钥保留可用
       ↓
  软删除：完整密钥标记 deleted，签名链路不再读取
       ↓
  [缓冲期 60 天] 持续观察，如有问题可恢复软删除记录
       ↓
  物理清理：从 KMS 永久删除完整密钥
```

> 物理清理需经审批方可执行，不允许单人操作。

### 12.7 Bot 钱包私钥导出流程

Bot 钱包无设备 TEE，无 Share A，导出时需由**服务端先用 B + C 生成 Share A**，经 ECDH 加密下发用户设备，用户在本地完成助记词重建和导出。复用 §7.4 两步恢复接口，仅入口不同。

```
步骤1：身份验证（用户服务）
  ├─ 2FA 验证（Passkey 优先，Email + 谷歌验证器备用）
  ├─ 弹出风险提示：
  │    "导出后钱包将转为本地 EOA 钱包，不再享有 Bot 自动交易能力。
  │     平台将在 30 天缓冲期后永久删除分片，操作不可逆。"
  └─ 签发 OperationToken（operation=recover_wallet, exp=15min）

步骤2：App 从平台云拉取 Share B（接口调用 1：平台云）
  ├─ App → POST /platform/share_b/download { wallet_address, jwt }
  ├─ 平台云验证账号身份，ECDH 加密 Share B 后下发
  └─ App 解密得到 Share B 明文，暂存内存

步骤3：App 提交加密 Share B，钱包服务恢复新 Share A（接口调用 2+3：复用 §7.4 两步）

  ── API 1：POST /recovery/submit（经用户服务路由至钱包服务）──
  ├─ 客户端生成临时 ECDH 密钥对 (ePub_client, ePriv_client)
  │    ePriv_client 仅存内存，用于后续解密 Share A
  ├─ 用钱包服务公钥 ECDH 加密 Share B
  └─ POST /recovery/submit
       { enc_B, ePub_client, wallet_address, operation_token, passkey_assertion(如有) }
       ↓
  钱包服务宿主 → Nitro Enclave：
       ├─ 验证 OperationToken、按 verified_methods 验证身份凭证
       ├─ 从 KMS 读取 Share C（x=3）
       ├─ B + C → Lagrange → BIP39 熵 S 及系数 a₁
       ├─ 分配新坐标 x=n，计算 Share A = f(n)
       ├─ 用 ePub_client 加密 Share A，存入短期缓存（绑定 recovery_token）
       ├─ S、a₁、B 明文及中间值立即销毁（memzero）
       └─ 返回 { recovery_token }（5 分钟有效，单次可用）

  ── API 2：POST /recovery/claim ──
  ├─ Passkey 生物识别二次确认（或账号 token 确认）
  └─ 钱包服务返回 { enc_A, new_x }，recovery_token 立即失效

步骤4：用户设备本地重建助记词
  ├─ 用 ePriv_client 解密得到 Share A 明文（x=n）
  ├─ Share A（x=n）+ Share B（x=2，步骤2已获取，内存中）→ Lagrange → BIP39 熵 S
  ├─ BIP39 熵编码为助记词（12/24 词）展示给用户
  └─ 重建全程在设备内存中完成，不经过网络

步骤5：用户确认导出，通知服务端清理
  ├─ 客户端发送"导出确认"请求（附 Passkey 签名）
  ├─ 软删除平台云 Share B（30 天缓冲期后物理删除）
  ├─ Share C 软删除（30 天缓冲期后物理删除）
  ├─ 撤销所有 Bot Agent Session Credit
  └─ 钱包标记为"已导出 / 本地 EOA 模式"

步骤6：设备本地收尾
  ├─ Share A 明文、BIP39 熵、助记词从内存清除
  └─ 用户自行决定是否将助记词导入本地钱包 App
```

**导出后状态：**
- Bot 自动交易功能关闭，平台不再持有任何该钱包的分片（Share C 30 天后物理删除）
- 钱包转为普通本地 EOA 钱包，用户自行保管助记词
- 如需恢复 Bot 能力，须重新创建 Bot 钱包

---

## 十三、EOA 钱包开通 Agent 代理交易

### 13.1 方案定位

用户已有助记词钱包（外部导入或历史创建）希望开通 Agent 自动交易功能，通过将本地助记词进行 SSS 分片并上传服务端，复用 Keyless 钱包的 Agent 签名链路。

**限制说明：**
- 仅支持**助记词（BIP39）钱包**，不支持单私钥 EOA 钱包
- 单私钥账户无法套用 BIP39 → SSS 分片方案，额外适配成本大，暂不支持
- 业界参考：币安、OKX 的 Agent 交易功能同样不支持单私钥钱包导入

### 13.2 与 Keyless 钱包流程对比

| 环节 | Keyless 钱包 | EOA 升级开通 Agent |
|------|------------|-----------------|
| 助记词来源 | 创建时服务端生成 | 用户本地持有，设备端生成分片 |
| Share A | TEE 生成并存储 | TEE 生成并存储（同 Keyless） |
| Share B 上传 | 创建流程中完成 | **新增：升级流程中上传平台云** |
| Share C 上传 | 创建流程中完成 | **新增：升级流程中钱包服务写入 KMS** |
| Agent 签名流程 | 平台云取 B + KMS 取 C → 重建 → 签名 | **完全相同，无区别** |
| 取消 Agent 授权 | 按平台云备份状态决定是否删除 B（见 §10.6）| **始终删除平台云 B**（EOA 无平台云备份场景） |

核心差异在两处：①**升级流程**（分片 + 上传）；②**取消授权时 Share B 的处理策略**。

### 13.3 升级开通 Agent 流程

```
用户触发"开通 Agent 交易"
    │
    ├─ 1. 身份验证
    │       ├─ Passkey 验证（生物识别）
    │       └─ 二次确认弹窗（告知将上传分片至云端）
    │
    ├─ 2. 设备端助记词分片（全程在设备内存中完成，不经过网络）
    │       ├─ 用户输入助记词（或从已有 EOA 钱包读取）→ 解码为 BIP39 熵（16/32 字节）
    │       ├─ 验证：BIP44 派生目标链地址，断言与用户当前 EOA 地址一致（防止输错助记词）
    │       ├─ SSS 2-of-3 Split of 熵字节：Share A（x=1）/ Share B（x=2）/ Share C（x=3）
    │       ├─ Share A → 写入设备 TEE（含 BIP44 预派生各链私钥）
    │       └─ BIP39 熵及中间值立即清除内存（TEE 中仅留 Share A 和派生私钥）
    │
    ├─ 3. 上传 Share B（流程同 §10.3 Share B 上传，绑定 Session Credit）
    │       ├─ ECDH 加密信道，master_sig 签名校验
    │       ├─ Share B 经钱包服务转存至平台云服务 KMS
    │       └─ 返回 share_b_ref（引用 ID，不含明文）
    │
    ├─ 4. 上传 Share C（EOA 升级特有步骤，Keyless 创建时 Share C 在服务端已有）
    │       ├─ ECDH 加密信道传输 Share C 至钱包服务
    │       ├─ 钱包服务写入 KMS
    │       └─ 返回 share_c_ref
    │
    └─ 5. 服务端确认 & 状态更新
            ├─ 钱包服务校验 share_b_ref + share_c_ref 均已就绪
            ├─ 钱包记录更新：wallet_type = EOA_AGENT，agent_enabled = true
            └─ 返回开通成功，后续流程与 Keyless Agent 完全一致
```

**安全要点：**
- 步骤 2 全程在设备端完成，助记词明文和 Master Seed **不经过网络**
- Share B 通过 ECDH 加密信道传输，服务端仅存密文
- 用户须明确知晓"助记词分片将上传云端"并二次确认

### 13.4 Agent 签名流程

与 Keyless 钱包 §10.4 **完全一致**，无需额外适配：

```
AI Agent 发起交易请求
    → 风控校验（§10.5）→ 签发 ApprovedToken
    → vsock → Nitro Enclave 取 Share B（平台云）+ Share C（KMS，PCR 绑定）
    → Enclave 内：Lagrange 重建 Master Seed → BIP44 派生私钥 → 签名
    → Enclave 内：Share B / C / Seed / 私钥明文立即销毁
    → 返回签名 → 广播上链
```

### 13.5 取消 Agent 授权流程

与 Keyless 钱包 §10.6 流程基本一致，但 **Share B 处理策略不同**：

EOA 钱包没有平台云助记词备份功能，Share B 仅为 Agent 签名期间临时存储，因此**关闭时必须软删除平台云 Share B**，无例外。

```
用户触发"关闭 Agent 交易"
    │
    ├─ 1. Passkey 验证
    │
    ├─ 2. 软删除平台云 Share B（必须执行，无条件，30 天后物理删除）
    │       └─ EOA 无平台云备份场景，Share B 关闭后不再使用
    │
    ├─ 3. Share C 软删除（30 天缓冲期后物理删除）
    │       └─ EOA 钱包的 Share C 是升级时临时上传的，关闭 Agent 后不再需要
    │          （与 Keyless 不同：Keyless Share C 跟随钱包生命周期，不在此处删除）
    │
    ├─ 4. 撤销所有有效 Session Credit
    │
    └─ 5. 钱包状态更新：agent_enabled = false
        └─ 写入审计日志
```

关闭后用户本地 TEE 仍保有 Share A 及预派生私钥，**本地签名功能不受影响**（见 §九）。

如需**重新开通 Agent**：
- 重新执行 §13.3 升级流程（助记词重新分片 → 上传新 Share B 和 Share C）
- 若 30 天缓冲期内尚未物理删除旧 Share C，可申请撤销软删除复用；缓冲期后须重新生成

### 13.6 不支持单私钥 EOA 的说明

| 项目 | 说明 |
|------|------|
| 根本原因 | SSS 分片对象是 BIP39 Master Seed（64 字节），单私钥钱包无助记词，无法套用同一方案 |
| 适配成本 | 需单独设计私钥加密分片协议、设备端存储格式、跨链地址映射等，额外工作量大 |
| 业界现状 | 币安、OKX Agent 交易均仅支持助记词钱包，单私钥账户不支持 |
| 当前结论 | 本期**不支持**单私钥 EOA 开通 Agent，在产品侧明确告知用户限制 |

---

## 十四、开发优先级排期与产品设计建议

### 14.1 整体路线图

```
                第一阶段                  第二阶段                第三阶段
                SSS 钱包上线      →    Bot 钱包升级 + 迁移   →   EOA Agent 开通
                （优先）               （并行运营过渡）           （高级交易能力）

平台云服务  ──── 第一阶段同步上线（P0）────────────── 第二/三阶段复用，仅小幅扩展 ────▶
```

> 平台云服务（AWS 账号 B）需与钱包服务**同步**在第一阶段完成，是 SSS 钱包上线的前置依赖。

---

### 14.2 第一阶段：SSS 钱包上线（最高优先级）

**目标：** 全新上线 SSS Keyless 钱包，作为主推产品。同期保持 Bot 钱包和 EOA 钱包正常运营，三种钱包并行。

#### 钱包服务 & Enclave

| 模块 | 内容 | 优先级 |
|------|------|-------|
| 钱包服务宿主 | API 接入、Share C 写 KMS、Agent 签名调度、软删除管理（§10）| P0 |
| Nitro Enclave 签名服务 | signing-service 镜像构建、vsock IPC、ApprovedToken 验证、KMS PCR 绑定策略（§10.1 / §10.4）| P0 |
| 风控模块 | 进程内 library，分级限频、签名校验、ApprovedToken 签发（§10.5）| P0 |
| Session Credit | 授权许可生成、撤销、有效期管理（§十一）| P0 |
| 钱包恢复流程 | 两步接口（submit / claim）、Share B+C 重建新 Share A（§7.4）| P0 |
| 本地签名 | TEE 预派生私钥直签（§九）| P0 |
| 删除钱包 | 软删除 + 30/60 天物理删除（§7.5）| P1 |

#### 平台云服务（AWS 账号 B，与钱包服务同步上线）

| 模块 | 内容 | 优先级 |
|------|------|-------|
| AWS 账号 & 基础设施 | 独立 AWS 账号申请、KMS 密钥创建、EC2 + 安全组配置 | P0 |
| App 上传接口 | AVE Token 验证、Master Key 签名校验、ECDH 解密、KMS 加密存储 Share B（§16.2）| P0 |
| App 下载接口 | AVE Token + 2FA 验证、KMS 解密 Share B、ECDH 加密回传、限频（§16.3）| P0 |
| Wallet Enclave 接口 | NSM Attestation PCR 验证、credit_id 有效性校验、KMS 解密 Share B、TLS 回传（§16.4）| P0 |
| AWS PrivateLink 配置 | Endpoint Service（NLB）创建、钱包服务账号跨账号白名单授权（§10.8）| P0 |
| Share B 生命周期管理 | purpose 区分（backup / agent）、软删除、30 天物理删除、到期自动清理（§16.5）| P0 |
| 访问审计日志 | 每次 Share B 读写记录（调用方、credit_id、时间、PCR 值）| P1 |
| 紧急响应接口 | 批量软删除 Share B（安全事件响应，§10.7）| P1 |

#### 设备端 SDK

| 模块 | 内容 | 优先级 |
|------|------|-------|
| 设备端 SDK | BIP39 生成、SSS 分片、TEE 写入、ECDH 加密上传平台云 | P0 |

**产品建议：**
- SSS 钱包作为**默认新建钱包类型**，在引导页突出"无需备份助记词"的安全卖点
- Bot 钱包和 EOA 钱包保持现有入口，不做下线，确保存量用户不受影响
- Agent 自动交易功能对 SSS 钱包、Bot 钱包（分片迁移后）、EOA 助记词钱包（升级后）均可用，共用同一签名链路

---

### 14.3 第二阶段：Bot 钱包升级为分片钱包

**目标：** 将存量 Bot 钱包从完整私钥托管升级为 SSS 2-of-2 分片，消除单点风险；同时支持 Bot 钱包导出为 EOA 钱包。跑稳 1–2 个月后关闭 Bot 钱包新建入口。

#### 钱包服务

| 模块 | 内容 | 优先级 |
|------|------|-------|
| 存量迁移服务 | KMS 解密 → SSS 分片 → B 写平台云 / C 写 KMS（§12.4）| P0 |
| 增量同步服务 | 以钱包表自增 ID 为水位，持续同步新增 Bot 钱包（§12.4）| P0 |
| 双模兼容运行 | 迁移期间 Bot 钱包支持原路径 + 分片路径双跑（§12.5）| P0 |
| Bot 钱包导出 | 两步接口复用 §7.4、B+C 重建 Share A 下发设备（§12.7）| P1 |
| 迁移监控 | 写入成功率、双跑对比告警、失败重试（§12.6）| P1 |

#### 平台云服务（小幅扩展，复用第一阶段接口）

| 模块 | 内容 | 优先级 |
|------|------|-------|
| 迁移批量写入支持 | 接受钱包服务迁移任务写入的 Bot 钱包 Share B（purpose=agent，批量接口限流适配）| P0 |
| 迁移水位监控 | 对接迁移任务，暴露 Share B 写入成功率指标供钱包服务监控 | P1 |

**阶段收尾（双跑观察 1–2 个月后）：**

```
观察期满 + 迁移完成
    ├─ 关闭 Bot 钱包新建入口（产品下架新建选项）
    ├─ 存量 Bot 钱包：已迁移分片的继续正常使用，未迁移的触发补跑
    ├─ 原完整私钥：软删除标记 → 60 天缓冲期 → 物理清理（§12.6）
    └─ 最终状态：平台仅保留 SSS 钱包 + EOA 钱包两种类型
```

**产品建议：**
- 迁移过程对 Bot 钱包用户**无感知**，不中断交易功能
- "导出为 EOA 钱包"作为 Bot 钱包设置页新增选项，引导有需要的用户主动导出
- 关闭入口前提前 30 天在产品内公告，给用户导出或切换 SSS 钱包的时间

---

### 14.4 第三阶段：EOA 助记词钱包升级支持 Agent 交易

**目标：** 允许已有 EOA 助记词钱包的用户开通 Agent 代理交易，复用 SSS 分片链路，支持自动挂单、高级交易策略、跟单等高级功能。

#### 钱包服务

| 模块 | 内容 | 优先级 |
|------|------|-------|
| EOA 升级流程 | 设备端分片 + 上传 B/C（§13.3）| P0 |
| Agent 签名复用 | 与 SSS 钱包完全共用，无新增开发 | — |
| 关闭 Agent 授权 | 始终删除平台云 B + Share C（§13.5）| P0 |
| 高级交易策略 | 自动挂单、止盈止损、跟单（AI Agent 侧功能）| P1 |
| 产品引导 | EOA 钱包内"升级开通 Agent"入口 + 用户教育 | P1 |

#### 平台云服务（完全复用，无新增开发）

EOA 升级上传 Share B 与 Keyless 钱包 Agent 激活走同一接口（§16.2），关闭 Agent 时 Share B / Share C 软删除走同一生命周期管理逻辑（§16.5），无需额外开发。

**产品建议：**
- EOA 升级为**可选功能**，不强制，用户主动选择是否上传分片
- 升级前需明确告知用户："助记词分片将加密上传至云端，关闭 Agent 后分片立即删除"
- 单私钥 EOA 钱包不支持升级，产品侧在入口处做检测并给出明确提示
- 跟单、自动挂单等高级策略作为 Agent 功能的增值能力，可配合会员体系分层开放

---

### 14.5 各阶段模块交付矩阵

| 模块 | 第一阶段 | 第二阶段 | 第三阶段 |
|------|---------|---------|---------|
| 设备端 SDK | ✅ 全量 | — | — |
| 钱包服务宿主 + 风控 | ✅ 全量 | ✅ 迁移扩展 | — |
| Nitro Enclave 签名服务 | ✅ 全量 | — | — |
| **平台云：账号 & 基础设施** | ✅ **P0** | — | — |
| **平台云：App 上传/下载接口** | ✅ **P0** | — | — |
| **平台云：Wallet Enclave 接口** | ✅ **P0** | — | — |
| **平台云：PrivateLink 配置** | ✅ **P0** | — | — |
| **平台云：Share B 生命周期** | ✅ **P0** | ✅ 批量写入适配 | — |
| Session Credit 管理 | ✅ 全量 | — | — |
| 钱包恢复（两步接口） | ✅ 全量 | — | — |
| Bot 迁移服务 | — | ✅ P0 | — |
| Bot 钱包导出 | — | ✅ P1 | — |
| EOA Agent 升级流程 | — | — | ✅ P0 |
| 高级交易策略 | — | — | ✅ P1 |

### 14.6 各阶段钱包类型与功能矩阵

| 功能 | 第一阶段 | 第二阶段 | 第三阶段（最终态） |
|------|---------|---------|----------------|
| SSS Keyless 钱包（新建） | ✅ 主推 | ✅ | ✅ |
| Bot 钱包（新建） | ✅ 保留 | ⚠️ 迁移中，观察期满后关闭入口 | ❌ 入口关闭 |
| EOA 钱包（导入/新建） | ✅ 保留 | ✅ | ✅ |
| SSS 钱包 Agent 交易 | ✅ | ✅ | ✅ |
| Bot 钱包 Agent 交易 | ✅ | ✅（分片后） | ✅（存量） |
| EOA 助记词钱包 Agent 交易 | ❌ | ❌ | ✅ |
| Bot 钱包导出为 EOA | ❌ | ✅ | ✅ |
| 自动挂单 / 跟单 | ❌ | ❌ | ✅ |

---

## 十五、待产品讨论问题列表

> 本章汇总全文中尚未最终决策的产品问题，供评审和讨论时参考。技术方案已预留支持，待产品拍板后补充至对应章节。

---

### P0 — 影响核心流程，须优先决策

| # | 问题 | 所在章节 | 选项 / 背景 |
|---|------|---------|------------|
| 1 | **平台云备份是否强制开启？** | §6.1 | 目前设计为"强烈建议"但非强制。若用户拒绝且 Share A 丢失，钱包永久不可恢复。是否在创建钱包时强制完成平台云备份，不允许跳过？ |
| 2 | **关闭 Agent 的触发条件** | §10.6 | 两种机制需二选一：① 连续 N 天无 Agent 交易自动关闭；② Session 固定时长到期关闭。是否允许用户在 App 内自行选择？ |
| 3 | **存量 Bot 钱包最终命运** | §12.5 | 路线 A：长期共存（底层已是分片存储，不强制关闭），用户自愿升级为 SSS 或 EOA；路线 B：设 3 个月缓冲期后关闭签名服务，引导统一升级。取决于存量规模和运营策略。 |

---

### P1 — 影响产品体验，须在开发前确认

| # | 问题 | 所在章节 | 选项 / 背景 |
|---|------|---------|------------|
| 5 | **创建钱包时是否展示助记词** | §6（创建流程） | 助记词是 BIP39 熵的人类可读形式。展示可让用户自行备份，但也意味着用户持有完整私钥，弱化了 Keyless 的"无私钥体验"定位。是否提供该选项？ |
| 6 | **Session Credit 有效期上限** | §11.2、§11.3 | 当前设计：默认 7 天，用户可自定义最长 30 天，到期不自动续期。是否允许更长有效期（如 90 天或永久）？延长后对 Agent 失控风险的影响需评估。 |
| 7 | **Bot 钱包升级默认推荐路径** | §12.5 | Bot → Keyless SSS（保留 Agent 能力，地址不变）vs Bot → 本地 EOA（彻底自主）。是否设置平台推荐路径，还是完全由用户自主选择？ |
| 8 | **EOA 助记词钱包开通 Agent 是否可选** | §13.1、§14.4 | 当前设计为可选功能，不强制，用户主动选择是否上传分片。是否需要产品引导路径设计（如首次使用 Agent 时弹出引导）？ |
| 9 | **私钥导出硬限制（每钱包仅 1 次）** | §9（限频策略） | 当前设计导出仅允许 1 次，防止多次导出扩大暴露面。若用户误操作（导出后未保存助记词），是否有补救路径？是否需要人工客服介入机制？ |
| 10 | **软删除 30 天缓冲期内用户撤销流程** | §7.5、§8.1 | 缓冲期内用户可申请撤销删除（恢复 Keyless 保护），需人工客服审核。审核标准、SLA、以及客服侧操作界面需产品和运营设计。 |

---

### P2 — 影响容量规划或未来扩展，可在上线后决策

| # | 问题 | 所在章节 | 选项 / 背景 |
|---|------|---------|------------|
| 11 | **xpub 缓存优化是否采用** | §3.5 | 缓存 `m/44'/60'/0'` xpub 可将单次签名 BIP44 耗时从 ~10ms 降至 ~2ms，单机吞吐提升约 5×。需评估 xpub 缓存在内存/KV 中的安全边界，再决策是否引入。 |
| 12 | **生产服务器真实压测** | §3.5 | 当前性能数据来自本地 8 核机，不含平台云 + KMS 网络 I/O（预估 2–10ms）。上线前须在目标部署环境完成压测，确认容量规划和扩容阈值。 |
| 13 | **Bot 存量迁移每批处理量 N** | §12.4 | 当前批量大小 N 待定，须根据 KMS 读写吞吐上限和迁移完成时间目标共同确定。 |
| 14 | **多链扩展规划（BTC / Solana / Sui 等）** | §5.1 | SSS 方案天然支持多链（BIP44 路径切换即可），但当前文档仅完整设计了 EVM 链。其他链的支持优先级和时间节点需产品排期。 |
| 15 | **密钥恢复超限（30 天 > 3 次）人工审核 SLA** | §9（限频策略） | 超限后账号恢复功能冻结，需人工客服审核。审核 SLA（如 24h 内响应）和标准（如身份核验要求）需运营侧定义。 |

---

## 十六、平台云服务设计

> 平台云服务（Platform Cloud Service）运行于独立 AWS 账号，负责加密存储 Share B，并向两类调用方提供受控访问：**App 客户端**（上传 / 下载 Share B）和**钱包服务 Enclave**（Agent 签名时取 Share B）。

### 16.1 架构决策：平台云不需要 Nitro Enclave

平台云只负责存取 Share B 这一个分片，**Share B 单独暴露无法还原私钥**，这正是 SSS 2-of-3 的设计前提。私钥被重建的危险边界在钱包服务（B+C → Master Seed → 派生私钥），那里才需要 Enclave 保护内存。

| 服务 | 内存中出现的最敏感数据 | 需要 Enclave？ |
|------|----------------------|--------------|
| 平台云服务 | Share B（单片，无法还原密钥） | **不需要** |
| 钱包服务 | Master Seed + 派生私钥（完整密钥材料） | **需要** |

平台云使用标准宿主进程处理即可，KMS 保证静态加密，TLS 保证传输加密，强身份认证控制访问。

```
┌──────────────────────────────────────────────────────────────┐
│                 平台云服务（AWS 独立账号）                     │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │                   宿主服务进程（EC2）                   │  │
│  │                                                        │  │
│  │  ┌─────────────────────┐  ┌────────────────────────┐  │  │
│  │  │     App 接口         │  │  Wallet Enclave 接口    │  │  │
│  │  │  - AVE Token 验证   │  │  - PrivateLink 来源校验 │  │  │
│  │  │  - Master Key 签名  │  │  - NSM Attestation 验证 │  │  │
│  │  │  - 2FA（下载场景）  │  │  - PCR 白名单校验       │  │  │
│  │  │  - 限频 / 审计日志  │  │  - credit_id 有效性     │  │  │
│  │  └──────────┬──────────┘  └───────────┬────────────┘  │  │
│  │             │                         │               │  │
│  │             └───────────┬─────────────┘               │  │
│  │                         ↓                             │  │
│  │             ┌───────────────────────┐                 │  │
│  │             │  Share B 读写逻辑      │                 │  │
│  │             │  KMS 加密/解密         │                 │  │
│  │             │  DB 存取               │                 │  │
│  │             └───────────────────────┘                 │  │
│  └────────────────────────────────────────────────────────┘  │
│                        ↓ KMS API                             │
│  ┌────────────────────────────────────────────────────────┐  │
│  │            AWS KMS（平台云账号）                        │  │
│  │  Share B 加密/解密密钥；key policy 限制宿主服务角色     │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
      ↑ HTTPS（AVE Token + Passkey）   ↑ E2E TLS + NSM Attestation
   App 客户端                       钱包服务 Enclave
                                    （AWS PrivateLink 私网通道）
```

---

### 16.2 Share B 写入接口

平台云提供统一写入接口，被两类调用方使用：

| 调用场景 | 调用方 | 说明 |
|---------|-------|------|
| 钱包创建（备份） | App 直接调用 | Share B 备份至平台云，`purpose=backup` |
| Agent 激活 / EOA 升级 | **钱包服务宿主进程** 转发 | App → 钱包服务（校验 master_sig / credit_json）→ 钱包服务重新加密后写入，`purpose=agent` |

> Agent 激活路径之所以经由钱包服务中转，是为了由钱包服务统一完成 Session Credit 业务校验，并保证 credit_id 写入与 Share B 写入的原子性。

```
步骤1：调用方发起上传请求（HTTPS）
  ├─ AVE Token（账号身份，备份场景为 App Token；Agent 场景为钱包服务服务账号 Token）
  ├─ wallet_address
  ├─ credit_id（Agent 激活场景；备份场景为空）
  ├─ enc_share_b：ECDH 加密的 Share B
  │    （调用方临时密钥对 + 平台云公钥协商 shared_secret → AES-256-GCM）
  └─ master_sig：对 hash(wallet_address + enc_share_b) 的签名
       （App 直调场景用 Master Key 签；钱包服务转发场景用钱包服务签名密钥签）

步骤2：服务进程校验
  ├─ 验证调用方 Token
  ├─ 验证 master_sig
  └─ 检查上传频率限制（同一钱包 24h ≤ 5 次）

步骤3：存储
  ├─ ECDH 解密 enc_share_b → Share B 明文
  ├─ 调用 KMS 加密 Share B → enc_b_kms
  ├─ 写入 DB：{ wallet_address, credit_id, enc_b_kms, purpose, status=active }
  ├─ Share B 明文变量清零
  └─ 返回 share_b_ref
```

---

### 16.3 App 下载 Share B（钱包恢复）

触发场景：换机恢复、Share A 丢失。

```
步骤1：App 发起下载请求（HTTPS）
  ├─ AVE Token + 2FA 凭证（Passkey 或 Email OTP）
  ├─ wallet_address
  └─ app_ephemeral_pub：App 临时 ECDH 公钥（用于加密回传）

步骤2：服务进程校验
  ├─ 验证 AVE Token + 2FA
  ├─ 验证 wallet_address 归属当前账号
  └─ 检查下载频率限制（同一账号 30 天 ≤ 3 次）

步骤3：读取并回传
  ├─ 从 DB 取 enc_b_kms
  ├─ 调用 KMS 解密 → Share B 明文
  ├─ 用 app_ephemeral_pub ECDH 加密 Share B
  ├─ Share B 明文变量清零
  └─ 返回加密后的 Share B

步骤4：App 接收
  └─ 用本地临时私钥解密 → Share B 明文 → 进入恢复流程
```

---

### 16.4 Wallet Service Enclave 请求 Share B（Agent 签名）

触发场景：每次 Agent 自动交易签名（见 §10.4）。

```
步骤1：Wallet Service Enclave 发起请求
  ├─ 网络通道：AWS PrivateLink（跨账号私网，不走公网）
  ├─ 传输层：TLS（平台云服务端终止，保护 Share B 不被钱包服务宿主截获）
  └─ 请求体：
       ├─ credit_id
       ├─ wallet_address
       └─ nsm_attestation：Wallet Service Enclave 的 NSM Attestation Document

步骤2：服务进程校验
  ├─ 验证来源为白名单 PrivateLink Endpoint（拒绝公网请求）
  ├─ 验证 nsm_attestation 的 AWS Nitro 根 CA 签名
  ├─ 检查 PCR0/1/2 是否在钱包服务 Enclave 镜像白名单中
  ├─ 验证 credit_id 有效性（存在、未过期、未撤销）
  ├─ 验证 wallet_address 与 credit_id 绑定关系
  └─ 检查请求频率（同一 credit_id 单位时间上限）

步骤3：读取并回传
  ├─ 从 DB 取 enc_b_kms
  ├─ 调用 KMS 解密 → Share B 明文
  ├─ 通过 TLS 回传 Share B（钱包服务宿主只见密文，Enclave 端解密）
  ├─ Share B 明文变量清零
  └─ 写入访问审计日志（credit_id、时间、PCR 值）
```

> **TLS 的保护对象**：平台云侧终止 TLS 是正常的——平台云本就持有 Share B，关键是 TLS 保护 Share B 在传输中不被**钱包服务宿主**截获。钱包服务 Enclave 是 TLS 的接收端，宿主只做 TCP relay，看不到明文。

---

### 16.5 Share B 存储设计

| 字段 | 说明 |
|------|------|
| `share_b_ref` | 唯一索引 ID，对外暴露，不含密钥材料 |
| `wallet_address` | 绑定钱包地址 |
| `credit_id` | 关联 Session Credit（Agent 场景）；备份场景为空 |
| `enc_b_kms` | KMS 加密后的 Share B 密文 |
| `purpose` | `backup`（平台云备份）/ `agent`（Agent 签名） |
| `status` | `active` / `soft_deleted` / `deleted` |
| `created_at` / `expire_at` | 生命周期管理 |

> 同一钱包可同时存在两条记录：`purpose=backup`（供 App 恢复下载）和 `purpose=agent`（供 Wallet Service Enclave 签名取用），生命周期独立管理。

---

### 16.6 访问控制矩阵

| 调用方 | 接口 | 身份认证 | 授权范围 |
|--------|------|---------|---------|
| App | 上传 Share B | AVE Token + Master Key 签名 | 只能操作自己账号下的钱包 |
| App | 下载 Share B | AVE Token + 2FA | 只能操作自己账号下的钱包 |
| Wallet Service Enclave | 获取 Share B | NSM Attestation PCR 验证 | 只能按 credit_id 获取，credit_id 必须有效 |
| 任何其他来源 | 所有接口 | — | 拒绝；PrivateLink + 安全组双重封锁公网 |

---

### 16.7 平台云与钱包服务的安全边界

```
┌──────────────────────┐         ┌───────────────────────────┐
│   钱包服务（账号 A）  │         │   平台云服务（账号 B）     │
│                      │         │                           │
│  持有 Share C        │         │  持有 Share B             │
│                      │         │                           │
│  单独泄露 → 无法      │         │  单独泄露 → 无法          │
│  还原 Master Seed    │         │  还原 Master Seed         │
└──────────────────────┘         └───────────────────────────┘
              需同时攻破两个独立账号才能还原用户私钥
```

两个账号的 KMS 密钥互不可见，IAM 角色互不信任。即使平台云宿主进程被完全入侵，攻击者拿到 Share B 后仍需突破钱包服务 Enclave 的 PCR 绑定才能获取 Share C，组合才有威胁。
