# TSS 技术调研总结

> 基于 [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib)（GG18/GG20 协议），调研环境：{t=2, n=3} 三方门限签名，已跑通完整 Demo。

---

## 1. 私钥导出支持程度

### 结论：支持完整私钥重建，但设计上不鼓励

TSS 的核心思想是"私钥永不聚合"，但该库底层基于 VSS（Verifiable Secret Sharing），数学上支持通过 Lagrange 插值从 t+1 份分片重建完整私钥。

| 场景 | 是否支持 | 说明 |
|------|----------|------|
| 正常签名（不导出私钥） | 是 | TSS 标准流程，私钥永不暴露 |
| Lagrange 插值重建私钥 | 是 | `vss.Shares.ReConstruct()` |
| 单个分片推导完整私钥 | 否 | 需 t+1 份才能重建 |
| 仅凭网络消息推导私钥 | 否 | GG20 协议保证 |

### 重建代码核心

```go
shares := make(vss.Shares, n)
for i, k := range savedKeys {
    shares[i] = &vss.Share{Threshold: t, ID: k.ShareID, Share: k.Xi}
}
privInt, _ := shares.ReConstruct(tss.S256())
```

### 适用场景

- 钱包迁移（导出后重新分片）
- 紧急恢复（用户流程兜底）
- **生产环境应将此功能放在严格的多重审批流程后才可触发**

---

## 2. 多链支持程度

### 底层曲线决定链的支持范围

| 曲线 | tss-lib 支持 | 支持的链 |
|------|-------------|---------|
| secp256k1 | `tss.S256()` | EVM 全系、BTC、BNB Chain、Polygon 等 |
| Ed25519 | `tss.Edwards()` | Solana、Sui、TON、Near、Aptos（部分）|
| secp256r1 (P-256) | 不支持 | Passkey、部分 Web3Auth 场景 |
| Schnorr/Taproot | 不支持 | BTC Taproot |

### 各链详细情况

| 链 | 曲线 | 地址派生 | 已验证 | 示例地址 |
|----|------|---------|--------|---------|
| EVM (ETH/BNB/Polygon...) | secp256k1 | `keccak256(pubX\|\|pubY)[12:]` | **是** | `0x58c7a6d4...` 含 BSC 真实转账 |
| BTC Legacy (P2PKH) | secp256k1 | `Base58Check(0x00\|\|hash160(compressed_pub))` | **是** | `1EffeZEPfLaDm6vz...` |
| BTC SegWit (P2WPKH) | secp256k1 | `bech32("bc", 0, hash160(compressed_pub))` | **是** | `bc1qjh5m87mng8xv2s...` |
| BTC Taproot (P2TR) | Schnorr | bech32m 编码 | 不支持 | 需 Schnorr，tss-lib 不支持 |
| Solana | Ed25519 | `base58(compressed_pub)` | **是** | `3ZCs6oD8eQ6j3CH3...` |
| Sui | Ed25519 | `blake2b256(0x00\|\|compressed_pub)` | **是** | `0x155547fad6cb...` |
| TON | Ed25519 | wallet 合约 StateInit hash（需 SDK） | **是**（签名） | `0:28073b4fcad4...` 地址为简化版 |
| Near | Ed25519 | `hex(compressed_pub)` 隐式账户 | **是** | `25f75fc9f955df6c...` |
| Aptos | Ed25519 | `sha3_256(compressed_pub\|\|0x00)` | **是** | `0x43aca986dcdf35...` |

### BTC 特殊说明

BTC Taproot（P2TR）使用 Schnorr 签名，tss-lib 当前不支持。如需支持 BTC Taproot，需寻找其他实现（如 [taurusgroup/multi-party-sig](https://github.com/taurusgroup/multi-party-sig) 等支持 Schnorr 的库）。

### 行业参考：币安 Web3 钱包（无私钥恢复）技术推断

币安 Web3 Wallet 支持 BTC Taproot 且密钥创建/签名性能极快（接近毫秒级），综合两个维度判断：

| 维度 | 现象 | 推断 |
|------|------|------|
| 支持 BTC Taproot | Taproot 需 Schnorr 签名 | 不使用 tss-lib（不支持 Schnorr） |
| 创建/签名性能极快 | 毫秒级体验 | 大概率不是 GG20 TSS（Keygen 至少 3-5s，签名需多轮网络交互） |

**更可能的实现方式：SSS + 服务端 TEE**

```
用户设备持有分片 A（本地加密存储）
币安服务器持有分片 B（TEE 可信执行环境）
         ↓ 签名时
A + B → 临时重建私钥（TEE 内） → 签名 → 私钥立即销毁
```

这套方案：
- 密钥创建毫秒级（SSS 分片是纯数学，极快）
- 签名毫秒级（本地 + 服务端一次通信即完成）
- 支持任意曲线和链（Taproot/Schnorr 均可，因为最终是用标准私钥签名）
- 用户看不到完整私钥，因此被称为"无私钥"

**"无私钥"是用户体验描述，不是密码学承诺：**
行业内大量"MPC 钱包"本质是 SSS + 安全重建，私钥在服务端 TEE 中短暂存在。真正做到私钥永不重建的是 ZenGo（论文级 TSS 实现）等少数产品。

**Schnorr TSS（FROST）补充说明：**
- FROST 协议是真正的 Schnorr 门限签名（私钥不重建），仅需 2 轮交互，比 GG20 快
- 但移动端 Keygen 仍需秒级时间，性能仍不如 SSS
- 币安的毫秒级体验基本排除了 FROST TSS 的可能

**结论对本项目的影响：**
- 若追求极致性能和多链全覆盖，SSS + 服务端 TEE 是更务实的方案
- 若追求最高安全性（私钥真正永不聚合），用 tss-lib，但需接受性能代价和 Taproot 不支持的限制
- 两者安全模型的核心差异：SSS 的信任根在服务端 TEE，TSS 无需信任任何单一方

---

## 3. 整体运行流程与性能

### 完整流程

```
[一次性初始化]
  生成 PreParams（Paillier 密钥 + 安全素数）
  → 加密存储本地，多钱包复用

[创建钱包]
  ECDSA Keygen (secp256k1)  → EVM/BTC 分片
  EdDSA Keygen (Ed25519)    → Solana/Sui/TON/Near/Aptos 分片
  → 各方持有自己的分片，无人知道完整私钥

[签名交易]
  各方对交易哈希运行 Signing 协议
  → 输出标准 (R, S, recovery) 签名
  → 广播到链上
```

### 实测性能（桌面 4 核 x86，多次运行均值）

| 阶段 | 实测耗时 | 备注 |
|------|---------|------|
| PreParams 生成（单次/方） | 12–33 秒 | 顺序生成，一次性可复用 |
| ECDSA Keygen (secp256k1) | ~4–5 秒 | 4 轮消息交互 |
| EdDSA Keygen (Ed25519) | ~250–500 ms | 3 轮，无 Paillier |
| ECDSA Signing (EVM / BTC) | ~650 ms – 1.2 s | 9 轮消息交互 |
| EdDSA Signing (Solana/Sui/TON/Near/Aptos) | ~100–200 ms | 3 轮消息交互 |
| Lagrange 私钥重建（secp256k1 + Ed25519） | ~18 ms | 纯本地计算 |

### 手机端性能预估

| 设备档次 | PreParams 生成 | ECDSA Signing |
|----------|--------------|--------------|
| 旗舰 (A17 / SD 8 Gen 3) | 1–2 分钟 | 2–5 秒 |
| 中端 (SD 7xx / Helio G99) | 3–8 分钟 | 5–15 秒 |
| 低端 (SD 4xx) | 10 分钟以上 | 不可接受 |

### 手机端主要性能风险

1. **热降频**：安全素数搜索持续满载 CPU，30 秒后芯片降频，实际时间比理论值长 2–3 倍
2. **iOS 后台限制**：iOS 不允许后台长时间 CPU 密集任务，PreParams 生成必须在前台完成
3. **内存压力**：Paillier 密钥较大，低端机可能触发 OOM
4. **网络轮次**：Signing 需要多轮 P2P 消息，弱网环境延迟叠加明显

### 优化方案

| 问题 | 优化方案 |
|------|---------|
| PreParams 生成慢 | App 安装时后台一次性生成，加密存储，后续所有钱包复用 |
| 多钱包重复 Keygen | 同一套 PreParams 可复用于无限次 Keygen |
| Signing 轮次多 | 优化 Relay Server 就近部署，降低消息往返延迟 |
| 低端机不可用 | 设置最低设备要求；或引入可信 Co-signer 服务端承担一方 |
| iOS 后台限制 | 生成阶段保持屏幕常亮 + 进度提示 UI |

---

## 4. 工程复杂度

### 与 SSS（助记词分片）对比

| 维度 | SSS 助记词分片 | TSS 私钥分片 |
|------|--------------|------------|
| 核心原理 | 对助记词/私钥字节做 Shamir 分片 | 分布式密钥生成，私钥从不聚合 |
| 签名方式 | 重建私钥后单点签名 | 多方协同签名，无需重建 |
| 私钥暴露风险 | 签名时必须重建，存在暴露窗口 | 签名全程私钥不出现 |
| 实现复杂度 | 极低（现有库一行代码） | 高（多轮协议、消息路由、状态机） |
| 网络依赖 | 无（本地重建） | 有（各方实时在线，需 P2P/Relay） |
| 离线签名 | 支持 | 不支持（必须多方同时在线） |
| 多链支持 | 天然支持（私钥通用） | 需按曲线分别实现 |
| 移动端集成 | 直接用 | 需要 gomobile 封装 + Relay 服务 |
| 维护成本 | 低 | 高 |
| 安全性 | 重建时有单点风险 | 更高，无单点 |

### TSS 工程复杂度拆解

```
需要自建的组件：
  1. TSS SDK 封装层（Go → gomobile → Android AAR / iOS xcframework）
  2. Relay Server（消息转发服务，无状态，需高可用）
  3. 本地状态机（管理 Keygen/Signing 多轮消息）
  4. 分片加密存储（Keychain / Keystore + 用户密码派生密钥）
  5. 网络协议（消息序列化、超时重试、断线重连）
  6. PreParams 生命周期管理（生成、存储、定期刷新）
```

### 多语言维护成本

| 层 | 语言 | 维护方 |
|----|------|--------|
| 密码学核心 | Go | 跟随 tss-lib 上游更新 |
| Android SDK | Kotlin + Go (gomobile) | 每次 tss-lib 更新需重新编译 .aar |
| iOS SDK | Swift + Go (gomobile) | 同上，重新编译 .xcframework |
| Relay Server | Go / 任意 | 独立服务，相对稳定 |
| 业务 App | Kotlin / Swift | 调用封装好的 SDK |

gomobile 编译工具链版本敏感，Go 大版本升级时可能需要适配。建议将 `.aar` / `.xcframework` 版本化管理，与 App 解耦发布。

---

## 5. 已验证功能清单

以下功能均已跑通完整代码并验证输出正确性：

### 密钥生成

- [x] ECDSA Keygen（secp256k1，{t=2, n=3}）
- [x] EdDSA Keygen（Ed25519，{t=2, n=3}）
- [x] PreParams 生成与复用
- [x] 密钥分片 JSON 序列化/反序列化（含 ECPoint 曲线还原）

### 地址派生

- [x] EVM 地址（`keccak256(pubX||pubY)[12:]`）→ `0x58c7a6d4...`
- [x] BTC Legacy P2PKH（`Base58Check(0x00||hash160(compressed_pub))`）→ `1EffeZEPfL...`
- [x] BTC SegWit P2WPKH（`bech32("bc", 0, hash160(compressed_pub))`）→ `bc1qjh5m87...`
- [x] Solana 地址（`base58(ed25519_compressed_pub)`）→ `3ZCs6oD8...`
- [x] Sui 地址（`blake2b256(0x00 || ed25519_compressed_pub)`）→ `0x155547fa...`
- [x] TON 地址简化版（`"0:"+sha256(pub)`，真实地址需 wallet 合约 StateInit）→ `0:28073b4f...`
- [x] Near 隐式账户（`hex(ed25519_compressed_pub)`）→ `25f75fc9f9...`
- [x] Aptos 地址（`sha3_256(compressed_pub||0x00)`）→ `0x43aca986...`

### 签名与验证

- [x] ECDSA TSS 签名 → EVM 交易签名验证
- [x] ECDSA TSS 签名 → BTC 交易签名验证（secp256k1 复用）
- [x] EdDSA TSS 签名 → Solana 签名验证
- [x] EdDSA TSS 签名 → Sui 签名验证
- [x] EdDSA TSS 签名 → TON 签名验证（Ed25519 曲线兼容）
- [x] EdDSA TSS 签名 → Near 签名验证
- [x] EdDSA TSS 签名 → Aptos 签名验证
- [x] BSC 主网 EIP-155 交易构造与广播（TSS 联合签名）
- [x] BSC 主网交易广播（Lagrange 重建私钥单钥签名）

### 私钥重建

- [x] Lagrange 插值重建完整私钥（secp256k1，`vss.Shares.ReConstruct`）→ 公钥匹配 true
- [x] Lagrange 插值重建完整私钥（Ed25519）→ 公钥匹配 true
- [x] 重建 secp256k1 私钥对 EVM/BTC 交易重签验证
- [x] 重建 Ed25519 私钥公钥一致性验证（Solana/Sui/TON/Near/Aptos 共用）

### 工程集成

- [x] 独立 Go module（`demo_bsc/`）引用本地 tss-lib（`replace` 指令）
- [x] go-ethereum 集成（余额查询、nonce、gasPrice、EstimateGas、广播）
- [x] Gas Limit 动态估算（`EstimateGas × 1.1`）
- [x] BTC bech32 P2WPKH 编码（手动实现，无额外依赖）

### 未验证（需后续工作）

- [ ] TON 精确地址（wallet 合约 StateInit hash，需 tongo/tonutils-go SDK）
- [ ] BTC Taproot / Schnorr（tss-lib 不支持，需替换为 FROST 实现）
- [ ] gomobile 编译与 Android/iOS 集成
- [ ] Relay Server 实现
- [ ] PreParams 加密持久化与跨 Session 复用
- [ ] 断线重连与 Signing 超时处理
