AVE Agent Wallet 技术方案（TEE-Centric EOA Agent Wallet）
一、方案定位
产品定位

AVE Agent Wallet 是：

面向 Web3 高频交易、AI Agent、自动挂单、跟单、量化策略的下一代智能钱包系统。

核心目标：

保持 EOA 兼容性
+
支持 AI 自动交易
+
支持用户离线挂单
+
不暴露主私钥
+
支持恢复与跨设备
+
兼容 Meme / 土狗 / anti-bot token
二、为什么不采用纯 4337 Smart Account？

虽然：

ERC-4337 + Session Key

是长期方向。

但当前现实问题：

1. 很多代币限制非 EOA

例如：

tx.origin == msg.sender
isContract(msg.sender)

导致：

Safe
4337
Smart Account

可能：

无法买入
无法卖出
无法转账
被高税
被黑名单

尤其：

Meme
Launch token
Bot-protected token

问题严重。

2. 高频交易兼容性

EOA：

兼容性最好
速度最快
Gas 最低
生态最成熟

因此：

当前阶段：

推荐：
EOA + TEE-Centric Agent Architecture

而不是：

Full Smart Account。
三、核心架构
最终架构图
                    Passkey
                        ↓
             用户身份认证 / 授权
                        ↓
        ┌────────────────────────┐
        │      Device TEE        │
        │ Secure Enclave         │
        │ Android StrongBox      │
        │                        │
        │  Master Key (EOA)      │
        │  Share A               │
        └────────────────────────┘
                        ↓
                 SSS Recovery
        ┌──────────────┴──────────────┐
        │                             │
 Cloud Backup Share B         Server TEE Share C
        │                             │
        └──────────────┬──────────────┘
                       ↓
              Recovery / Migration

==================================================

            用户开启 Agent Trading
                       ↓
                 Passkey 授权
                       ↓
              Session Policy 创建
                       ↓
         Cloud TEE Session Signing Engine
                       ↓
                Risk Engine
                       ↓
             Policy Validation
                       ↓
                 TEE Sign Tx
                       ↓
                Broadcast Tx
四、密钥体系设计
1. 主私钥（Master Key）

类型：

EOA 私钥

用途：

资产最终控制权
大额转账
提现
恢复
Session 授权

特点：

默认不可导出
默认不离开设备TEE
默认不参与后台自动交易

存储：

iOS：Secure Enclave
Android：StrongBox / TEE
五、SSS 分片设计

主私钥：

采用：

Shamir Secret Sharing

推荐：

2-of-3
Share 分布
Share	存储位置	用途
Share A	用户设备 TEE	本地控制
Share B	用户云备份	换机恢复
Share C	平台安全 TEE/HSM	恢复辅助
六、Recovery 设计
支持：
1. 云恢复
iCloud
Google Drive
加密云存储
2. 社交恢复

Guardian：

朋友
家人
备用设备
企业管理员
硬件钱包

推荐：

2-of-3
3-of-5
3. 跨设备恢复

支持：

旧设备迁移
扫码迁移
Passkey 恢复
Guardian 恢复
七、Emergency Export

允许：

紧急导出完整私钥。

但：

必须：

Passkey
+
二次验证
+
冷却期
+
设备风险检查
+
旧设备通知

推荐：

24h 延迟

导出后：

关闭 Agent Mode
撤销 Session
作废旧 Share
提示迁移资产
八、为什么选择 EOA Agent Wallet？

核心原因：

EOA 兼容性无敌。

特别：

Meme
Bot-protected token
launch token

相比：

Smart Account

EOA：

兼容性更强
更适合高频
更适合土狗
九、Agent Trading 设计
核心思想

不是：

后端拿主私钥

而是：

用户授权有限自动交易权。
十、Session Policy

用户在线时：

通过：

Passkey
FaceID
TouchID

授权：

未来24h允许AI交易
Session Policy 示例
{
  "expire": "24h",
  "daily_limit": "1000 USDT",
  "single_tx_limit": "100 USDT",
  "allowed_dex": [
    "Uniswap",
    "Pancake"
  ],
  "allowed_tokens": [
    "ETH",
    "USDC",
    "SOL"
  ],
  "max_slippage": "1%",
  "allow_transfer": false,
  "allow_unlimited_approve": false
}
十一、Session Key 设计

注意：

Session Key ≠ 主私钥。

Session Key：

本质：

临时受限交易权限

用途：

挂单
AI交易
跟单
自动止盈止损
自动策略
十二、TEE 的真正作用

TEE：

不是：

替代钱包。

而是：

保护 Session Key。

Session Key：

只存在于：

Cloud TEE

例如：

AWS Nitro Enclave
Intel SGX
AMD SEV
十三、签名流程
用户在线时
Passkey 授权
↓
生成 Session Policy
↓
TEE 创建 Session Key
↓
Session Key 进入 TEE
用户离线后
AI Agent 提交 Order Intent
↓
Risk Engine 风控
↓
TEE 解析交易
↓
Policy 校验
↓
TEE Sign
↓
广播交易
十四、关键安全原则（极重要）
TEE 禁止暴露：
sign(raw_tx)

只能提供：

policy_sign(tx, policy, risk_token)
十五、TEE 内部必须校验
必须：
Token 白名单
DEX 白名单
限额
有效期
nonce
滑点
method_id
approve 风险
十六、EVM 高危方法限制

默认禁止：

approve unlimited
setApprovalForAll
delegatecall
未知 router
未知 permit

推荐：

精确额度 approve
自动 revoke
短期 permit
十七、风控体系
外部 Risk Engine

负责：

黑名单
钓鱼
MEV
价格异常
IP异常
行为异常
频率异常
资金风险
TEE 内部 Policy Engine

负责：

最终不可绕过规则

例如：

额度
Token
时间
方法
DEX
十八、最大风险点（非常重要）
1. 后端不要长期持有两份 Master Share

否则：

本质变成托管钱包

正确做法：

主私钥永不进入业务服务器
2. TEE 不是绝对安全

风险：

side-channel
供应链
硬件漏洞
云厂商

因此：

大额交易必须本地确认
3. Session Key 泄露

风险：

自动交易失控

解决：

短有效期
限额
可撤销
风控熔断
十九、冷热分层（推荐）
热层（高频）
Session Key
TEE
温层
本地 TEE Master Key
冷层
Recovery / Export
二十、未来升级路线
第一阶段（当前）
EOA Agent Wallet
第二阶段

引入：

TEE + MPC Hybrid

用于：

大额资产
企业钱包
机构托管
第三阶段

部分迁移：

4337 Trading Vault
二十一、最终产品定义（推荐）
英文
AVE Agent Wallet

A TEE-centric EOA-based intelligent wallet infrastructure designed for AI trading, delegated execution, social recovery, and secure automated transactions.

中文
AVE 智能 Agent 钱包

一套基于 EOA 与 TEE 的智能钱包基础设施，支持 AI 自动交易、委托执行、社交恢复、安全挂单与高频交易场景。