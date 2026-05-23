# TSS BSC 转账 Demo

基于 tss-lib 的 3 方门限签名（t=2, n=3），演示在 BSC 主网发起真实转账。

## 前提

```bash
cd demo_bsc
go mod tidy
```

---

## 第一步：生成密钥分片

```bash
go run main.go keygen
```

输出 BSC 钱包地址，并将 3 份私钥分片保存至 `tss_bsc_keys.json`。

向打印出的地址充入少量 BNB（建议 >= 0.001 BNB）。

---

## 第二步：TSS 联合签名转账

```bash
go run main.go transfer <接收方地址> <数量BNB>

# 示例
go run main.go transfer 0xYourAddress 0.0001
```

3 方在本地协同完成 MPC 签名，广播交易到 BSC 主网，输出 TxHash 和 BSCScan 链接。

---

## 第三步：重建私钥后单钥签名转账

```bash
go run main.go transfer-sk <接收方地址> <数量BNB>

# 示例
go run main.go transfer-sk 0xYourAddress 0.0001
```

通过 Lagrange 插值从 3 份分片重建完整私钥，使用标准 ECDSA 签名广播交易，验证重建私钥与 TSS 公钥地址一致。

> **警告：** 第三步会在内存中还原完整私钥，仅供演示，生产环境中严禁执行。

---

## 文件说明

| 文件 | 说明 |
|------|------|
| `main.go` | 主程序 |
| `tss_bsc_keys.json` | Keygen 生成的私钥分片（勿泄露） |
| `go.mod` | 依赖声明，replace 指向本地 tss-lib |
