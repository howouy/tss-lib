// Demo: TSS BSC 真实链上转账
//
// 第一步: go run main.go keygen
//         → 生成三方私钥分片，打印 BSC 地址，保存密钥到 tss_bsc_keys.json
//
// 第二步: go run main.go transfer <接收方地址> <数量BNB>
//         → 加载分片，TSS 联合签名，广播真实交易到 BSC 主网
//
// 第三步: go run main.go transfer-sk <接收方地址> <数量BNB>
//         → Lagrange 插值重建完整私钥，用单私钥签名，广播真实交易到 BSC 主网
package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sort"
	"sync/atomic"
	"time"

	gocrypto "github.com/ethereum/go-ethereum/crypto"

	ethereum "github.com/ethereum/go-ethereum"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"

	tsscommon "github.com/bnb-chain/tss-lib/v3/common"
	"github.com/bnb-chain/tss-lib/v3/crypto/vss"
	"github.com/bnb-chain/tss-lib/v3/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v3/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v3/tss"
)

const (
	partyCount = 3
	threshold  = 2 // 全部 3 方参与

	keyFilePath = "tss_bsc_keys.json"
	bscRPC      = "https://bsc-dataseed.binance.org/"
	bscChainID  = int64(56)
)

// ──────────────────────────────────────────────────────
// 持久化结构
// ──────────────────────────────────────────────────────

type KeyFile struct {
	Keys []keygen.LocalPartySaveData `json:"keys"`
}

// ──────────────────────────────────────────────────────
// 入口
// ──────────────────────────────────────────────────────

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}
	switch os.Args[1] {
	case "keygen":
		stepKeygen()
	case "transfer":
		if len(os.Args) < 4 {
			fmt.Println("缺少参数: go run main.go transfer <接收方地址> <数量BNB>")
			os.Exit(1)
		}
		stepTransfer(os.Args[2], os.Args[3])
	case "transfer-sk":
		if len(os.Args) < 4 {
			fmt.Println("缺少参数: go run main.go transfer-sk <接收方地址> <数量BNB>")
			os.Exit(1)
		}
		stepTransferWithReconstructedKey(os.Args[2], os.Args[3])
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println("用法:")
	fmt.Println("  go run main.go keygen                                # 第一步: 生成密钥分片")
	fmt.Println("  go run main.go transfer <接收方地址> <数量BNB>        # 第二步: TSS 联合签名转账")
	fmt.Println("  go run main.go transfer-sk <接收方地址> <数量BNB>     # 第三步: 重建私钥后单钥签名转账")
}

// ──────────────────────────────────────────────────────
// 第一步: Keygen → 打印地址
// ──────────────────────────────────────────────────────

func stepKeygen() {
	total := time.Now()
	fmt.Println("=== 第一步: TSS 密钥生成 ===")
	fmt.Printf("方案: {t=%d, n=%d}，需要全部 %d 方参与\n\n", threshold, partyCount, threshold+1)

	partyIDs := tss.GenerateTestPartyIDs(partyCount)

	// 生成预参数
	fmt.Println("[1/2] 生成 ECDSA 预参数（约需 20-30s）...")
	preParams := make([]keygen.LocalPreParams, partyCount)
	for i := 0; i < partyCount; i++ {
		t0 := time.Now()
		p, err := keygen.GeneratePreParams(5 * time.Minute)
		if err != nil {
			panic(fmt.Sprintf("P%d 预参数失败: %v", i+1, err))
		}
		preParams[i] = *p
		fmt.Printf("  P%d 完成  耗时: %s\n", i+1, time.Since(t0).Round(time.Millisecond))
	}

	// Keygen
	fmt.Println("\n[2/2] 运行 Keygen 协议...")
	t0 := time.Now()
	savedKeys := runKeygen(partyIDs, preParams)
	fmt.Printf("  Keygen 完成  耗时: %s\n", time.Since(t0).Round(time.Millisecond))

	// 派生 BSC/EVM 地址
	pub := savedKeys[0].ECDSAPub
	ecPub := &ecdsa.PublicKey{Curve: tss.S256(), X: pub.X(), Y: pub.Y()}
	addr := gocrypto.PubkeyToAddress(*ecPub)

	// 保存密钥到文件
	bz, _ := json.MarshalIndent(KeyFile{Keys: savedKeys}, "", "  ")
	if err := os.WriteFile(keyFilePath, bz, 0600); err != nil {
		panic(fmt.Sprintf("保存密钥文件失败: %v", err))
	}

	fmt.Printf("\n总耗时: %s\n", time.Since(total).Round(time.Millisecond))
	fmt.Println()
	fmt.Println("════════════════════════════════════════════════")
	fmt.Printf("  BSC 钱包地址: %s\n", addr.Hex())
	fmt.Printf("  密钥分片已保存至: %s\n", keyFilePath)
	fmt.Println("════════════════════════════════════════════════")
	fmt.Println()
	fmt.Println("请向上述地址充入少量 BNB（建议 0.001 BNB 以上），")
	fmt.Println("充值确认后执行第二步:")
	fmt.Printf("  go run main.go transfer <接收方地址> <数量>\n")
	fmt.Printf("  示例: go run main.go transfer %s 0.0001\n", addr.Hex())
}

// ──────────────────────────────────────────────────────
// 第二步: 加载分片 → TSS 签名 → 广播
// ──────────────────────────────────────────────────────

func stepTransfer(toAddrStr, amountBNB string) {
	fmt.Println("=== 第二步: TSS BSC 链上转账 ===\n")

	// 1. 加载密钥分片
	fmt.Printf("[1/4] 加载密钥分片 (%s)...\n", keyFilePath)
	savedKeys, partyIDs := loadKeys()
	pub := savedKeys[0].ECDSAPub
	ecPub := &ecdsa.PublicKey{Curve: tss.S256(), X: pub.X(), Y: pub.Y()}
	fromAddr := gocrypto.PubkeyToAddress(*ecPub)
	toAddr := ethcommon.HexToAddress(toAddrStr)
	amountWei := bnbToWei(amountBNB)

	fmt.Printf("  发送方: %s\n", fromAddr.Hex())
	fmt.Printf("  接收方: %s\n", toAddr.Hex())
	fmt.Printf("  金额:   %s BNB (%s Wei)\n", amountBNB, amountWei.String())

	// 2. 连接 BSC 主网，查询链上状态
	fmt.Printf("\n[2/4] 连接 BSC 主网 (%s)...\n", bscRPC)
	client, err := ethclient.Dial(bscRPC)
	if err != nil {
		panic(fmt.Sprintf("连接 RPC 失败: %v\n请检查网络连接", err))
	}
	defer client.Close()
	ctx := context.Background()

	// 查询余额
	balance, err := client.BalanceAt(ctx, fromAddr, nil)
	if err != nil {
		panic(fmt.Sprintf("查询余额失败: %v", err))
	}
	fmt.Printf("  当前余额: %s Wei (%.6f BNB)\n",
		balance.String(), weiToBNBFloat(balance))

	// 查询 Nonce
	nonce, err := client.PendingNonceAt(ctx, fromAddr)
	if err != nil {
		panic(fmt.Sprintf("查询 nonce 失败: %v", err))
	}

	// 查询建议 GasPrice，BSC 最低 3 Gwei，加 20% 溢价保障上链
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		panic(fmt.Sprintf("查询 gasPrice 失败: %v", err))
	}
	minGas := new(big.Int).SetUint64(3_000_000_000) // 3 Gwei
	if gasPrice.Cmp(minGas) < 0 {
		gasPrice = minGas
	}
	gasPrice = new(big.Int).Mul(gasPrice, big.NewInt(120))
	gasPrice = new(big.Int).Div(gasPrice, big.NewInt(100))

	gasLimit := estimateGasLimit(ctx, client, fromAddr, toAddr, amountWei, nil)
	gasCost := new(big.Int).Mul(gasPrice, new(big.Int).SetUint64(gasLimit))
	totalCost := new(big.Int).Add(amountWei, gasCost)

	fmt.Printf("  Nonce:    %d\n", nonce)
	fmt.Printf("  GasPrice: %s Gwei\n", new(big.Int).Div(gasPrice, big.NewInt(1e9)).String())
	fmt.Printf("  GasLimit: %d\n", gasLimit)
	fmt.Printf("  预估手续费: %.8f BNB\n", weiToBNBFloat(gasCost))
	fmt.Printf("  总花费:   %.8f BNB\n", weiToBNBFloat(totalCost))

	// 余额检查
	if balance.Cmp(totalCost) < 0 {
		fmt.Printf("\n[ERROR] 余额不足!\n")
		fmt.Printf("  需要: %.8f BNB\n", weiToBNBFloat(totalCost))
		fmt.Printf("  余额: %.8f BNB\n", weiToBNBFloat(balance))
		os.Exit(1)
	}

	// 3. 构造交易 → 计算 EIP-155 签名哈希 → TSS 联合签名
	fmt.Println("\n[3/4] TSS 联合签名...")
	chainID := big.NewInt(bscChainID)
	signer := types.NewEIP155Signer(chainID)
	tx := types.NewTransaction(nonce, toAddr, amountWei, gasLimit, gasPrice, nil)

	// EIP-155 签名哈希: keccak256(RLP(nonce,gasPrice,gasLimit,to,value,data,chainID,0,0))
	txSignHash := signer.Hash(tx)
	fmt.Printf("  EIP-155 签名哈希: 0x%x\n", txSignHash)

	t0 := time.Now()
	txHashInt := new(big.Int).SetBytes(txSignHash[:])
	sigData := runSigning(partyIDs, savedKeys, txHashInt)
	fmt.Printf("  TSS 签名完成  耗时: %s\n", time.Since(t0).Round(time.Millisecond))

	// 组装标准 65 字节签名: R(32) || S(32) || recovery_byte(1)
	// EIP-155 signer 的 WithSignature 接受 recovery_byte = 0 or 1，内部自动转为 v = recid + chainID*2 + 35
	rBytes := make([]byte, 32)
	sBytes := make([]byte, 32)
	new(big.Int).SetBytes(sigData.R).FillBytes(rBytes)
	new(big.Int).SetBytes(sigData.S).FillBytes(sBytes)
	sig65 := make([]byte, 65)
	copy(sig65[0:32], rBytes)
	copy(sig65[32:64], sBytes)
	sig65[64] = sigData.SignatureRecovery[0] // 0 or 1

	signedTx, err := tx.WithSignature(signer, sig65)
	if err != nil {
		panic(fmt.Sprintf("组装签名交易失败: %v", err))
	}

	// 验证签名者地址与 TSS 地址一致
	sender, err := types.Sender(signer, signedTx)
	if err != nil {
		panic(fmt.Sprintf("恢复签名者地址失败: %v", err))
	}
	if sender != fromAddr {
		panic(fmt.Sprintf("签名者地址不匹配!\n  期望: %s\n  实际: %s", fromAddr.Hex(), sender.Hex()))
	}
	fmt.Printf("  签名者地址验证通过: %s\n", sender.Hex())

	// 4. 广播到 BSC 主网
	fmt.Println("\n[4/4] 广播交易...")
	if err := client.SendTransaction(ctx, signedTx); err != nil {
		panic(fmt.Sprintf("广播失败: %v", err))
	}

	txHash := signedTx.Hash().Hex()
	fmt.Println()
	fmt.Println("════════════════════════════════════════════════")
	fmt.Printf("  交易已广播!\n")
	fmt.Printf("  TxHash:  %s\n", txHash)
	fmt.Printf("  BSCScan: https://bscscan.com/tx/%s\n", txHash)
	fmt.Println("════════════════════════════════════════════════")
}

// ──────────────────────────────────────────────────────
// 第三步: Lagrange 重建私钥 → 单钥签名 → 广播
// ──────────────────────────────────────────────────────

func stepTransferWithReconstructedKey(toAddrStr, amountBNB string) {
	fmt.Println("=== 第三步: 重建私钥后链上转账（单私钥签名）===\n")
	fmt.Println("*** 警告: 此操作会暴露完整私钥，仅供演示，生产环境中严禁执行！***\n")

	// 1. 加载密钥分片并重建完整私钥
	fmt.Printf("[1/4] 加载分片 (%s) 并重建私钥...\n", keyFilePath)
	savedKeys, _ := loadKeys()
	privKey, fromAddr := reconstructPrivKey(savedKeys)
	toAddr := ethcommon.HexToAddress(toAddrStr)
	amountWei := bnbToWei(amountBNB)

	privKeyHex := fmt.Sprintf("0x%x", privKey.D.Bytes())
	fmt.Printf("  重建私钥: %s...%s\n", privKeyHex[:10], privKeyHex[len(privKeyHex)-6:])
	fmt.Printf("  派生地址: %s\n", fromAddr.Hex())
	fmt.Printf("  接收方:   %s\n", toAddr.Hex())
	fmt.Printf("  金额:     %s BNB\n", amountBNB)

	// 验证派生地址与 TSS 公钥一致
	tssAddr := gocrypto.PubkeyToAddress(privKey.PublicKey)
	if tssAddr != fromAddr {
		panic(fmt.Sprintf("地址不匹配! TSS=%s 重建=%s", tssAddr.Hex(), fromAddr.Hex()))
	}
	fmt.Printf("  地址验证: 与 TSS 公钥地址一致 ✓\n")

	// 2. 连接 BSC 主网
	fmt.Printf("\n[2/4] 连接 BSC 主网 (%s)...\n", bscRPC)
	client, err := ethclient.Dial(bscRPC)
	if err != nil {
		panic(fmt.Sprintf("连接 RPC 失败: %v", err))
	}
	defer client.Close()
	ctx := context.Background()

	balance, err := client.BalanceAt(ctx, fromAddr, nil)
	if err != nil {
		panic(fmt.Sprintf("查询余额失败: %v", err))
	}
	fmt.Printf("  当前余额: %.6f BNB\n", weiToBNBFloat(balance))

	nonce, err := client.PendingNonceAt(ctx, fromAddr)
	if err != nil {
		panic(fmt.Sprintf("查询 nonce 失败: %v", err))
	}

	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		panic(fmt.Sprintf("查询 gasPrice 失败: %v", err))
	}
	minGas := new(big.Int).SetUint64(3_000_000_000)
	if gasPrice.Cmp(minGas) < 0 {
		gasPrice = minGas
	}
	gasPrice = new(big.Int).Mul(gasPrice, big.NewInt(120))
	gasPrice = new(big.Int).Div(gasPrice, big.NewInt(100))

	gasLimit := estimateGasLimit(ctx, client, fromAddr, toAddr, amountWei, nil)
	gasCost := new(big.Int).Mul(gasPrice, new(big.Int).SetUint64(gasLimit))
	totalCost := new(big.Int).Add(amountWei, gasCost)

	fmt.Printf("  Nonce:    %d\n", nonce)
	fmt.Printf("  GasPrice: %s Gwei\n", new(big.Int).Div(gasPrice, big.NewInt(1e9)).String())
	fmt.Printf("  GasLimit: %d\n", gasLimit)
	fmt.Printf("  预估手续费: %.8f BNB\n", weiToBNBFloat(gasCost))

	if balance.Cmp(totalCost) < 0 {
		fmt.Printf("\n[ERROR] 余额不足! 需要 %.8f BNB，当前 %.8f BNB\n",
			weiToBNBFloat(totalCost), weiToBNBFloat(balance))
		os.Exit(1)
	}

	// 3. 构造交易，用重建私钥直接签名
	fmt.Println("\n[3/4] 用重建私钥签名交易...")
	chainID := big.NewInt(bscChainID)
	signer := types.NewEIP155Signer(chainID)
	tx := types.NewTransaction(nonce, toAddr, amountWei, gasLimit, gasPrice, nil)

	t0 := time.Now()
	signedTx, err := types.SignTx(tx, signer, privKey)
	if err != nil {
		panic(fmt.Sprintf("签名失败: %v", err))
	}
	fmt.Printf("  签名完成  耗时: %s\n", time.Since(t0).Round(time.Microsecond))

	sender, err := types.Sender(signer, signedTx)
	if err != nil {
		panic(fmt.Sprintf("恢复签名者失败: %v", err))
	}
	if sender != fromAddr {
		panic(fmt.Sprintf("签名者地址不匹配! 期望=%s 实际=%s", fromAddr.Hex(), sender.Hex()))
	}
	fmt.Printf("  签名者地址验证通过: %s\n", sender.Hex())

	// 4. 广播
	fmt.Println("\n[4/4] 广播交易...")
	if err := client.SendTransaction(ctx, signedTx); err != nil {
		panic(fmt.Sprintf("广播失败: %v", err))
	}

	txHash := signedTx.Hash().Hex()
	fmt.Println()
	fmt.Println("════════════════════════════════════════════════")
	fmt.Printf("  交易已广播! (重建私钥单钥签名)\n")
	fmt.Printf("  TxHash:  %s\n", txHash)
	fmt.Printf("  BSCScan: https://bscscan.com/tx/%s\n", txHash)
	fmt.Println("════════════════════════════════════════════════")
}

// reconstructPrivKey 用 Lagrange 插值从三份分片重建完整私钥
func reconstructPrivKey(savedKeys []keygen.LocalPartySaveData) (*ecdsa.PrivateKey, ethcommon.Address) {
	shares := make(vss.Shares, len(savedKeys))
	for i, k := range savedKeys {
		shares[i] = &vss.Share{
			Threshold: threshold,
			ID:        k.ShareID,
			Share:     k.Xi,
		}
	}
	privInt, err := shares.ReConstruct(tss.S256())
	if err != nil {
		panic(fmt.Sprintf("私钥重建失败: %v", err))
	}

	privBytes := make([]byte, 32)
	privInt.FillBytes(privBytes)
	privKey, err := gocrypto.ToECDSA(privBytes)
	if err != nil {
		panic(fmt.Sprintf("转换 ECDSA 私钥失败: %v", err))
	}
	addr := gocrypto.PubkeyToAddress(privKey.PublicKey)
	return privKey, addr
}

// ──────────────────────────────────────────────────────
// TSS 核心流程
// ──────────────────────────────────────────────────────

func runKeygen(partyIDs tss.SortedPartyIDs, preParams []keygen.LocalPreParams) []keygen.LocalPartySaveData {
	p2pCtx := tss.NewPeerContext(partyIDs)
	errCh := make(chan *tss.Error, partyCount)
	outCh := make(chan tss.Message, partyCount*partyCount*20)
	endCh := make(chan *keygen.LocalPartySaveData, partyCount)

	parties := make([]tss.Party, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, partyIDs[i], partyCount, threshold)
		params.SetNoProofMod() // 演示加速，生产环境请删除
		params.SetNoProofFac() // 演示加速，生产环境请删除
		parties[i] = keygen.NewLocalParty(params, outCh, endCh, preParams[i])
	}
	for _, p := range parties {
		go func(p tss.Party) {
			if err := p.Start(); err != nil {
				errCh <- err
			}
		}(p)
	}

	saved := make([]keygen.LocalPartySaveData, partyCount)
	var done int32
	for atomic.LoadInt32(&done) < int32(partyCount) {
		select {
		case err := <-errCh:
			panic(fmt.Sprintf("Keygen 错误: %v", err))
		case msg := <-outCh:
			go routeMsg(parties, msg, errCh)
		case save := <-endCh:
			idx, err := save.OriginalIndex()
			if err != nil {
				panic(err)
			}
			saved[idx] = *save
			atomic.AddInt32(&done, 1)
		}
	}
	// 按 ShareID 升序排列，保证与 partyIDs 顺序一致
	sort.Slice(saved, func(i, j int) bool {
		return saved[i].ShareID.Cmp(saved[j].ShareID) < 0
	})
	return saved
}

func runSigning(partyIDs tss.SortedPartyIDs, keys []keygen.LocalPartySaveData, msg *big.Int) *tsscommon.SignatureData {
	p2pCtx := tss.NewPeerContext(partyIDs)
	errCh := make(chan *tss.Error, partyCount)
	outCh := make(chan tss.Message, partyCount*partyCount*50)
	endCh := make(chan *tsscommon.SignatureData, partyCount)

	parties := make([]tss.Party, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, partyIDs[i], partyCount, threshold)
		parties[i] = signing.NewLocalParty(msg, params, keys[i], outCh, endCh)
	}
	for _, p := range parties {
		go func(p tss.Party) {
			if err := p.Start(); err != nil {
				errCh <- err
			}
		}(p)
	}

	var result *tsscommon.SignatureData
	var done int32
	for atomic.LoadInt32(&done) < int32(partyCount) {
		select {
		case err := <-errCh:
			panic(fmt.Sprintf("Signing 错误: %v", err))
		case msg := <-outCh:
			go routeMsg(parties, msg, errCh)
		case sig := <-endCh:
			if result == nil {
				result = sig
			}
			atomic.AddInt32(&done, 1)
		}
	}
	return result
}

// ──────────────────────────────────────────────────────
// 密钥文件加载
// ──────────────────────────────────────────────────────

func loadKeys() ([]keygen.LocalPartySaveData, tss.SortedPartyIDs) {
	bz, err := os.ReadFile(keyFilePath)
	if err != nil {
		panic(fmt.Sprintf("读取密钥文件失败: %v\n请先运行: go run main.go keygen", err))
	}
	var kf KeyFile
	if err := json.Unmarshal(bz, &kf); err != nil {
		panic(fmt.Sprintf("解析密钥文件失败: %v", err))
	}
	keys := kf.Keys

	// JSON 反序列化后 ECPoint 丢失曲线信息，需重新设置
	for i := range keys {
		for _, bxj := range keys[i].BigXj {
			bxj.SetCurve(tss.S256())
		}
		keys[i].ECDSAPub.SetCurve(tss.S256())
	}

	// 按 ShareID 升序排列
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].ShareID.Cmp(keys[j].ShareID) < 0
	})

	// 从 ShareID 重建 PartyID（ShareID 即为当初 keygen 时的 PartyID.Key）
	unsorted := make(tss.UnSortedPartyIDs, len(keys))
	for i, k := range keys {
		moniker := fmt.Sprintf("P%d", i+1)
		unsorted[i] = tss.NewPartyID(moniker, moniker, k.ShareID)
	}
	partyIDs := tss.SortPartyIDs(unsorted)
	return keys, partyIDs
}

// ──────────────────────────────────────────────────────
// 消息路由（模拟 P2P）
// ──────────────────────────────────────────────────────

func routeMsg(parties []tss.Party, msg tss.Message, errCh chan<- *tss.Error) {
	bz, _, err := msg.WireBytes()
	if err != nil {
		errCh <- parties[0].WrapError(err)
		return
	}
	send := func(p tss.Party) {
		pMsg, err2 := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
		if err2 != nil {
			errCh <- p.WrapError(err2)
			return
		}
		if _, err3 := p.Update(pMsg); err3 != nil {
			errCh <- err3
		}
	}
	if dest := msg.GetTo(); dest == nil {
		for _, p := range parties {
			if p.PartyID().Index != msg.GetFrom().Index {
				go send(p)
			}
		}
	} else {
		for _, p := range parties {
			if p.PartyID().Index == dest[0].Index {
				go send(p)
				return
			}
		}
	}
}

// ──────────────────────────────────────────────────────
// 工具函数
// ──────────────────────────────────────────────────────

// estimateGasLimit 向节点查询预估 gas，结果乘以 1.1 倍作为 gasLimit
func estimateGasLimit(ctx context.Context, client *ethclient.Client,
	from, to ethcommon.Address, value *big.Int, data []byte) uint64 {
	estimated, err := client.EstimateGas(ctx, ethereum.CallMsg{
		From:  from,
		To:    &to,
		Value: value,
		Data:  data,
	})
	if err != nil {
		// 查询失败时回退到 21000 的 1.1 倍
		return 23100
	}
	// 乘以 1.1（放大为 110%）
	return estimated * 110 / 100
}

// bnbToWei 将 BNB 字符串（如 "0.001"）转为 Wei
func bnbToWei(bnb string) *big.Int {
	f, ok := new(big.Float).SetString(bnb)
	if !ok {
		panic(fmt.Sprintf("无法解析金额: %s", bnb))
	}
	weiPerBNB := new(big.Float).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	wei, _ := new(big.Float).Mul(f, weiPerBNB).Int(nil)
	return wei
}

// weiToBNBFloat 将 Wei 转为 BNB 浮点数（仅用于显示）
func weiToBNBFloat(wei *big.Int) float64 {
	f := new(big.Float).SetInt(wei)
	weiPerBNB := new(big.Float).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	result, _ := new(big.Float).Quo(f, weiPerBNB).Float64()
	return result
}
