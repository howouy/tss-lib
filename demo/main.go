// Demo: TSS 三方私钥分片 —— Keygen + 联合签名 + 私钥重建
//
// 方案: {t=2, n=3} 门限，即需要全部 3 个参与方才能签名
//
// 注意: SetNoProofMod / SetNoProofFac 仅为加快演示速度，生产环境禁止使用！
//       私钥重建会彻底破坏 TSS 安全模型，仅供学习演示。
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/bnb-chain/tss-lib/v3/common"
	"github.com/bnb-chain/tss-lib/v3/crypto/vss"
	"github.com/bnb-chain/tss-lib/v3/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v3/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v3/tss"
)

const (
	partyCount = 3
	threshold  = 2 // 需要 threshold+1 = 3 方全部参与
)

func main() {
	demoStart := time.Now()

	fmt.Println("=== TSS 三方私钥分片 Demo ===")
	fmt.Printf("方案: {t=%d, n=%d}，需要 %d 方参与签名\n\n", threshold, partyCount, threshold+1)

	// ──────────────────────────────────────────────────────
	// 阶段 1: 生成预参数（Paillier 密钥 + 安全素数）
	// ──────────────────────────────────────────────────────
	phase1Start := time.Now()
	fmt.Println("[阶段 1/3] 生成预参数（每个参与方独立生成 Paillier 密钥，需要几分钟）...")

	preParams := make([]keygen.LocalPreParams, partyCount)
	for i := 0; i < partyCount; i++ {
		t0 := time.Now()
		p, err := keygen.GeneratePreParams(5 * time.Minute)
		if err != nil {
			panic(fmt.Sprintf("P%d 生成预参数失败: %v", i+1, err))
		}
		preParams[i] = *p
		fmt.Printf("  P%d 预参数完成  耗时: %s\n", i+1, time.Since(t0).Round(time.Millisecond))
	}
	fmt.Printf("  >> 阶段 1 总耗时: %s\n", time.Since(phase1Start).Round(time.Millisecond))

	// ──────────────────────────────────────────────────────
	// 阶段 2: Keygen —— 生成三个私钥分片
	// ──────────────────────────────────────────────────────
	phase2Start := time.Now()
	fmt.Println("\n[阶段 2/3] 密钥生成 (Keygen)...")

	// 创建参与方 ID（已按 key 排序，Index 自动赋值）
	partyIDs := tss.GenerateTestPartyIDs(partyCount)
	p2pCtx := tss.NewPeerContext(partyIDs)

	keyErrCh := make(chan *tss.Error, partyCount)
	keyOutCh := make(chan tss.Message, partyCount*partyCount*20)
	keyEndCh := make(chan *keygen.LocalPartySaveData, partyCount)

	keyParties := make([]tss.Party, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, partyIDs[i], partyCount, threshold)
		params.SetNoProofMod() // 仅演示用，跳过慢速 ZK 证明
		params.SetNoProofFac() // 仅演示用
		keyParties[i] = keygen.NewLocalParty(params, keyOutCh, keyEndCh, preParams[i])
	}
	for _, p := range keyParties {
		go func(p tss.Party) {
			if err := p.Start(); err != nil {
				keyErrCh <- err
			}
		}(p)
	}

	// 按原始索引存储 saveData，记录每个参与方完成时间
	savedKeys := make([]keygen.LocalPartySaveData, partyCount)
	var keyDone int32
keygenLoop:
	for {
		select {
		case err := <-keyErrCh:
			panic(fmt.Sprintf("Keygen 错误: %v", err))
		case msg := <-keyOutCh:
			go routeMsg(keyParties, msg, keyErrCh)
		case save := <-keyEndCh:
			idx, err := save.OriginalIndex()
			if err != nil {
				panic(fmt.Sprintf("获取参与方索引失败: %v", err))
			}
			savedKeys[idx] = *save
			fmt.Printf("  P%d 密钥分片生成完毕  (Keygen 已运行 %s)\n",
				idx+1, time.Since(phase2Start).Round(time.Millisecond))
			if atomic.AddInt32(&keyDone, 1) == int32(partyCount) {
				break keygenLoop
			}
		}
	}
	fmt.Printf("  >> 阶段 2 总耗时: %s\n", time.Since(phase2Start).Round(time.Millisecond))

	// 打印分片摘要
	pubKey := savedKeys[0].ECDSAPub
	fmt.Println("\n  -- 密钥分片信息 --")
	fmt.Printf("  群组公钥 X: 0x%x...\n", pubKey.X().Bytes()[:6])
	fmt.Printf("  群组公钥 Y: 0x%x...\n", pubKey.Y().Bytes()[:6])
	for i := 0; i < partyCount; i++ {
		fmt.Printf("  P%d ShareID : 0x%x...\n", i+1, savedKeys[i].ShareID.Bytes()[:6])
		fmt.Printf("  P%d Xi(分片): 0x%x...\n", i+1, savedKeys[i].Xi.Bytes()[:6])
	}

	// ──────────────────────────────────────────────────────
	// 阶段 3-A: 签名 —— 三方联合对转账交易签名
	// ──────────────────────────────────────────────────────
	phase3aStart := time.Now()
	fmt.Println("\n[阶段 3/3 - A] 联合签名 (Signing)...")

	// 构造模拟转账消息哈希（SHA-256 of 交易字符串）
	txStr := "FROM:0xAlice TO:0xBob AMOUNT:1.5ETH NONCE:42"
	txHash := sha256.Sum256([]byte(txStr))
	txMsg := new(big.Int).SetBytes(txHash[:])
	fmt.Printf("  交易: %s\n", txStr)
	fmt.Printf("  哈希: 0x%x\n\n", txHash)

	signErrCh := make(chan *tss.Error, partyCount)
	signOutCh := make(chan tss.Message, partyCount*partyCount*50)
	signEndCh := make(chan *common.SignatureData, partyCount)

	signCtx := tss.NewPeerContext(partyIDs)
	signParties := make([]tss.Party, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.S256(), signCtx, partyIDs[i], partyCount, threshold)
		// signing.NewLocalParty 内部自动调用 BuildLocalSaveDataSubset
		signParties[i] = signing.NewLocalParty(txMsg, params, savedKeys[i], signOutCh, signEndCh)
	}
	for _, p := range signParties {
		go func(p tss.Party) {
			if err := p.Start(); err != nil {
				signErrCh <- err
			}
		}(p)
	}

	var signDone int32
	var sigData *common.SignatureData
signLoop:
	for {
		select {
		case err := <-signErrCh:
			panic(fmt.Sprintf("Signing 错误: %v", err))
		case msg := <-signOutCh:
			go routeMsg(signParties, msg, signErrCh)
		case sig := <-signEndCh:
			if sigData == nil {
				sigData = sig // 取第一个即可，各方输出一致
			}
			if atomic.AddInt32(&signDone, 1) == int32(partyCount) {
				break signLoop
			}
		}
	}
	fmt.Printf("  >> 阶段 3-A 总耗时: %s\n", time.Since(phase3aStart).Round(time.Millisecond))

	// 验证 TSS 签名
	r := new(big.Int).SetBytes(sigData.R)
	s := new(big.Int).SetBytes(sigData.S)
	ecPub := ecdsa.PublicKey{Curve: tss.S256(), X: pubKey.X(), Y: pubKey.Y()}
	tssVerify := ecdsa.Verify(&ecPub, txHash[:], r, s)

	fmt.Printf("  签名 R: 0x%x...\n", sigData.R[:6])
	fmt.Printf("  签名 S: 0x%x...\n", sigData.S[:6])
	fmt.Printf("  TSS 联合签名验证: %v\n", tssVerify)

	// ──────────────────────────────────────────────────────
	// 阶段 3-B: 从三个分片重建原始私钥
	// ──────────────────────────────────────────────────────
	phase3bStart := time.Now()
	fmt.Println("\n[阶段 3/3 - B] 私钥重建 (ReConstruct)...")
	fmt.Println("  *** 警告: 此操作会破坏 TSS 安全模型，仅供演示！***\n")

	// 收集三个 Shamir 份额，进行 Lagrange 插值
	shares := make(vss.Shares, partyCount)
	for i := 0; i < partyCount; i++ {
		shares[i] = &vss.Share{
			Threshold: threshold,
			ID:        savedKeys[i].ShareID,
			Share:     savedKeys[i].Xi,
		}
	}

	privKeyInt, err := shares.ReConstruct(tss.S256())
	if err != nil {
		panic(fmt.Sprintf("私钥重建失败: %v", err))
	}

	// 验证: 重建私钥推导公钥 == 群组公钥
	recX, recY := tss.S256().ScalarBaseMult(privKeyInt.Bytes())
	matched := recX.Cmp(pubKey.X()) == 0 && recY.Cmp(pubKey.Y()) == 0

	fmt.Printf("  重建私钥: 0x%x...\n", privKeyInt.Bytes()[:6])
	fmt.Printf("  推导公钥 X: 0x%x...\n", recX.Bytes()[:6])
	fmt.Printf("  群组公钥 X: 0x%x...\n", pubKey.X().Bytes()[:6])
	fmt.Printf("  公钥匹配: %v\n", matched)
	fmt.Printf("  >> 阶段 3-B 总耗时: %s\n", time.Since(phase3bStart).Round(time.Millisecond))

	if !matched {
		fmt.Println("\n  [FAIL] 私钥重建失败，公钥不匹配")
		return
	}

	// 用重建的完整私钥对同一笔交易签名，验证等价性
	ecSK := &ecdsa.PrivateKey{PublicKey: ecPub, D: privKeyInt}
	r2, s2, err := ecdsa.Sign(rand.Reader, ecSK, txHash[:])
	if err != nil {
		panic(fmt.Sprintf("单密钥签名失败: %v", err))
	}
	singleVerify := ecdsa.Verify(&ecPub, txHash[:], r2, s2)
	fmt.Printf("\n  用重建私钥对同一交易重新签名验证: %v\n", singleVerify)

	// ──────────────────────────────────────────────────────
	// 汇总
	// ──────────────────────────────────────────────────────
	fmt.Println("\n=== Demo 完成 ===")
	fmt.Println("各阶段耗时汇总:")
	fmt.Printf("  阶段 1 - 预参数生成 (x%d):  %s\n", partyCount, time.Since(phase1Start).Round(time.Millisecond))
	fmt.Printf("  阶段 2 - Keygen:             %s\n", time.Since(phase2Start).Round(time.Millisecond))
	fmt.Printf("  阶段 3-A - 联合签名:          %s\n", time.Since(phase3aStart).Round(time.Millisecond))
	fmt.Printf("  阶段 3-B - 私钥重建:          %s\n", time.Since(phase3bStart).Round(time.Millisecond))
	fmt.Printf("  全流程总耗时:                 %s\n", time.Since(demoStart).Round(time.Millisecond))
	fmt.Println("\n结果:")
	fmt.Printf("  Keygen:      生成了 %d 个私钥分片 (Xi), 无任何一方知道完整私钥\n", partyCount)
	fmt.Printf("  Signing:     %d 方联合签名验证=%v\n", partyCount, tssVerify)
	fmt.Printf("  Reconstruct: Lagrange 插值重建, 公钥匹配=%v, 单钥签名验证=%v\n", matched, singleVerify)
}

// routeMsg 模拟网络传输：将消息路由到目标参与方
func routeMsg(parties []tss.Party, msg tss.Message, errCh chan<- *tss.Error) {
	bz, _, err := msg.WireBytes()
	if err != nil {
		errCh <- parties[0].WrapError(err)
		return
	}
	dest := msg.GetTo()
	send := func(p tss.Party) {
		// 每个接收方独立解析，避免共享可变状态
		pMsg, err2 := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
		if err2 != nil {
			errCh <- p.WrapError(err2)
			return
		}
		if _, err3 := p.Update(pMsg); err3 != nil {
			errCh <- err3
		}
	}
	if dest == nil {
		// 广播：发给除自己以外的所有参与方
		for _, p := range parties {
			if p.PartyID().Index == msg.GetFrom().Index {
				continue
			}
			go send(p)
		}
	} else {
		// 点对点：发给指定参与方
		for _, p := range parties {
			if p.PartyID().Index == dest[0].Index {
				go send(p)
				return
			}
		}
	}
}
