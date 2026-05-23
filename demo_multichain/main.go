// Demo: TSS 多链钱包 —— EVM + Solana + Sui + BTC + TON + Near + Aptos
//
// 方案: {t=2, n=3} 门限
//   secp256k1 (ECDSA): EVM 全系、BTC Legacy(P2PKH)、BTC SegWit(P2WPKH)
//   Ed25519   (EdDSA): Solana、Sui、TON（曲线兼容）、Near、Aptos
//
// 注意:
//   SetNoProofMod/SetNoProofFac 仅加快演示，生产环境禁止使用！
//   私钥重建会破坏 TSS 安全模型，仅供学习演示。
//   TON 地址为简化版（真实地址需 wallet 合约 StateInit hash），仅验证曲线兼容性。
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"

	"github.com/bnb-chain/tss-lib/v3/common"
	"github.com/bnb-chain/tss-lib/v3/crypto/vss"
	eckeygen "github.com/bnb-chain/tss-lib/v3/ecdsa/keygen"
	ecsigning "github.com/bnb-chain/tss-lib/v3/ecdsa/signing"
	edkeygen "github.com/bnb-chain/tss-lib/v3/eddsa/keygen"
	edsigning "github.com/bnb-chain/tss-lib/v3/eddsa/signing"
	"github.com/bnb-chain/tss-lib/v3/tss"
)

const (
	partyCount = 3
	threshold  = 2
)

func main() {
	demoStart := time.Now()
	fmt.Println("=== TSS 多链钱包 Demo (EVM + BTC + Solana + Sui + TON + Near + Aptos) ===")
	fmt.Printf("方案: {t=%d, n=%d}，全部 %d 方参与\n\n", threshold, partyCount, threshold+1)

	partyIDs := tss.GenerateTestPartyIDs(partyCount)

	// ──────────────────────────────────────────────────────
	// 阶段 1: ECDSA 预参数（secp256k1 需要，EdDSA 不需要）
	// ──────────────────────────────────────────────────────
	phase1Start := time.Now()
	fmt.Println("[阶段 1/4] 生成 ECDSA 预参数（EVM/BTC 专用，需约 20s）...")
	preParams := make([]eckeygen.LocalPreParams, partyCount)
	for i := 0; i < partyCount; i++ {
		t0 := time.Now()
		p, err := eckeygen.GeneratePreParams(5 * time.Minute)
		if err != nil {
			panic(fmt.Sprintf("P%d 预参数失败: %v", i+1, err))
		}
		preParams[i] = *p
		fmt.Printf("  P%d 完成  耗时: %s\n", i+1, time.Since(t0).Round(time.Millisecond))
	}
	phase1Dur := time.Since(phase1Start)
	fmt.Printf("  >> 阶段 1 耗时: %s\n", phase1Dur.Round(time.Millisecond))

	// ──────────────────────────────────────────────────────
	// 阶段 2: 两次 Keygen
	//   2a: ECDSA Keygen (secp256k1) → EVM + BTC 分片
	//   2b: EdDSA Keygen (Ed25519)   → Solana + Sui + TON + Near + Aptos 分片
	// ──────────────────────────────────────────────────────
	fmt.Println("\n[阶段 2/4] 密钥生成（两条曲线各跑一次 Keygen）...")

	t2a := time.Now()
	fmt.Println("  [2a] ECDSA Keygen (secp256k1) ...")
	ecSavedKeys := runECDSAKeygen(partyIDs, preParams)
	phase2aDur := time.Since(t2a)
	fmt.Printf("  >> ECDSA Keygen 耗时: %s\n", phase2aDur.Round(time.Millisecond))

	t2b := time.Now()
	fmt.Println("  [2b] EdDSA Keygen (Ed25519) ...")
	edSavedKeys := runEdDSAKeygen(partyIDs)
	phase2bDur := time.Since(t2b)
	fmt.Printf("  >> EdDSA Keygen 耗时: %s\n", phase2bDur.Round(time.Millisecond))

	// ──────────────────────────────────────────────────────
	// 阶段 3: 派生各链地址
	// ──────────────────────────────────────────────────────
	fmt.Println("\n[阶段 3/4] 派生多链地址...")

	ecPub := ecSavedKeys[0].ECDSAPub
	edPub := edSavedKeys[0].EDDSAPub

	// secp256k1 链
	evmAddr := deriveEVMAddress(ecPub.X(), ecPub.Y())
	btcLegacyAddr := deriveBTCLegacyAddress(ecPub.X(), ecPub.Y())
	btcSegWitAddr := deriveBTCSegWitAddress(ecPub.X(), ecPub.Y())

	// Ed25519 链
	solanaAddr := deriveSolanaAddress(edPub.X(), edPub.Y())
	suiAddr := deriveSuiAddress(edPub.X(), edPub.Y())
	tonAddr := deriveTONAddress(edPub.X(), edPub.Y())
	nearAddr := deriveNearAddress(edPub.X(), edPub.Y())
	aptosAddr := deriveAptosAddress(edPub.X(), edPub.Y())

	fmt.Printf("  EVM          地址: %s\n", evmAddr)
	fmt.Printf("  BTC Legacy   地址: %s\n", btcLegacyAddr)
	fmt.Printf("  BTC SegWit   地址: %s\n", btcSegWitAddr)
	fmt.Printf("  Solana       地址: %s\n", solanaAddr)
	fmt.Printf("  Sui          地址: %s\n", suiAddr)
	fmt.Printf("  TON          地址: %s  (简化版，见注释)\n", tonAddr)
	fmt.Printf("  Near         地址: %s\n", nearAddr)
	fmt.Printf("  Aptos        地址: %s\n", aptosAddr)

	fmt.Println("\n  -- 私钥分片摘要 --")
	for i := 0; i < partyCount; i++ {
		fmt.Printf("  P%d  ECDSA Xi: 0x%x...  EdDSA Xi: 0x%x...\n",
			i+1,
			ecSavedKeys[i].Xi.Bytes()[:4],
			edSavedKeys[i].Xi.Bytes()[:4],
		)
	}

	// ──────────────────────────────────────────────────────
	// 阶段 4-A: 各链各签一笔模拟转账
	// ──────────────────────────────────────────────────────
	fmt.Println("\n[阶段 4/4 - A] 联合签名（每条链独立走一轮 MPC Signing）...")

	ecPubKey := ecdsa.PublicKey{Curve: tss.S256(), X: ecPub.X(), Y: ecPub.Y()}
	edPubKey := &edwards.PublicKey{Curve: tss.Edwards(), X: edPub.X(), Y: edPub.Y()}

	// EVM
	t4a := time.Now()
	evmTx := "EVM  FROM:0xAlice TO:0xBob   AMOUNT:1.0ETH"
	evmHash := sha256.Sum256([]byte(evmTx))
	evmSig := runECDSASigning(partyIDs, ecSavedKeys, new(big.Int).SetBytes(evmHash[:]))
	evmOk := ecdsa.Verify(&ecPubKey, evmHash[:], new(big.Int).SetBytes(evmSig.R), new(big.Int).SetBytes(evmSig.S))
	phase4aDur := time.Since(t4a)
	fmt.Printf("  [EVM]    %s\n           签名验证: %v  耗时: %s\n", evmTx, evmOk, phase4aDur.Round(time.Millisecond))

	// BTC（复用 secp256k1 分片，签名算法与 EVM 相同）
	t4b := time.Now()
	btcTx := "BTC  FROM:1Alice  TO:1Bob    AMOUNT:0.01BTC"
	btcHash := sha256.Sum256([]byte(btcTx))
	btcSig := runECDSASigning(partyIDs, ecSavedKeys, new(big.Int).SetBytes(btcHash[:]))
	btcOk := ecdsa.Verify(&ecPubKey, btcHash[:], new(big.Int).SetBytes(btcSig.R), new(big.Int).SetBytes(btcSig.S))
	phase4bDur := time.Since(t4b)
	fmt.Printf("  [BTC]    %s\n           签名验证: %v  耗时: %s\n", btcTx, btcOk, phase4bDur.Round(time.Millisecond))

	// Solana
	t4c := time.Now()
	solanaTx := "SOL  FROM:Alice   TO:Bob     AMOUNT:10.0SOL"
	solanaHash := sha256.Sum256([]byte(solanaTx))
	solanaSig := runEdDSASigning(partyIDs, edSavedKeys, new(big.Int).SetBytes(solanaHash[:]))
	solanaOk := edwards.Verify(edPubKey, solanaHash[:], new(big.Int).SetBytes(solanaSig.R), new(big.Int).SetBytes(solanaSig.S))
	phase4cDur := time.Since(t4c)
	fmt.Printf("  [Solana] %s\n           签名验证: %v  耗时: %s\n", solanaTx, solanaOk, phase4cDur.Round(time.Millisecond))

	// Sui（复用 Ed25519 分片）
	t4d := time.Now()
	suiTx := "SUI  FROM:Alice   TO:Bob     AMOUNT:5.0SUI"
	suiHash := sha256.Sum256([]byte(suiTx))
	suiSig := runEdDSASigning(partyIDs, edSavedKeys, new(big.Int).SetBytes(suiHash[:]))
	suiOk := edwards.Verify(edPubKey, suiHash[:], new(big.Int).SetBytes(suiSig.R), new(big.Int).SetBytes(suiSig.S))
	phase4dDur := time.Since(t4d)
	fmt.Printf("  [Sui]    %s\n           签名验证: %v  耗时: %s\n", suiTx, suiOk, phase4dDur.Round(time.Millisecond))

	// TON（Ed25519，签名格式与 Solana/Sui 相同）
	t4e := time.Now()
	tonTx := "TON  FROM:Alice   TO:Bob     AMOUNT:1.0TON"
	tonHash := sha256.Sum256([]byte(tonTx))
	tonSig := runEdDSASigning(partyIDs, edSavedKeys, new(big.Int).SetBytes(tonHash[:]))
	tonOk := edwards.Verify(edPubKey, tonHash[:], new(big.Int).SetBytes(tonSig.R), new(big.Int).SetBytes(tonSig.S))
	phase4eDur := time.Since(t4e)
	fmt.Printf("  [TON]    %s\n           签名验证: %v  耗时: %s\n", tonTx, tonOk, phase4eDur.Round(time.Millisecond))

	// Near（Ed25519）
	t4f := time.Now()
	nearTx := "NEAR FROM:alice.near TO:bob.near AMOUNT:5.0NEAR"
	nearHash := sha256.Sum256([]byte(nearTx))
	nearSig := runEdDSASigning(partyIDs, edSavedKeys, new(big.Int).SetBytes(nearHash[:]))
	nearOk := edwards.Verify(edPubKey, nearHash[:], new(big.Int).SetBytes(nearSig.R), new(big.Int).SetBytes(nearSig.S))
	phase4fDur := time.Since(t4f)
	fmt.Printf("  [Near]   %s\n           签名验证: %v  耗时: %s\n", nearTx, nearOk, phase4fDur.Round(time.Millisecond))

	// Aptos（Ed25519）
	t4g := time.Now()
	aptosTx := "APT  FROM:0xAlice TO:0xBob   AMOUNT:10.0APT"
	aptosHash := sha256.Sum256([]byte(aptosTx))
	aptosSig := runEdDSASigning(partyIDs, edSavedKeys, new(big.Int).SetBytes(aptosHash[:]))
	aptosOk := edwards.Verify(edPubKey, aptosHash[:], new(big.Int).SetBytes(aptosSig.R), new(big.Int).SetBytes(aptosSig.S))
	phase4gDur := time.Since(t4g)
	fmt.Printf("  [Aptos]  %s\n           签名验证: %v  耗时: %s\n", aptosTx, aptosOk, phase4gDur.Round(time.Millisecond))

	// ──────────────────────────────────────────────────────
	// 阶段 4-B: 重建所有链私钥
	// ──────────────────────────────────────────────────────
	fmt.Println("\n[阶段 4/4 - B] 重建所有链私钥（Lagrange 插值）...")
	fmt.Println("  *** 警告: 仅供演示，生产环境中禁止执行此操作！***\n")

	tRec := time.Now()

	// 重建 secp256k1 私钥 → EVM + BTC
	ecShares := make(vss.Shares, partyCount)
	for i := 0; i < partyCount; i++ {
		ecShares[i] = &vss.Share{Threshold: threshold, ID: ecSavedKeys[i].ShareID, Share: ecSavedKeys[i].Xi}
	}
	ecPriv, err := ecShares.ReConstruct(tss.S256())
	if err != nil {
		panic(fmt.Sprintf("secp256k1 私钥重建失败: %v", err))
	}
	ecRecX, _ := tss.S256().ScalarBaseMult(ecPriv.Bytes())
	ecKeyMatch := ecRecX.Cmp(ecPub.X()) == 0

	// 重建 Ed25519 私钥 → Solana + Sui + TON + Near + Aptos
	edShares := make(vss.Shares, partyCount)
	for i := 0; i < partyCount; i++ {
		edShares[i] = &vss.Share{Threshold: threshold, ID: edSavedKeys[i].ShareID, Share: edSavedKeys[i].Xi}
	}
	edPriv, err := edShares.ReConstruct(tss.Edwards())
	if err != nil {
		panic(fmt.Sprintf("Ed25519 私钥重建失败: %v", err))
	}
	edRecX, _ := tss.Edwards().ScalarBaseMult(edPriv.Bytes())
	edKeyMatch := edRecX.Cmp(edPub.X()) == 0

	recDur := time.Since(tRec)

	fmt.Printf("  EVM/BTC 私钥:    0x%x...  公钥匹配: %v\n", ecPriv.Bytes()[:4], ecKeyMatch)
	fmt.Printf("  Sol/Sui/TON/Near/Aptos 私钥: 0x%x...  公钥匹配: %v\n", edPriv.Bytes()[:4], edKeyMatch)
	fmt.Printf("  >> 重建耗时: %s\n", recDur.Round(time.Millisecond))

	// 用重建私钥验证 EVM 和 BTC 签名
	ecSK := &ecdsa.PrivateKey{PublicKey: ecPubKey, D: ecPriv}
	r2, s2, _ := ecdsa.Sign(rand.Reader, ecSK, evmHash[:])
	evmReSig := ecdsa.Verify(&ecPubKey, evmHash[:], r2, s2)
	r3, s3, _ := ecdsa.Sign(rand.Reader, ecSK, btcHash[:])
	btcReSig := ecdsa.Verify(&ecPubKey, btcHash[:], r3, s3)
	fmt.Printf("  用重建私钥对 EVM 交易重签验证: %v\n", evmReSig)
	fmt.Printf("  用重建私钥对 BTC 交易重签验证: %v\n", btcReSig)

	// ──────────────────────────────────────────────────────
	// 汇总
	// ──────────────────────────────────────────────────────
	fmt.Println("\n=== 完成 ===")
	fmt.Println("各阶段耗时:")
	fmt.Printf("  阶段 1  - ECDSA 预参数:       %s\n", phase1Dur.Round(time.Millisecond))
	fmt.Printf("  阶段 2a - ECDSA Keygen:        %s\n", phase2aDur.Round(time.Millisecond))
	fmt.Printf("  阶段 2b - EdDSA Keygen:        %s\n", phase2bDur.Round(time.Millisecond))
	fmt.Printf("  阶段 4a - EVM 签名:            %s\n", phase4aDur.Round(time.Millisecond))
	fmt.Printf("  阶段 4b - BTC 签名:            %s\n", phase4bDur.Round(time.Millisecond))
	fmt.Printf("  阶段 4c - Solana 签名:         %s\n", phase4cDur.Round(time.Millisecond))
	fmt.Printf("  阶段 4d - Sui 签名:            %s\n", phase4dDur.Round(time.Millisecond))
	fmt.Printf("  阶段 4e - TON 签名:            %s\n", phase4eDur.Round(time.Millisecond))
	fmt.Printf("  阶段 4f - Near 签名:           %s\n", phase4fDur.Round(time.Millisecond))
	fmt.Printf("  阶段 4g - Aptos 签名:          %s\n", phase4gDur.Round(time.Millisecond))
	fmt.Printf("  阶段 4h - 私钥重建 (x2):       %s\n", recDur.Round(time.Millisecond))
	fmt.Printf("  全流程总耗时:                  %s\n", time.Since(demoStart).Round(time.Millisecond))

	fmt.Println("\n多链钱包验证结果:")
	fmt.Printf("  EVM        %s  签名=%v 重建=%v\n", evmAddr, evmOk, ecKeyMatch)
	fmt.Printf("  BTC Legacy %s  签名=%v 重建=%v\n", btcLegacyAddr, btcOk, ecKeyMatch)
	fmt.Printf("  BTC SegWit %s  签名=%v 重建=%v\n", btcSegWitAddr, btcOk, ecKeyMatch)
	fmt.Printf("  Solana     %s  签名=%v 重建=%v\n", solanaAddr, solanaOk, edKeyMatch)
	fmt.Printf("  Sui        %s  签名=%v 重建=%v\n", suiAddr, suiOk, edKeyMatch)
	fmt.Printf("  TON        %s  签名=%v 重建=%v\n", tonAddr, tonOk, edKeyMatch)
	fmt.Printf("  Near       %s  签名=%v 重建=%v\n", nearAddr, nearOk, edKeyMatch)
	fmt.Printf("  Aptos      %s  签名=%v 重建=%v\n", aptosAddr, aptosOk, edKeyMatch)
}

// ──────────────────────────────────────────────────────
// Keygen
// ──────────────────────────────────────────────────────

func runECDSAKeygen(partyIDs tss.SortedPartyIDs, preParams []eckeygen.LocalPreParams) []eckeygen.LocalPartySaveData {
	p2pCtx := tss.NewPeerContext(partyIDs)
	errCh := make(chan *tss.Error, partyCount)
	outCh := make(chan tss.Message, partyCount*partyCount*20)
	endCh := make(chan *eckeygen.LocalPartySaveData, partyCount)

	parties := make([]tss.Party, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, partyIDs[i], partyCount, threshold)
		params.SetNoProofMod()
		params.SetNoProofFac()
		parties[i] = eckeygen.NewLocalParty(params, outCh, endCh, preParams[i])
	}
	for _, p := range parties {
		go func(p tss.Party) {
			if err := p.Start(); err != nil {
				errCh <- err
			}
		}(p)
	}

	saved := make([]eckeygen.LocalPartySaveData, partyCount)
	var done int32
	for atomic.LoadInt32(&done) < int32(partyCount) {
		select {
		case err := <-errCh:
			panic(fmt.Sprintf("ECDSA Keygen 错误: %v", err))
		case msg := <-outCh:
			go routeMsg(parties, msg, errCh)
		case save := <-endCh:
			idx, err := save.OriginalIndex()
			if err != nil {
				panic(fmt.Sprintf("ECDSA OriginalIndex 失败: %v", err))
			}
			saved[idx] = *save
			atomic.AddInt32(&done, 1)
		}
	}
	return saved
}

func runEdDSAKeygen(partyIDs tss.SortedPartyIDs) []edkeygen.LocalPartySaveData {
	p2pCtx := tss.NewPeerContext(partyIDs)
	errCh := make(chan *tss.Error, partyCount)
	outCh := make(chan tss.Message, partyCount*partyCount*20)
	endCh := make(chan *edkeygen.LocalPartySaveData, partyCount)

	parties := make([]tss.Party, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.Edwards(), p2pCtx, partyIDs[i], partyCount, threshold)
		parties[i] = edkeygen.NewLocalParty(params, outCh, endCh)
	}
	for _, p := range parties {
		go func(p tss.Party) {
			if err := p.Start(); err != nil {
				errCh <- err
			}
		}(p)
	}

	saved := make([]edkeygen.LocalPartySaveData, partyCount)
	var done int32
	for atomic.LoadInt32(&done) < int32(partyCount) {
		select {
		case err := <-errCh:
			panic(fmt.Sprintf("EdDSA Keygen 错误: %v", err))
		case msg := <-outCh:
			go routeMsg(parties, msg, errCh)
		case save := <-endCh:
			idx := edOriginalIndex(*save)
			saved[idx] = *save
			atomic.AddInt32(&done, 1)
		}
	}
	return saved
}

func edOriginalIndex(save edkeygen.LocalPartySaveData) int {
	for j, kj := range save.Ks {
		if kj.Cmp(save.ShareID) == 0 {
			return j
		}
	}
	panic("EdDSA: 无法找到参与方原始索引")
}

// ──────────────────────────────────────────────────────
// Signing
// ──────────────────────────────────────────────────────

func runECDSASigning(partyIDs tss.SortedPartyIDs, keys []eckeygen.LocalPartySaveData, msg *big.Int) *common.SignatureData {
	p2pCtx := tss.NewPeerContext(partyIDs)
	errCh := make(chan *tss.Error, partyCount)
	outCh := make(chan tss.Message, partyCount*partyCount*50)
	endCh := make(chan *common.SignatureData, partyCount)

	parties := make([]tss.Party, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, partyIDs[i], partyCount, threshold)
		parties[i] = ecsigning.NewLocalParty(msg, params, keys[i], outCh, endCh)
	}
	for _, p := range parties {
		go func(p tss.Party) {
			if err := p.Start(); err != nil {
				errCh <- err
			}
		}(p)
	}

	var result *common.SignatureData
	var done int32
	for atomic.LoadInt32(&done) < int32(partyCount) {
		select {
		case err := <-errCh:
			panic(fmt.Sprintf("ECDSA Signing 错误: %v", err))
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

func runEdDSASigning(partyIDs tss.SortedPartyIDs, keys []edkeygen.LocalPartySaveData, msg *big.Int) *common.SignatureData {
	p2pCtx := tss.NewPeerContext(partyIDs)
	errCh := make(chan *tss.Error, partyCount)
	outCh := make(chan tss.Message, partyCount*partyCount*20)
	endCh := make(chan *common.SignatureData, partyCount)

	parties := make([]tss.Party, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.Edwards(), p2pCtx, partyIDs[i], partyCount, threshold)
		parties[i] = edsigning.NewLocalParty(msg, params, keys[i], outCh, endCh)
	}
	for _, p := range parties {
		go func(p tss.Party) {
			if err := p.Start(); err != nil {
				errCh <- err
			}
		}(p)
	}

	var result *common.SignatureData
	var done int32
	for atomic.LoadInt32(&done) < int32(partyCount) {
		select {
		case err := <-errCh:
			panic(fmt.Sprintf("EdDSA Signing 错误: %v", err))
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
// 地址派生 — secp256k1 链
// ──────────────────────────────────────────────────────

// EVM 地址: keccak256(pubX || pubY)[12:]
func deriveEVMAddress(x, y *big.Int) string {
	xb := make([]byte, 32)
	yb := make([]byte, 32)
	x.FillBytes(xb)
	y.FillBytes(yb)
	h := sha3.NewLegacyKeccak256()
	h.Write(append(xb, yb...))
	return "0x" + hex.EncodeToString(h.Sum(nil)[12:])
}

// compressedSecp256k1 返回 33 字节压缩公钥
func compressedSecp256k1(x, y *big.Int) []byte {
	b := make([]byte, 33)
	if y.Bit(0) == 0 {
		b[0] = 0x02
	} else {
		b[0] = 0x03
	}
	x.FillBytes(b[1:])
	return b
}

// hash160 = RIPEMD160(SHA256(data))
func hash160(data []byte) []byte {
	s := sha256.Sum256(data)
	r := ripemd160.New()
	r.Write(s[:])
	return r.Sum(nil)
}

// BTC Legacy P2PKH: Base58Check(0x00 || hash160(compressed_pub))
func deriveBTCLegacyAddress(x, y *big.Int) string {
	h160 := hash160(compressedSecp256k1(x, y))
	payload := append([]byte{0x00}, h160...) // version byte 0x00 = mainnet P2PKH
	c1 := sha256.Sum256(payload)
	c2 := sha256.Sum256(c1[:])
	return base58.Encode(append(payload, c2[:4]...))
}

// BTC SegWit P2WPKH: bech32("bc", 0, hash160(compressed_pub))
func deriveBTCSegWitAddress(x, y *big.Int) string {
	h160 := hash160(compressedSecp256k1(x, y))
	return bech32EncodeP2WPKH("bc", h160)
}

// ──────────────────────────────────────────────────────
// 地址派生 — Ed25519 链
// ──────────────────────────────────────────────────────

// Solana 地址: base58(ed25519_compressed_pub_32bytes)
func deriveSolanaAddress(x, y *big.Int) string {
	pk := &edwards.PublicKey{Curve: tss.Edwards(), X: x, Y: y}
	return base58.Encode(pk.SerializeCompressed())
}

// Sui 地址: 0x + hex(blake2b256(0x00 || ed25519_compressed_pub))
func deriveSuiAddress(x, y *big.Int) string {
	pk := &edwards.PublicKey{Curve: tss.Edwards(), X: x, Y: y}
	h, _ := blake2b.New256(nil)
	h.Write(append([]byte{0x00}, pk.SerializeCompressed()...))
	return "0x" + hex.EncodeToString(h.Sum(nil))
}

// TON 地址（简化版）: "0:{sha256(pubkey)}"
// 真实 TON 地址由 wallet 合约 StateInit hash 派生，需 TON SDK（tongo/tonutils-go）
// 此处仅验证 Ed25519 曲线签名兼容性，地址格式供参考
func deriveTONAddress(x, y *big.Int) string {
	pk := &edwards.PublicKey{Curve: tss.Edwards(), X: x, Y: y}
	h := sha256.Sum256(pk.SerializeCompressed())
	return "0:" + hex.EncodeToString(h[:])
}

// Near 隐式账户地址: hex(ed25519_pub_32bytes)（64 个十六进制字符）
func deriveNearAddress(x, y *big.Int) string {
	pk := &edwards.PublicKey{Curve: tss.Edwards(), X: x, Y: y}
	return hex.EncodeToString(pk.SerializeCompressed())
}

// Aptos 地址: 0x + hex(sha3_256(ed25519_pub_32bytes || 0x00))
// 0x00 = Ed25519 single-key scheme flag
func deriveAptosAddress(x, y *big.Int) string {
	pk := &edwards.PublicKey{Curve: tss.Edwards(), X: x, Y: y}
	h := sha3.New256()
	h.Write(pk.SerializeCompressed())
	h.Write([]byte{0x00})
	return "0x" + hex.EncodeToString(h.Sum(nil))
}

// ──────────────────────────────────────────────────────
// Bech32 编码（BTC SegWit P2WPKH）
// ──────────────────────────────────────────────────────

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32ConvertBits(data []byte, fromBits, toBits int, pad bool) []byte {
	acc, bits := 0, 0
	var result []byte
	maxv := (1 << toBits) - 1
	for _, b := range data {
		acc = (acc << fromBits) | int(b)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			result = append(result, byte((acc>>bits)&maxv))
		}
	}
	if pad && bits > 0 {
		result = append(result, byte((acc<<(toBits-bits))&maxv))
	}
	return result
}

func bech32Polymod(values []byte) uint32 {
	c := uint32(1)
	for _, v := range values {
		c0 := c >> 25
		c = ((c & 0x1ffffff) << 5) ^ uint32(v)
		if c0&1 != 0 { c ^= 0x3b6a57b2 }
		if c0&2 != 0 { c ^= 0x26508e6d }
		if c0&4 != 0 { c ^= 0x1ea119fa }
		if c0&8 != 0 { c ^= 0x3d4233dd }
		if c0&16 != 0 { c ^= 0x2a1462b3 }
	}
	return c ^ 1
}

func bech32HRPExpand(hrp string) []byte {
	var result []byte
	for _, c := range hrp {
		result = append(result, byte(c>>5))
	}
	result = append(result, 0)
	for _, c := range hrp {
		result = append(result, byte(c&31))
	}
	return result
}

func bech32Checksum(hrp string, data []byte) []byte {
	values := append(bech32HRPExpand(hrp), data...)
	pm := bech32Polymod(append(values, 0, 0, 0, 0, 0, 0))
	result := make([]byte, 6)
	for i := range result {
		result[i] = byte((pm >> (5 * (5 - i))) & 31)
	}
	return result
}

// bech32EncodeP2WPKH 编码 P2WPKH 地址 (witness version=0, program=hash160)
func bech32EncodeP2WPKH(hrp string, hash160Bytes []byte) string {
	// witness version 0 + 5bit 转换后的 hash160
	data := append([]byte{0x00}, bech32ConvertBits(hash160Bytes, 8, 5, true)...)
	checksum := bech32Checksum(hrp, data)
	combined := append(data, checksum...)
	result := hrp + "1"
	for _, b := range combined {
		result += string(bech32Charset[b])
	}
	return result
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
	dest := msg.GetTo()
	if dest == nil {
		for _, p := range parties {
			if p.PartyID().Index == msg.GetFrom().Index {
				continue
			}
			go send(p)
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
