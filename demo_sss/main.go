// demo_sss: SSS wallet demo — AVE Wallet
// Tests full flow: BIP39 mnemonic → SSS 2-of-3 split → A+B reconstruct → BIP44 EVM key → sign tx
// Timing benchmarks included to validate Agent signing hot-path performance.
package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	bip32 "github.com/tyler-smith/go-bip32"
	bip39 "github.com/tyler-smith/go-bip39"

	"demo_sss/internal/shamir"
)

func ms(d time.Duration) string {
	return fmt.Sprintf("%.3f ms", float64(d.Microseconds())/1000.0)
}

func step(label string, t0 time.Time) time.Time {
	fmt.Printf("  %-50s %s\n", label, ms(time.Since(t0)))
	return time.Now()
}

// deriveEVMKey derives the BIP44 EVM key at m/44'/60'/0'/0/0 from a seed.
func deriveEVMKey(seed []byte) (*ecdsa.PrivateKey, error) {
	master, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, err
	}
	h := bip32.FirstHardenedChild
	path := []uint32{h + 44, h + 60, h + 0, 0, 0}
	key := master
	for _, idx := range path {
		key, err = key.NewChildKey(idx)
		if err != nil {
			return nil, err
		}
	}
	return crypto.ToECDSA(key.Key)
}

func main() {
	fmt.Println("════════════════════════════════════════════════════════")
	fmt.Println("  AVE Wallet — SSS Demo (GF-256 Shamir, BIP39/BIP44)")
	fmt.Println("════════════════════════════════════════════════════════")
	fmt.Println()

	totalStart := time.Now()

	// ───────────────────────────────────────────────────────
	// Step 1: BIP39 — Generate 24-word mnemonic (256-bit entropy)
	// ───────────────────────────────────────────────────────
	fmt.Println("▶ Step 1: Generate BIP39 mnemonic (24 words, 256-bit entropy)")
	t := time.Now()

	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		panic(err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		panic(err)
	}
	t = step("bip39.NewEntropy + NewMnemonic", t)
	fmt.Printf("  Mnemonic: %s\n\n", mnemonic)

	// ───────────────────────────────────────────────────────
	// Step 2: BIP39 — Derive 64-byte seed (PBKDF2-HMAC-SHA512)
	// ───────────────────────────────────────────────────────
	fmt.Println("▶ Step 2: Derive BIP39 seed (PBKDF2, 2048 iterations)")
	t = time.Now()

	seed := bip39.NewSeed(mnemonic, "")

	t = step("bip39.NewSeed (PBKDF2-HMAC-SHA512)", t)
	fmt.Printf("  Seed (hex): %s...\n\n", hex.EncodeToString(seed[:16]))

	// ───────────────────────────────────────────────────────
	// Step 3: SSS — 2-of-3 split of 64-byte seed
	// ───────────────────────────────────────────────────────
	fmt.Println("▶ Step 3: SSS 2-of-3 split (GF-256, 64-byte seed)")
	t = time.Now()

	shares, err := shamir.Split(seed, 3, 2)
	if err != nil {
		panic(err)
	}
	t = step("shamir.Split (n=3, k=2)", t)

	shareA, shareB, shareC := shares[0], shares[1], shares[2]
	fmt.Printf("  Share A (%d bytes): %s...\n", len(shareA), hex.EncodeToString(shareA[:8]))
	fmt.Printf("  Share B (%d bytes): %s...\n", len(shareB), hex.EncodeToString(shareB[:8]))
	fmt.Printf("  Share C (%d bytes): %s...\n\n", len(shareC), hex.EncodeToString(shareC[:8]))

	// ───────────────────────────────────────────────────────
	// Step 4a: Reconstruct from A+B (client-side recovery path)
	// ───────────────────────────────────────────────────────
	fmt.Println("▶ Step 4a: Reconstruct seed from Share A + B (client recovery path)")
	t = time.Now()

	recAB, err := shamir.Combine([][]byte{shareA, shareB})
	if err != nil {
		panic(err)
	}
	t = step("shamir.Combine (A+B)", t)

	if hex.EncodeToString(recAB) != hex.EncodeToString(seed) {
		panic("A+B reconstruction mismatch!")
	}
	fmt.Println("  Verified: A+B == original seed ✓\n")

	// ───────────────────────────────────────────────────────
	// Step 4b: Reconstruct from B+C (server Agent signing path)
	// ───────────────────────────────────────────────────────
	fmt.Println("▶ Step 4b: Reconstruct seed from Share B + C (server Agent signing path)")
	t = time.Now()

	recBC, err := shamir.Combine([][]byte{shareB, shareC})
	if err != nil {
		panic(err)
	}
	t = step("shamir.Combine (B+C)", t)

	if hex.EncodeToString(recBC) != hex.EncodeToString(seed) {
		panic("B+C reconstruction mismatch!")
	}
	fmt.Println("  Verified: B+C == original seed ✓\n")

	// ───────────────────────────────────────────────────────
	// Step 5: BIP44 EVM key derivation (m/44'/60'/0'/0/0)
	// ───────────────────────────────────────────────────────
	fmt.Println("▶ Step 5: BIP44 EVM key derivation (m/44'/60'/0'/0/0)")
	t = time.Now()

	privKey, err := deriveEVMKey(recBC)
	if err != nil {
		panic(err)
	}
	t = step("bip32.NewMasterKey + 5-level derive", t)

	pubKey := privKey.Public().(*ecdsa.PublicKey)
	address := crypto.PubkeyToAddress(*pubKey)
	fmt.Printf("  EVM Address: %s\n\n", address.Hex())

	// ───────────────────────────────────────────────────────
	// Step 6: Sign EVM transaction (EIP-155, BSC mainnet chainID=56)
	// ───────────────────────────────────────────────────────
	fmt.Println("▶ Step 6: Sign EVM transaction (EIP-155, BSC chainID=56)")

	toAddr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	chainID := big.NewInt(56)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    1,
		To:       &toAddr,
		Value:    big.NewInt(1e18), // 1 BNB
		Gas:      21000,
		GasPrice: big.NewInt(5e9), // 5 Gwei
	})
	signer := types.NewEIP155Signer(chainID)

	t = time.Now()
	signedTx, err := types.SignTx(tx, signer, privKey)
	if err != nil {
		panic(err)
	}
	t = step("types.SignTx (ECDSA secp256k1)", t)

	v, r, s := signedTx.RawSignatureValues()
	fmt.Printf("  TxHash: %s\n", signedTx.Hash().Hex())
	fmt.Printf("  Sig v=%s r=%s... s=%s...\n\n", v, r.Text(16)[:8], s.Text(16)[:8])

	// ───────────────────────────────────────────────────────
	// Benchmark: server Agent signing hot path (B+C → sign)
	// ───────────────────────────────────────────────────────
	fmt.Println("════════════════════════════════════════════════════════")
	fmt.Println("  Benchmark: Agent signing hot path (B+C → sign)")
	fmt.Println("  (excludes network I/O for fetching B from platform cloud")
	fmt.Println("   and C from KMS; add ~2-10 ms for in-datacenter calls)")
	fmt.Println("════════════════════════════════════════════════════════")

	const N = 100
	var sumRecon, sumDerive, sumSign time.Duration

	for i := 0; i < N; i++ {
		t0 := time.Now()
		rec, err := shamir.Combine([][]byte{shareB, shareC})
		if err != nil {
			panic(err)
		}
		sumRecon += time.Since(t0)

		t0 = time.Now()
		pk, err := deriveEVMKey(rec)
		if err != nil {
			panic(err)
		}
		sumDerive += time.Since(t0)

		t0 = time.Now()
		stx, err := types.SignTx(tx, signer, pk)
		if err != nil {
			panic(err)
		}
		_ = stx
		sumSign += time.Since(t0)
	}

	avgRecon := sumRecon / N
	avgDerive := sumDerive / N
	avgSign := sumSign / N
	avgTotal := avgRecon + avgDerive + avgSign

	fmt.Printf("\n  Results (avg over %d iterations):\n\n", N)
	fmt.Printf("  %-45s  %s\n", "SSS reconstruct B+C → seed (GF-256 Lagrange):", ms(avgRecon))
	fmt.Printf("  %-45s  %s\n", "BIP44 key derive (NewMasterKey + 5 levels):", ms(avgDerive))
	fmt.Printf("  %-45s  %s\n", "ECDSA secp256k1 sign:", ms(avgSign))
	fmt.Printf("  %-45s  %s\n", "─── Total crypto hot path ───", ms(avgTotal))
	fmt.Printf("\n  Total demo elapsed: %s\n", ms(time.Since(totalStart)))
	fmt.Println()
	fmt.Println("  ⚠️  待验证: production Agent signing = above + network I/O.")
	fmt.Println("      Target: end-to-end < 20 ms (including platform cloud + KMS fetch).")
	fmt.Println()
}
