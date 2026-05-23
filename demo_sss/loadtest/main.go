// loadtest: concurrent SSS signing load test
// Simulates N concurrent Agent signing requests (B+C → BIP44 → sign)
// Reports throughput, latency percentiles, and CPU utilization estimate.
//
// Usage:
//   go run ./loadtest                     # default: 1000 concurrent, 1 round
//   go run ./loadtest -c 100 -rounds 5   # 100 concurrent, 5 rounds
//   go run ./loadtest -c 1,10,100,1000   # sweep concurrency levels
package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"runtime/pprof"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	bip32 "github.com/tyler-smith/go-bip32"
	bip39 "github.com/tyler-smith/go-bip39"

	"demo_sss/internal/shamir"
)

var (
	flagConcurrency = flag.Int("c", 1000, "number of concurrent goroutines")
	flagRounds      = flag.Int("rounds", 3, "number of rounds to average")
	flagCPUProfile  = flag.String("cpuprofile", "", "write CPU pprof to file (e.g. cpu.prof)")
	flagSweep       = flag.Bool("sweep", false, "sweep concurrency: 1,10,100,500,1000")
)

// ─────────────────────────────────────────
// Hot path: B+C → BIP44 → sign (one request)
// ─────────────────────────────────────────

func hotPath(shareB, shareC []byte, tx *types.Transaction, signer types.Signer) error {
	// Step 1: SSS reconstruct
	seed, err := shamir.Combine([][]byte{shareB, shareC})
	if err != nil {
		return err
	}

	// Step 2: BIP44 key derive m/44'/60'/0'/0/0
	privKey, err := deriveEVMKey(seed)
	if err != nil {
		return err
	}

	// Step 3: sign
	_, err = types.SignTx(tx, signer, privKey)
	return err
}

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

// ─────────────────────────────────────────
// Run one concurrency level, return latencies
// ─────────────────────────────────────────

func runLevel(concurrency int, shareB, shareC []byte, tx *types.Transaction, signer types.Signer) (latencies []time.Duration, wallTime time.Duration) {
	latencies = make([]time.Duration, concurrency)
	var mu sync.Mutex
	_ = mu

	// Use a barrier so all goroutines start simultaneously
	var ready sync.WaitGroup
	var start sync.WaitGroup
	var wg sync.WaitGroup
	startCh := make(chan struct{})

	ready.Add(concurrency)
	wg.Add(concurrency)

	wallStart := time.Now()

	for i := 0; i < concurrency; i++ {
		idx := i
		go func() {
			defer wg.Done()
			ready.Done()
			<-startCh // wait for barrier

			t0 := time.Now()
			if err := hotPath(shareB, shareC, tx, signer); err != nil {
				fmt.Fprintf(os.Stderr, "hotPath error: %v\n", err)
			}
			latencies[idx] = time.Since(t0)
		}()
	}

	ready.Wait() // wait until all goroutines are ready
	_ = start
	close(startCh)   // fire all at once
	wg.Wait()        // wait for all to finish
	wallTime = time.Since(wallStart)

	return latencies, wallTime
}

// ─────────────────────────────────────────
// Stats helpers
// ─────────────────────────────────────────

type stats struct {
	min, p50, p95, p99, p999, max time.Duration
	avg                           time.Duration
	throughput                    float64 // req/s
	cpuUtil                       float64 // estimated %
	numCPU                        int
}

func calcStats(latencies []time.Duration, wall time.Duration) stats {
	n := len(latencies)
	sorted := make([]time.Duration, n)
	copy(sorted, latencies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	var sum time.Duration
	for _, d := range sorted {
		sum += d
	}
	avg := sum / time.Duration(n)

	pct := func(p float64) time.Duration {
		idx := int(float64(n-1) * p)
		return sorted[idx]
	}

	numCPU := runtime.GOMAXPROCS(0)
	// Estimated CPU utilization: total CPU time spent / (wall * numCPU)
	cpuUtil := float64(sum) / float64(wall*time.Duration(numCPU)) * 100

	return stats{
		min:        sorted[0],
		p50:        pct(0.50),
		p95:        pct(0.95),
		p99:        pct(0.99),
		p999:       pct(0.999),
		max:        sorted[n-1],
		avg:        avg,
		throughput: float64(n) / wall.Seconds(),
		cpuUtil:    cpuUtil,
		numCPU:     numCPU,
	}
}

func ms(d time.Duration) string { return fmt.Sprintf("%.1f ms", float64(d.Microseconds())/1000.0) }

func printStats(concurrency int, s stats, wall time.Duration) {
	fmt.Printf("  Concurrency=%-5d  wall=%-8s  tps=%-8.0f  cpu_est=%.0f%%\n",
		concurrency, ms(wall), s.throughput, s.cpuUtil)
	fmt.Printf("    latency:  min=%-8s p50=%-8s p95=%-8s p99=%-8s p99.9=%-8s max=%s\n",
		ms(s.min), ms(s.p50), ms(s.p95), ms(s.p99), ms(s.p999), ms(s.max))
}

// ─────────────────────────────────────────
// Main
// ─────────────────────────────────────────

func main() {
	flag.Parse()

	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Println("  AVE Wallet — SSS Concurrent Load Test")
	fmt.Printf("  OS CPUs: %d   GOMAXPROCS: %d\n", runtime.NumCPU(), runtime.GOMAXPROCS(0))
	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Println()

	// ── Setup: generate a single set of shares (shared across all goroutines read-only) ──
	entropy, _ := bip39.NewEntropy(256)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	seed := bip39.NewSeed(mnemonic, "")
	shares, err := shamir.Split(seed, 3, 2)
	if err != nil {
		panic(err)
	}
	shareB, shareC := shares[1], shares[2]

	chainID := big.NewInt(56)
	toAddr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    1,
		To:       &toAddr,
		Value:    big.NewInt(1e18),
		Gas:      21000,
		GasPrice: big.NewInt(5e9),
	})
	signer := types.NewEIP155Signer(chainID)

	// ── Optional CPU profile ──
	if *flagCPUProfile != "" {
		f, err := os.Create(*flagCPUProfile)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
		fmt.Printf("  CPU profile → %s\n\n", *flagCPUProfile)
	}

	// ── Determine concurrency levels ──
	var levels []int
	if *flagSweep {
		levels = []int{1, 10, 100, 500, 1000}
	} else {
		levels = []int{*flagConcurrency}
	}

	for _, concurrency := range levels {
		fmt.Printf("▶ Concurrency = %d  (%d rounds)\n", concurrency, *flagRounds)

		// Warm-up round (not counted)
		runLevel(min(concurrency, 10), shareB, shareC, tx, signer)

		// Actual rounds
		var allLatencies []time.Duration
		var totalWall time.Duration

		for r := 0; r < *flagRounds; r++ {
			lats, wall := runLevel(concurrency, shareB, shareC, tx, signer)
			allLatencies = append(allLatencies, lats...)
			totalWall += wall
		}

		// Average wall time across rounds
		avgWall := totalWall / time.Duration(*flagRounds)
		// Use all latency samples for percentile calculation
		s := calcStats(allLatencies, avgWall)
		printStats(concurrency, s, avgWall)
		fmt.Println()
	}

	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Println("  Notes:")
	fmt.Println("  - wall time = real elapsed for all N concurrent requests")
	fmt.Println("  - tps = N / wall (server throughput)")
	fmt.Println("  - cpu_est = Σ(per-request latency) / (wall × GOMAXPROCS) × 100%")
	fmt.Println("  - latency excludes network I/O (ShareB fetch + ShareC KMS fetch)")
	fmt.Println("  - BIP44 derive dominates (~10ms/req); scales linearly with CPU cores")
	fmt.Println("════════════════════════════════════════════════════════════════")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
