// Package shamir implements Shamir's Secret Sharing over GF(2^8).
// Algorithm matches github.com/hashicorp/vault/shamir (MIT License, Apache-2.0).
// GF(2^8) with AES irreducible polynomial ensures cross-platform compatibility.
package shamir

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
)

const shareOverhead = 1 // 1 byte x-coordinate appended to each share

// ─────────────────────────────────────────
// GF(2^8) arithmetic
// Irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (AES, 0x11b)
// ─────────────────────────────────────────

// gfAdd is XOR addition in GF(2^8).
func gfAdd(a, b uint8) uint8 { return a ^ b }

// gfMul multiplies two GF(2^8) elements using Russian Peasant Multiplication.
func gfMul(a, b uint8) (out uint8) {
	for b != 0 {
		if b&1 != 0 {
			out ^= a
		}
		carry := a & 0x80
		a <<= 1
		if carry != 0 {
			a ^= 0x1b // reduce: x^8 mod (x^8+x^4+x^3+x+1) = x^4+x^3+x+1
		}
		b >>= 1
	}
	return
}

// gfInv returns the multiplicative inverse of a in GF(2^8) using extended Euclidean.
// gfInv(0) panics (undefined).
func gfInv(a uint8) uint8 {
	if a == 0 {
		panic("shamir: multiplicative inverse of 0 is undefined in GF(2^8)")
	}
	// Fermat's little theorem: a^(2^8-2) = a^254 = a^(-1) in GF(2^8)
	result := uint8(1)
	base := a
	exp := 254
	for exp > 0 {
		if exp&1 != 0 {
			result = gfMul(result, base)
		}
		base = gfMul(base, base)
		exp >>= 1
	}
	return result
}

// gfDiv divides a by b in GF(2^8).
func gfDiv(a, b uint8) uint8 {
	if b == 0 {
		panic("shamir: division by zero in GF(2^8)")
	}
	if a == 0 {
		return 0
	}
	return gfMul(a, gfInv(b))
}

// ─────────────────────────────────────────
// Polynomial over GF(2^8)
// ─────────────────────────────────────────

// evaluate computes the polynomial at x using Horner's method.
// coefficients[0] is the constant term (the secret byte).
func evaluate(coefficients []uint8, x uint8) uint8 {
	if x == 0 {
		return coefficients[0]
	}
	out := coefficients[len(coefficients)-1]
	for i := len(coefficients) - 2; i >= 0; i-- {
		out = gfAdd(gfMul(out, x), coefficients[i])
	}
	return out
}

// lagrangeAt0 uses Lagrange interpolation to compute f(0) given sample points.
func lagrangeAt0(xSamples, ySamples []uint8) uint8 {
	k := len(xSamples)
	var result uint8
	for i := 0; i < k; i++ {
		basis := uint8(1)
		for j := 0; j < k; j++ {
			if i == j {
				continue
			}
			// basis *= x[j] / (x[i] XOR x[j])
			num := xSamples[j]
			denom := gfAdd(xSamples[i], xSamples[j])
			basis = gfMul(basis, gfDiv(num, denom))
		}
		result = gfAdd(result, gfMul(ySamples[i], basis))
	}
	return result
}

// ─────────────────────────────────────────
// Public API
// ─────────────────────────────────────────

// Split splits secret into n shares requiring k for reconstruction.
// Each returned share is len(secret)+1 bytes; the last byte is the x-coordinate.
func Split(secret []byte, n, k int) ([][]byte, error) {
	if k < 2 {
		return nil, fmt.Errorf("shamir: threshold k=%d must be >= 2", k)
	}
	if n < k {
		return nil, fmt.Errorf("shamir: parts n=%d must be >= threshold k=%d", n, k)
	}
	if n > 255 {
		return nil, fmt.Errorf("shamir: parts n=%d must be <= 255", n)
	}
	if len(secret) == 0 {
		return nil, errors.New("shamir: secret must not be empty")
	}

	// Allocate shares
	shares := make([][]byte, n)
	for i := range shares {
		shares[i] = make([]byte, len(secret)+shareOverhead)
		shares[i][len(secret)] = uint8(i + 1) // x-coordinate: 1..n
	}

	// For each secret byte, build a random degree-(k-1) polynomial and evaluate
	coefficients := make([]uint8, k)
	randBuf := make([]byte, k-1)

	for byteIdx, secretByte := range secret {
		coefficients[0] = secretByte
		if _, err := rand.Read(randBuf); err != nil {
			return nil, fmt.Errorf("shamir: rand.Read: %w", err)
		}
		copy(coefficients[1:], randBuf)

		for i := 0; i < n; i++ {
			x := uint8(i + 1)
			shares[i][byteIdx] = evaluate(coefficients, x)
		}
	}
	return shares, nil
}

// Combine reconstructs the secret from k or more shares.
// Shares must all be the same length; the last byte of each is the x-coordinate.
func Combine(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, fmt.Errorf("shamir: need at least 2 shares, got %d", len(shares))
	}
	shareLen := len(shares[0])
	if shareLen < 2 {
		return nil, errors.New("shamir: share too short")
	}
	for i, s := range shares {
		if len(s) != shareLen {
			return nil, fmt.Errorf("shamir: share %d has length %d, expected %d", i, len(s), shareLen)
		}
	}

	// Check for duplicate x-coordinates
	xSeen := make(map[uint8]bool, len(shares))
	xSamples := make([]uint8, len(shares))
	for i, s := range shares {
		x := s[shareLen-1]
		if xSeen[x] {
			return nil, fmt.Errorf("shamir: duplicate x-coordinate %d", x)
		}
		xSeen[x] = true
		xSamples[i] = x
	}

	secretLen := shareLen - shareOverhead
	secret := make([]byte, secretLen)
	ySamples := make([]uint8, len(shares))

	for byteIdx := range secret {
		for i, s := range shares {
			ySamples[i] = s[byteIdx]
		}
		secret[byteIdx] = lagrangeAt0(xSamples, ySamples)
	}
	return secret, nil
}

// Verify checks that a set of shares correctly reconstructs the expected secret.
// Uses constant-time comparison.
func Verify(shares [][]byte, expected []byte) bool {
	rec, err := Combine(shares)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(rec, expected) == 1
}
