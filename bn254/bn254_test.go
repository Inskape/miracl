/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/core).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Test and benchmark elliptic curve functions */

/* Test driver and function exerciser for Boneh-Lynn-Shacham BLS Signature API Functions */

/* To reverse the groups G1 and G2, edit BLS*.go

Swap G1 <-> G2
Swap ECP <-> ECPn
Disable G2 precomputation
Switch G1/G2 parameter order in pairing function calls

Swap G1S and G2S in this program

See CPP library version for example

*/

package bn254_test

import (
	"encoding/hex"
	"testing"

	"github.com/Inskape/miracl/bn254"
	"github.com/Inskape/miracl/core"
)

var (
	RAW [100]byte
	rng *core.RAND
)

func TestMain(m *testing.M) {
	rng = core.NewRAND()

	rng.Clean()
	for i := 0; i < 100; i++ {
		RAW[i] = byte(i)
	}

	rng.Seed(100, RAW[:])
	m.Run()
}

func TestBN254(t *testing.T) {
	if bn254.CURVE_PAIRING_TYPE == bn254.BN {
		t.Log("BN Pairing-Friendly Curve")
	}
	if bn254.CURVE_PAIRING_TYPE > bn254.BN {
		t.Log("BLS Pairing-Friendly Curve")
	}

	t.Logf("Modulus size %d bits", bn254.MODBITS)
	t.Logf("%d bit build", bn254.CHUNK)

	G := bn254.ECP_generator()
	r := bn254.NewBIGints(bn254.CURVE_Order)
	s := bn254.Randtrunc(r, 16*bn254.AESKEY, rng)

	rw := bn254.NewFPrand(rng)
	P := bn254.ECP_map2point(rw)
	P.Cfp()
	if P.Is_infinity() {
		t.Error("HASHING FAILURE - P=O")
	}

	P = bn254.G1mul(G, r)

	if !P.Is_infinity() {
		t.Error("FAILURE - rP!=O")
	}

	P = bn254.G1mul(G, s)
	Q := bn254.ECP2_generator()

	rz := bn254.NewFP2rand(rng)
	W := bn254.ECP2_map2point(rz)
	W.Cfp()
	if W.Is_infinity() {
		t.Error("HASHING FAILURE - P=O")
	}
	W = bn254.G2mul(W, r)
	if !W.Is_infinity() {
		t.Error("FAILURE - rQ!=O")
	}

	W = bn254.G2mul(Q, r)

	if !W.Is_infinity() {
		t.Error("FAILURE - rQ!=O")
	}

	W = bn254.G2mul(Q, s)

	w := bn254.Ate(Q, P)
	w = bn254.Fexp(w)

	g := bn254.GTpow(w, r)

	if !g.Isunity() {
		t.Error("FAILURE - g^r!=1")
	}

	P.Copy(G)
	Q.Copy(W)

	P = bn254.G1mul(P, s)

	g = bn254.Ate(Q, P)
	g = bn254.Fexp(g)

	P.Copy(G)
	Q = bn254.G2mul(Q, s)

	w = bn254.Ate(Q, P)
	w = bn254.Fexp(w)

	if !bn254.G1member(P) {
		t.Error("FAILURE - P not in G1")
	}

	if !bn254.G2member(Q) {
		t.Error("FAILURE - Q not in G2")
	}

	if !bn254.GTmember(w) {
		t.Error("FAILURE - e(Q,P) not in GT")
	}

	if !g.Equals(w) {
		t.Error("FAILURE - e(sQ,p)!=e(Q,sP)")
	}

	Q.Copy(W)
	g = bn254.Ate(Q, P)
	g = bn254.Fexp(g)
	g = bn254.GTpow(g, s)

	if !g.Equals(w) {
		t.Error("FAILURE - e(sQ,p)!=e(Q,P)^s")
	}
}

func TestBN254Signature(t *testing.T) {

	const BGS = bn254.BGS
	const BFS = bn254.BFS
	const G1S = BFS + 1   /* Group 1 Size */
	const G2S = 2*BFS + 1 /* Group 2 Size */

	var S [BGS]byte
	var W [G2S]byte
	var SIG [G1S]byte
	var IKM [32]byte

	for i := 0; i < len(IKM); i++ {
		IKM[i] = byte(rng.GetByte())
	}

	mess := "This is a test message"

	res := bn254.Init()
	if res != 0 {
		t.Error("Failed to Initialize")
	}

	res = bn254.KeyPairGenerate(IKM[:], S[:], W[:])
	if res != 0 {
		t.Error("Failed to generate keys")
	}
	t.Logf("Private key: 0x%s", hex.EncodeToString(S[:]))
	t.Logf("Public key: 0x%s", hex.EncodeToString(W[:]))

	bn254.Core_Sign(SIG[:], []byte(mess), S[:])
	t.Logf("Signature: 0x%s", hex.EncodeToString(SIG[:]))

	res = bn254.Core_Verify(SIG[:], []byte(mess), W[:])

	if res != 0 {
		t.Error("Signature is *NOT* OK")
	}
}

func BenchmarkBN254G1Mul(b *testing.B) {
	G := bn254.ECP_generator()
	r := bn254.NewBIGints(bn254.CURVE_Order)
	s := bn254.Randtrunc(r, 16*bn254.AESKEY, rng)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = bn254.G1mul(G, s)
	}
}

func BenchmarkBN254G2Mul(b *testing.B) {
	r := bn254.NewBIGints(bn254.CURVE_Order)
	s := bn254.Randtrunc(r, 16*bn254.AESKEY, rng)

	Q := bn254.ECP2_generator()

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = bn254.G2mul(Q, s)
	}
}

func BenchmarkBN254GtPow(b *testing.B) {
	G := bn254.ECP_generator()
	r := bn254.NewBIGints(bn254.CURVE_Order)
	s := bn254.Randtrunc(r, 16*bn254.AESKEY, rng)

	rw := bn254.NewFPrand(rng)
	P := bn254.ECP_map2point(rw)
	P.Cfp()
	if P.Is_infinity() {
		b.Error("HASHING FAILURE - P=O")
	}

	P = bn254.G1mul(G, r)

	if !P.Is_infinity() {
		b.Error("FAILURE - rP!=O")
	}

	Q := bn254.ECP2_generator()

	w := bn254.Ate(Q, P)
	w = bn254.Fexp(w)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = bn254.GTpow(w, s)
	}
}

func BenchmarkBN254GtPowCompressed(b *testing.B) {
	G := bn254.ECP_generator()
	r := bn254.NewBIGints(bn254.CURVE_Order)
	s := bn254.Randtrunc(r, 16*bn254.AESKEY, rng)

	rw := bn254.NewFPrand(rng)
	P := bn254.ECP_map2point(rw)
	P.Cfp()
	if P.Is_infinity() {
		b.Error("HASHING FAILURE - P=O")
	}

	P = bn254.G1mul(G, r)

	if !P.Is_infinity() {
		b.Error("FAILURE - rP!=O")
	}

	Q := bn254.ECP2_generator()

	w := bn254.Ate(Q, P)
	w = bn254.Fexp(w)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = w.Compow(s, r)
	}
}

func BenchmarkBN254Ate(b *testing.B) {
	G := bn254.ECP_generator()
	r := bn254.NewBIGints(bn254.CURVE_Order)
	s := bn254.Randtrunc(r, 16*bn254.AESKEY, rng)

	rw := bn254.NewFPrand(rng)
	P := bn254.ECP_map2point(rw)
	P.Cfp()
	if P.Is_infinity() {
		b.Error("HASHING FAILURE - P=O")
	}

	P = bn254.G1mul(G, r)

	if !P.Is_infinity() {
		b.Error("FAILURE - rP!=O")
	}

	P = bn254.G1mul(G, s)

	Q := bn254.ECP2_generator()

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = bn254.Ate(Q, P)
	}
}

func BenchmarkBN254Fexp(b *testing.B) {
	G := bn254.ECP_generator()
	r := bn254.NewBIGints(bn254.CURVE_Order)

	rw := bn254.NewFPrand(rng)
	P := bn254.ECP_map2point(rw)
	P.Cfp()
	if P.Is_infinity() {
		b.Error("HASHING FAILURE - P=O")
	}

	P = bn254.G1mul(G, r)

	if !P.Is_infinity() {
		b.Error("FAILURE - rP!=O")
	}

	Q := bn254.ECP2_generator()

	w := bn254.Ate(Q, P)
	w = bn254.Fexp(w)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = bn254.Fexp(w)
	}
}
