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

package bls24479_test

import (
	"encoding/hex"
	"miracl/core"
	"miracl/core/bls24479"
	"testing"
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

func TestBLS24479(t *testing.T) {
	if bls24479.CURVE_PAIRING_TYPE == bls24479.BN {
		t.Log("BN Pairing-Friendly Curve")
	}
	if bls24479.CURVE_PAIRING_TYPE > bls24479.BN {
		t.Log("BLS Pairing-Friendly Curve")
	}

	t.Logf("Modulus size %d bits", bls24479.MODBITS)
	t.Logf("%d bit build", core.CHUNK)

	G := bls24479.ECP_generator()
	r := bls24479.NewBIGints(bls24479.CURVE_Order)
	s := bls24479.Randtrunc(r, 16*bls24479.AESKEY, rng)

	rw := bls24479.NewFPrand(rng)
	P := bls24479.ECP_map2point(rw)
	P.Cfp()
	if P.Is_infinity() {
		t.Error("HASHING FAILURE - P=O")
	}

	P = bls24479.G1mul(G, r)

	if !P.Is_infinity() {
		t.Error("FAILURE - rP!=O")
	}

	P = bls24479.G1mul(G, s)

	Q := bls24479.ECP4_generator()

	rz := bls24479.NewFP4rand(rng)
	W := bls24479.ECP4_map2point(rz)
	W.Cfp()
	if W.Is_infinity() {
		t.Error("HASHING FAILURE - P=O")
	}
	W = bls24479.G2mul(W, r)
	if !W.Is_infinity() {
		t.Error("FAILURE - rQ!=O")
	}

	W = bls24479.G2mul(Q, r)

	if !W.Is_infinity() {
		t.Error("FAILURE - rQ!=O")
	}

	W = bls24479.G2mul(Q, s)

	w := bls24479.Ate(Q, P)
	w = bls24479.Fexp(w)

	g := bls24479.GTpow(w, r)

	if !g.Isunity() {
		t.Error("FAILURE - g^r!=1")
	}

	P.Copy(G)
	Q.Copy(W)

	P = bls24479.G1mul(P, s)

	g = bls24479.Ate(Q, P)
	g = bls24479.Fexp(g)

	P.Copy(G)
	Q = bls24479.G2mul(Q, s)

	w = bls24479.Ate(Q, P)
	w = bls24479.Fexp(w)

	if !bls24479.G1member(P) {
		t.Error("FAILURE - P not in G1 ")
	}

	if !bls24479.G2member(Q) {
		t.Error("FAILURE - Q not in G2 ")
	}

	if !bls24479.GTmember(w) {
		t.Error("FAILURE - e(Q,P) not in GT ")

	}

	if !g.Equals(w) {
		t.Error("FAILURE - e(sQ,p)!=e(Q,sP) ")
	}

	Q.Copy(W)
	g = bls24479.Ate(Q, P)
	g = bls24479.Fexp(g)
	g = bls24479.GTpow(g, s)

	if !g.Equals(w) {
		t.Error("FAILURE - e(sQ,p)!=e(Q,P)^s ")
	}
}

func TestBLS24479Signature(t *testing.T) {
	const BGS = bls24479.BGS
	const BFS = bls24479.BFS
	const G1S = BFS + 1   /* Group 1 Size */
	const G2S = 4*BFS + 1 /* Group 2 Size */

	var S [BGS]byte
	var W [G2S]byte
	var SIG [G1S]byte
	var IKM [48]byte

	for i := 0; i < len(IKM); i++ {
		IKM[i] = byte(rng.GetByte())
	}

	mess := "This is a test message"

	res := bls24479.Init()
	if res != 0 {
		t.Error("Failed to Initialize")
		return
	}

	res = bls24479.KeyPairGenerate(IKM[:], S[:], W[:])
	if res != 0 {
		t.Error("Failed to generate keys")
		return
	}
	t.Logf("Private key: 0x%s", hex.EncodeToString(S[:]))
	t.Logf("Public key: 0x%s", hex.EncodeToString(W[:]))

	bls24479.Core_Sign(SIG[:], []byte(mess), S[:])
	t.Logf("Signature: 0x%s", hex.EncodeToString(SIG[:]))

	res = bls24479.Core_Verify(SIG[:], []byte(mess), W[:])

	if res != 0 {
		t.Error("Signature is *NOT* OK")
	}
}

func BenchmarkBls24479G1Mul(b *testing.B) {
	G := bls24479.ECP_generator()
	r := bls24479.NewBIGints(bls24479.CURVE_Order)
	s := bls24479.Randtrunc(r, 16*bls24479.AESKEY, rng)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = bls24479.G1mul(G, s)
	}
}

func BenchmarkBls24479G2Mul(b *testing.B) {
	r := bls24479.NewBIGints(bls24479.CURVE_Order)
	s := bls24479.Randtrunc(r, 16*bls24479.AESKEY, rng)

	Q := bls24479.ECP4_generator()

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = bls24479.G2mul(Q, s)
	}
}

func BenchmarkBls24479GtPow(b *testing.B) {
	G := bls24479.ECP_generator()
	r := bls24479.NewBIGints(bls24479.CURVE_Order)
	s := bls24479.Randtrunc(r, 16*bls24479.AESKEY, rng)

	rw := bls24479.NewFPrand(rng)
	P := bls24479.ECP_map2point(rw)
	P.Cfp()
	if P.Is_infinity() {
		b.Error("HASHING FAILURE - P=O")
	}

	P = bls24479.G1mul(G, r)

	if !P.Is_infinity() {
		b.Error("FAILURE - rP!=O")
	}

	Q := bls24479.ECP4_generator()

	w := bls24479.Ate(Q, P)
	w = bls24479.Fexp(w)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = bls24479.GTpow(w, s)
	}
}

func BenchmarkBls24479Ate(b *testing.B) {
	G := bls24479.ECP_generator()
	r := bls24479.NewBIGints(bls24479.CURVE_Order)
	s := bls24479.Randtrunc(r, 16*bls24479.AESKEY, rng)

	rw := bls24479.NewFPrand(rng)
	P := bls24479.ECP_map2point(rw)
	P.Cfp()
	if P.Is_infinity() {
		b.Error("HASHING FAILURE - P=O")
	}

	P = bls24479.G1mul(G, r)

	if !P.Is_infinity() {
		b.Error("FAILURE - rP!=O")
	}

	P = bls24479.G1mul(G, s)

	Q := bls24479.ECP4_generator()

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = bls24479.Ate(Q, P)
	}
}

func BenchmarkBls24479Fexp(b *testing.B) {
	G := bls24479.ECP_generator()
	r := bls24479.NewBIGints(bls24479.CURVE_Order)

	rw := bls24479.NewFPrand(rng)
	P := bls24479.ECP_map2point(rw)
	P.Cfp()
	if P.Is_infinity() {
		b.Error("HASHING FAILURE - P=O")
	}

	P = bls24479.G1mul(G, r)

	if !P.Is_infinity() {
		b.Error("FAILURE - rP!=O")
	}

	Q := bls24479.ECP4_generator()

	w := bls24479.Ate(Q, P)
	w = bls24479.Fexp(w)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = bls24479.Fexp(w)
	}
}
