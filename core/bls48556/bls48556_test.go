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

package bls48556_test

import (
	"encoding/hex"
	"miracl/core/bls48556"
	"testing"

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

func TestBLS48556(t *testing.T) {
	if bls48556.CURVE_PAIRING_TYPE == bls48556.BN {
		t.Log("BN Pairing-Friendly Curve")
	}
	if bls48556.CURVE_PAIRING_TYPE > bls48556.BN {
		t.Log("BLS Pairing-Friendly Curve")
	}

	t.Logf("Modulus size %d bits", bls48556.MODBITS)
	t.Logf("%d bit build", bls48556.CHUNK)

	G := bls48556.ECP_generator()
	r := bls48556.NewBIGints(bls48556.CURVE_Order)
	s := bls48556.Randtrunc(r, 16*bls48556.AESKEY, rng)

	rw := bls48556.NewFPrand(rng)
	P := bls48556.ECP_map2point(rw)
	P.Cfp()
	if P.Is_infinity() {
		t.Error("HASHING FAILURE - P=O")
	}

	P = bls48556.G1mul(G, r)

	if !P.Is_infinity() {
		t.Error("FAILURE - rP!=O")
	}

	P = bls48556.G1mul(G, s)

	Q := bls48556.ECP8_generator()

	rz := bls48556.NewFP8rand(rng)
	W := bls48556.ECP8_map2point(rz)
	W.Cfp()
	if W.Is_infinity() {
		t.Error("HASHING FAILURE - P=O")
	}
	W = bls48556.G2mul(W, r)
	if !W.Is_infinity() {
		t.Error("FAILURE - rQ!=O")
	}

	W = bls48556.G2mul(Q, r)

	if !W.Is_infinity() {
		t.Error("FAILURE - rQ!=O")
	}

	W = bls48556.G2mul(Q, s)

	w := bls48556.Ate(Q, P)
	w = bls48556.Fexp(w)

	g := bls48556.GTpow(w, r)

	if !g.Isunity() {
		t.Error("FAILURE - g^r!=1")
	}

	P.Copy(G)
	Q.Copy(W)

	P = bls48556.G1mul(P, s)

	g = bls48556.Ate(Q, P)
	g = bls48556.Fexp(g)

	P.Copy(G)
	Q = bls48556.G2mul(Q, s)

	w = bls48556.Ate(Q, P)
	w = bls48556.Fexp(w)

	if !bls48556.G1member(P) {
		t.Error("FAILURE - P not in G1")
	}

	if !bls48556.G2member(Q) {
		t.Error("FAILURE - Q not in G2")
	}

	if !bls48556.GTmember(w) {
		t.Error("FAILURE - e(Q,P) not in GT")

	}

	if !g.Equals(w) {
		t.Error("FAILURE - e(sQ,p)!=e(Q,sP)")
	}

	Q.Copy(W)
	g = bls48556.Ate(Q, P)
	g = bls48556.Fexp(g)
	g = bls48556.GTpow(g, s)

	if !g.Equals(w) {
		t.Error("FAILURE - e(sQ,p)!=e(Q,P)^s")
	}

}

func TestBLS48556Signature(t *testing.T) {

	const BGS = bls48556.BGS
	const BFS = bls48556.BFS
	const G1S = BFS + 1   /* Group 1 Size */
	const G2S = 8*BFS + 1 /* Group 2 Size */

	var S [BGS]byte
	var W [G2S]byte
	var SIG [G1S]byte
	var IKM [64]byte

	for i := 0; i < len(IKM); i++ {
		IKM[i] = byte(rng.GetByte())
	}

	mess := "This is a test message"

	res := bls48556.Init()
	if res != 0 {
		t.Error("Failed to Initialize")
		return
	}

	res = bls48556.KeyPairGenerate(IKM[:], S[:], W[:])
	if res != 0 {
		t.Error("Failed to generate keys")
		return
	}
	t.Logf("Private key: 0x%s", hex.EncodeToString(S[:]))
	t.Logf("Public key: 0x%s", hex.EncodeToString(W[:]))

	bls48556.Core_Sign(SIG[:], []byte(mess), S[:])
	t.Logf("Signature: 0x%s", hex.EncodeToString(SIG[:]))

	res = bls48556.Core_Verify(SIG[:], []byte(mess), W[:])

	if res != 0 {
		t.Error("Signature is *NOT* OK")
	}
}

func BenchmarkBls48556G1Mul(b *testing.B) {
	G := bls48556.ECP_generator()
	r := bls48556.NewBIGints(bls48556.CURVE_Order)
	s := bls48556.Randtrunc(r, 16*bls48556.AESKEY, rng)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = bls48556.G1mul(G, s)
	}
}

func BenchmarkBls48556G2Mul(b *testing.B) {
	r := bls48556.NewBIGints(bls48556.CURVE_Order)
	s := bls48556.Randtrunc(r, 16*bls48556.AESKEY, rng)

	Q := bls48556.ECP8_generator()

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = bls48556.G2mul(Q, s)
	}
}

func BenchmarkBls48556GtPow(b *testing.B) {
	G := bls48556.ECP_generator()
	r := bls48556.NewBIGints(bls48556.CURVE_Order)
	s := bls48556.Randtrunc(r, 16*bls48556.AESKEY, rng)

	rw := bls48556.NewFPrand(rng)
	P := bls48556.ECP_map2point(rw)
	P.Cfp()
	if P.Is_infinity() {
		b.Error("HASHING FAILURE - P=O")
	}

	P = bls48556.G1mul(G, r)

	if !P.Is_infinity() {
		b.Error("FAILURE - rP!=O")
	}

	Q := bls48556.ECP8_generator()

	w := bls48556.Ate(Q, P)
	w = bls48556.Fexp(w)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = bls48556.GTpow(w, s)
	}
}

func BenchmarkBls48556Ate(b *testing.B) {
	G := bls48556.ECP_generator()
	r := bls48556.NewBIGints(bls48556.CURVE_Order)
	s := bls48556.Randtrunc(r, 16*bls48556.AESKEY, rng)

	rw := bls48556.NewFPrand(rng)
	P := bls48556.ECP_map2point(rw)
	P.Cfp()
	if P.Is_infinity() {
		b.Error("HASHING FAILURE - P=O")
	}

	P = bls48556.G1mul(G, r)

	if !P.Is_infinity() {
		b.Error("FAILURE - rP!=O")
	}

	P = bls48556.G1mul(G, s)

	Q := bls48556.ECP8_generator()

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = bls48556.Ate(Q, P)
	}
}

func BenchmarkBls48556Fexp(b *testing.B) {
	G := bls48556.ECP_generator()
	r := bls48556.NewBIGints(bls48556.CURVE_Order)

	rw := bls48556.NewFPrand(rng)
	P := bls48556.ECP_map2point(rw)
	P.Cfp()
	if P.Is_infinity() {
		b.Error("HASHING FAILURE - P=O")
	}

	P = bls48556.G1mul(G, r)

	if !P.Is_infinity() {
		b.Error("FAILURE - rP!=O")
	}

	Q := bls48556.ECP8_generator()

	w := bls48556.Ate(Q, P)
	w = bls48556.Fexp(w)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = bls48556.Fexp(w)
	}
}
