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

/* Test and benchmark elliptic curve and RSA functions */

package bls48556_test

import (
	"fmt"
	"miracl/core"
	"miracl/core/bls48556"
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

func BLS_48(rng *core.RAND) {

	fmt.Printf("\nTesting/Timing BLS48556 Pairings\n")

	if bls48556.CURVE_PAIRING_TYPE == bls48556.BN {
		fmt.Printf("BN Pairing-Friendly Curve\n")
	}
	if bls48556.CURVE_PAIRING_TYPE > bls48556.BN {
		fmt.Printf("BLS Pairing-Friendly Curve\n")
	}

	fmt.Printf("Modulus size %d bits\n", bls48556.MODBITS)
	fmt.Printf("%d bit build\n", core.CHUNK)

	G := bls48556.ECP_generator()
	r := bls48556.NewBIGints(bls48556.CURVE_Order)
	s := bls48556.Randtrunc(r, 16*bls48556.AESKEY, rng)

	rw := bls48556.NewFPrand(rng)
	P := bls48556.ECP_map2point(rw)
	P.Cfp()
	if P.Is_infinity() {
		fmt.Printf("HASHING FAILURE - P=O\n")
		return
	}

	P = bls48556.G1mul(G, r)

	if !P.Is_infinity() {
		fmt.Printf("FAILURE - rP!=O\n")
		return
	}

	P = bls48556.G1mul(G, s)

	Q := bls48556.ECP8_generator()

	rz := bls48556.NewFP8rand(rng)
	W := bls48556.ECP8_map2point(rz)
	W.Cfp()
	if W.Is_infinity() {
		fmt.Printf("HASHING FAILURE - P=O\n")
		return
	}
	W = bls48556.G2mul(W, r)
	if !W.Is_infinity() {
		fmt.Printf("FAILURE - rQ!=O\n")
		return
	}

	W = bls48556.G2mul(Q, r)

	if !W.Is_infinity() {
		fmt.Printf("FAILURE - rQ!=O\n")
		return
	}

	W = bls48556.G2mul(Q, s)

	w := bls48556.Ate(Q, P)
	w = bls48556.Fexp(w)

	g := bls48556.GTpow(w, r)

	if !g.Isunity() {
		fmt.Printf("FAILURE - g^r!=1\n")
		return
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
		fmt.Printf("FAILURE - P not in G1 \n")
		return
	}

	if !bls48556.G2member(Q) {
		fmt.Printf("FAILURE - Q not in G2 \n")
		return
	}

	if !bls48556.GTmember(w) {
		fmt.Printf("FAILURE - e(Q,P) not in GT \n")
		return

	}

	if !g.Equals(w) {
		fmt.Printf("FAILURE - e(sQ,p)!=e(Q,sP) \n")
		return
	}

	Q.Copy(W)
	g = bls48556.Ate(Q, P)
	g = bls48556.Fexp(g)
	g = bls48556.GTpow(g, s)

	if !g.Equals(w) {
		fmt.Printf("FAILURE - e(sQ,p)!=e(Q,P)^s \n")
		return
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
