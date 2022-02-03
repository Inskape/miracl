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

package bls24479_test

import (
	"fmt"
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

func BLS_24(rng *core.RAND) {

	fmt.Printf("\nTesting/Timing BLS24479 Pairings\n")

	if bls24479.CURVE_PAIRING_TYPE == bls24479.BN {
		fmt.Printf("BN Pairing-Friendly Curve\n")
	}
	if bls24479.CURVE_PAIRING_TYPE > bls24479.BN {
		fmt.Printf("BLS Pairing-Friendly Curve\n")
	}

	fmt.Printf("Modulus size %d bits\n", bls24479.MODBITS)
	fmt.Printf("%d bit build\n", core.CHUNK)

	G := bls24479.ECP_generator()
	r := bls24479.NewBIGints(bls24479.CURVE_Order)
	s := bls24479.Randtrunc(r, 16*bls24479.AESKEY, rng)

	rw := bls24479.NewFPrand(rng)
	P := bls24479.ECP_map2point(rw)
	P.Cfp()
	if P.Is_infinity() {
		fmt.Printf("HASHING FAILURE - P=O\n")
		return
	}

	P = bls24479.G1mul(G, r)

	if !P.Is_infinity() {
		fmt.Printf("FAILURE - rP!=O\n")
		return
	}

	P = bls24479.G1mul(G, s)

	Q := bls24479.ECP4_generator()

	rz := bls24479.NewFP4rand(rng)
	W := bls24479.ECP4_map2point(rz)
	W.Cfp()
	if W.Is_infinity() {
		fmt.Printf("HASHING FAILURE - P=O\n")
		return
	}
	W = bls24479.G2mul(W, r)
	if !W.Is_infinity() {
		fmt.Printf("FAILURE - rQ!=O\n")
		return
	}

	W = bls24479.G2mul(Q, r)

	if !W.Is_infinity() {
		fmt.Printf("FAILURE - rQ!=O\n")
		return
	}

	W = bls24479.G2mul(Q, s)

	w := bls24479.Ate(Q, P)
	w = bls24479.Fexp(w)

	g := bls24479.GTpow(w, r)

	if !g.Isunity() {
		fmt.Printf("FAILURE - g^r!=1\n")
		return
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
		fmt.Printf("FAILURE - P not in G1 \n")
		return
	}

	if !bls24479.G2member(Q) {
		fmt.Printf("FAILURE - Q not in G2 \n")
		return
	}

	if !bls24479.GTmember(w) {
		fmt.Printf("FAILURE - e(Q,P) not in GT \n")
		return

	}

	if !g.Equals(w) {
		fmt.Printf("FAILURE - e(sQ,p)!=e(Q,sP) \n")
		return
	}

	Q.Copy(W)
	g = bls24479.Ate(Q, P)
	g = bls24479.Fexp(g)
	g = bls24479.GTpow(g, s)

	if !g.Equals(w) {
		fmt.Printf("FAILURE - e(sQ,p)!=e(Q,P)^s \n")
		return
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
