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

package bls12383_test

import (
	"miracl/core"
	"miracl/core/bls12383"
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

func TestBls383(t *testing.T) {
	if bls12383.CURVE_PAIRING_TYPE == bls12383.BN {
		t.Log("BN Pairing-Friendly Curve")
	}
	if bls12383.CURVE_PAIRING_TYPE > bls12383.BN {
		t.Log("BLS Pairing-Friendly Curve")
	}

	t.Logf("Modulus size %d bits", bls12383.MODBITS)
	t.Logf("%d bit build", core.CHUNK)

	G := bls12383.ECP_generator()
	r := bls12383.NewBIGints(bls12383.CURVE_Order)
	s := bls12383.Randtrunc(r, 16*bls12383.AESKEY, rng)

	rw := bls12383.NewFPrand(rng)
	P := bls12383.ECP_map2point(rw)
	P.Cfp()
	if P.Is_infinity() {
		t.Error("HASHING FAILURE - P=O")
	}

	P = bls12383.G1mul(G, r)

	if !P.Is_infinity() {
		t.Error("FAILURE - rP!=O")
	}

	// TODO: DONE
	P = bls12383.G1mul(G, s)

	Q := bls12383.ECP2_generator()

	rz := bls12383.NewFP2rand(rng)
	W := bls12383.ECP2_map2point(rz)
	W.Cfp()
	if W.Is_infinity() {
		t.Error("HASHING FAILURE - P=O")
	}
	W = bls12383.G2mul(W, r)
	if !W.Is_infinity() {
		t.Error("FAILURE - rQ!=O")
	}

	W = bls12383.G2mul(Q, r)

	if !W.Is_infinity() {
		t.Error("FAILURE - rQ!=O")
	}

	// TODO: DONE
	W = bls12383.G2mul(Q, s)

	w := bls12383.Ate(Q, P)
	w = bls12383.Fexp(w)

	g := bls12383.GTpow(w, r)

	if !g.Isunity() {
		t.Error("FAILURE - g^r!=1")
	}

	P.Copy(G)
	Q.Copy(W)

	P = bls12383.G1mul(P, s)

	g = bls12383.Ate(Q, P)
	g = bls12383.Fexp(g)

	P.Copy(G)
	Q = bls12383.G2mul(Q, s)

	w = bls12383.Ate(Q, P)
	w = bls12383.Fexp(w)

	if !bls12383.G1member(P) {
		t.Error("FAILURE - P not in G1")
	}

	if !bls12383.G2member(Q) {
		t.Error("FAILURE - Q not in G2")
	}

	if !bls12383.GTmember(w) {
		t.Error("FAILURE - e(Q,P) not in GT")

	}

	if !g.Equals(w) {
		t.Error("FAILURE - e(sQ,p)!=e(Q,sP)")
	}

	Q.Copy(W)
	g = bls12383.Ate(Q, P)
	g = bls12383.Fexp(g)
	g = bls12383.GTpow(g, s)

	if !g.Equals(w) {
		t.Error("FAILURE - e(sQ,p)!=e(Q,P)^s")
	}
}

func BenchmarkBls12383G1Mul(b *testing.B) {
	G := bls12383.ECP_generator()
	r := bls12383.NewBIGints(bls12383.CURVE_Order)
	s := bls12383.Randtrunc(r, 16*bls12383.AESKEY, rng)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = bls12383.G1mul(G, s)
	}
}

func BenchmarkBls12383G2Mul(b *testing.B) {
	r := bls12383.NewBIGints(bls12383.CURVE_Order)
	s := bls12383.Randtrunc(r, 16*bls12383.AESKEY, rng)

	Q := bls12383.ECP2_generator()

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = bls12383.G2mul(Q, s)
	}
}

func BenchmarkBls12383GtPow(b *testing.B) {
	G := bls12383.ECP_generator()
	r := bls12383.NewBIGints(bls12383.CURVE_Order)
	s := bls12383.Randtrunc(r, 16*bls12383.AESKEY, rng)

	rw := bls12383.NewFPrand(rng)
	P := bls12383.ECP_map2point(rw)
	P.Cfp()
	if P.Is_infinity() {
		b.Error("HASHING FAILURE - P=O")
	}

	P = bls12383.G1mul(G, r)

	if !P.Is_infinity() {
		b.Error("FAILURE - rP!=O")
	}

	Q := bls12383.ECP2_generator()

	w := bls12383.Ate(Q, P)
	w = bls12383.Fexp(w)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = bls12383.GTpow(w, s)
	}
}

func BenchmarkBls12383GtPowCompressed(b *testing.B) {
	G := bls12383.ECP_generator()
	r := bls12383.NewBIGints(bls12383.CURVE_Order)
	s := bls12383.Randtrunc(r, 16*bls12383.AESKEY, rng)

	rw := bls12383.NewFPrand(rng)
	P := bls12383.ECP_map2point(rw)
	P.Cfp()
	if P.Is_infinity() {
		b.Error("HASHING FAILURE - P=O")
	}

	P = bls12383.G1mul(G, r)

	if !P.Is_infinity() {
		b.Error("FAILURE - rP!=O")
	}

	Q := bls12383.ECP2_generator()

	w := bls12383.Ate(Q, P)
	w = bls12383.Fexp(w)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = w.Compow(s, r)
	}
}

func BenchmarkBls12383Ate(b *testing.B) {
	G := bls12383.ECP_generator()
	r := bls12383.NewBIGints(bls12383.CURVE_Order)
	s := bls12383.Randtrunc(r, 16*bls12383.AESKEY, rng)

	rw := bls12383.NewFPrand(rng)
	P := bls12383.ECP_map2point(rw)
	P.Cfp()
	if P.Is_infinity() {
		b.Error("HASHING FAILURE - P=O")
	}

	P = bls12383.G1mul(G, r)

	if !P.Is_infinity() {
		b.Error("FAILURE - rP!=O")
	}

	P = bls12383.G1mul(G, s)

	Q := bls12383.ECP2_generator()

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = bls12383.Ate(Q, P)
	}
}

func BenchmarkBls12383Fexp(b *testing.B) {
	G := bls12383.ECP_generator()
	r := bls12383.NewBIGints(bls12383.CURVE_Order)

	rw := bls12383.NewFPrand(rng)
	P := bls12383.ECP_map2point(rw)
	P.Cfp()
	if P.Is_infinity() {
		b.Error("HASHING FAILURE - P=O")
	}

	P = bls12383.G1mul(G, r)

	if !P.Is_infinity() {
		b.Error("FAILURE - rP!=O")
	}

	Q := bls12383.ECP2_generator()

	w := bls12383.Ate(Q, P)
	w = bls12383.Fexp(w)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = bls12383.Fexp(w)
	}
}
