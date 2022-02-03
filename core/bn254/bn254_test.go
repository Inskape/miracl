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

package bn254_test

import (
	"miracl/core"
	"miracl/core/bn254"
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

func TestBN254(t *testing.T) {
	if bn254.CURVE_PAIRING_TYPE == bn254.BN {
		t.Log("BN Pairing-Friendly Curve")
	}
	if bn254.CURVE_PAIRING_TYPE > bn254.BN {
		t.Log("BLS Pairing-Friendly Curve")
	}

	t.Logf("Modulus size %d bits", bn254.MODBITS)
	t.Logf("%d bit build", core.CHUNK)

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
