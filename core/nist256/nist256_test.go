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

package nist256_test

import (
	"miracl/core"
	"miracl/core/nist256"
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

func TestNist256(t *testing.T) {
	switch nist256.CURVETYPE {
	case nist256.WEIERSTRASS:
		t.Log("Weierstrass parameterization")
	case nist256.EDWARDS:
		t.Log("Edwards parameterization")
	case nist256.MONTGOMERY:
		t.Log("Montgomery parameterization")
	}

	switch nist256.MODTYPE {
	case nist256.PSEUDO_MERSENNE:
		t.Log("Pseudo-Mersenne Modulus")
	case nist256.MONTGOMERY_FRIENDLY:
		t.Log("Montgomery friendly Modulus")
	case nist256.GENERALISED_MERSENNE:
		t.Log("Generalised-Mersenne Modulus")
	case nist256.NOT_SPECIAL:
		t.Log("Not special Modulus")
	}

	t.Logf("Modulus size %d bits", nist256.MODBITS)
	t.Logf("%d bit build", core.CHUNK)

	var rw *nist256.FP
	var WP *nist256.ECP

	EG := nist256.ECP_generator()
	er := nist256.NewBIGints(nist256.CURVE_Order)

	for i := 0; i < 10; i++ {
		rw = nist256.NewFPrand(rng)
		WP = nist256.ECP_map2point(rw)
		WP.Cfp()
		if WP.Is_infinity() {
			t.Error("HASHING FAILURE - P=O")
		}
	}

	WP = EG.Mul(er)
	if !WP.Is_infinity() {
		t.Error("FAILURE - rG!=O")
	}
}

func BenchmarkNist256Mul(b *testing.B) {
	var rw *nist256.FP
	var WP *nist256.ECP

	EG := nist256.ECP_generator()
	er := nist256.NewBIGints(nist256.CURVE_Order)
	es := nist256.Randtrunc(er, 16*nist256.AESKEY, rng)

	for i := 0; i < 10; i++ {
		rw = nist256.NewFPrand(rng)
		WP = nist256.ECP_map2point(rw)
		WP.Cfp()
		if WP.Is_infinity() {
			b.Error("HASHING FAILURE - P=O")
		}
	}

	WP = EG.Mul(er)
	if !WP.Is_infinity() {
		b.Error("FAILURE - rG!=O")
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = EG.Mul(es)
	}
}
