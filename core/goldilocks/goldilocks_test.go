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

package goldilocks_test

import (
	"miracl/core"
	"miracl/core/goldilocks"
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

func TestGoldilocks(t *testing.T) {
	switch goldilocks.CURVETYPE {
	case goldilocks.WEIERSTRASS:
		t.Log("Weierstrass parameterization")
	case goldilocks.EDWARDS:
		t.Log("Edwards parameterization")
	case goldilocks.MONTGOMERY:
		t.Log("Montgomery parameterization")
	}

	switch goldilocks.MODTYPE {
	case goldilocks.PSEUDO_MERSENNE:
		t.Log("Pseudo-Mersenne Modulus")
	case goldilocks.MONTGOMERY_FRIENDLY:
		t.Log("Montgomery friendly Modulus")
	case goldilocks.GENERALISED_MERSENNE:
		t.Log("Generalised-Mersenne Modulus")
	case goldilocks.NOT_SPECIAL:
		t.Log("Not special Modulus")
	}

	t.Logf("Modulus size %d bits", goldilocks.MODBITS)
	t.Logf("%d bit build", core.CHUNK)

	var rw *goldilocks.FP
	var WP *goldilocks.ECP

	EG := goldilocks.ECP_generator()
	er := goldilocks.NewBIGints(goldilocks.CURVE_Order)

	for i := 0; i < 10; i++ {
		rw = goldilocks.NewFPrand(rng)
		WP = goldilocks.ECP_map2point(rw)
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

func BenchmarkGoldilocksMul(b *testing.B) {
	var rw *goldilocks.FP
	var WP *goldilocks.ECP

	EG := goldilocks.ECP_generator()
	er := goldilocks.NewBIGints(goldilocks.CURVE_Order)
	es := goldilocks.Randtrunc(er, 16*goldilocks.AESKEY, rng)
	for i := 0; i < 10; i++ {
		rw = goldilocks.NewFPrand(rng)
		WP = goldilocks.ECP_map2point(rw)
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
