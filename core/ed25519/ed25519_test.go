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

package ed25519_test

import (
	"miracl/core"
	"miracl/core/ed25519"
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

func TestEd25519(t *testing.T) {
	switch ed25519.CURVETYPE {
	case ed25519.WEIERSTRASS:
		t.Log("Weierstrass parameterization")
	case ed25519.EDWARDS:
		t.Log("Edwards parameterization")
	case ed25519.MONTGOMERY:
		t.Log("Montgomery parameterization")
	}

	switch ed25519.MODTYPE {
	case ed25519.PSEUDO_MERSENNE:
		t.Log("Pseudo-Mersenne Modulus")
	case ed25519.MONTGOMERY_FRIENDLY:
		t.Log("Montgomery friendly Modulus")
	case ed25519.GENERALISED_MERSENNE:
		t.Log("Generalised-Mersenne Modulus")
	case ed25519.NOT_SPECIAL:
		t.Log("Not special Modulus")
	}

	t.Logf("Modulus size %d bits", ed25519.MODBITS)
	t.Logf("%d bit build", core.CHUNK)

	var rw *ed25519.FP
	var WP *ed25519.ECP
	EG := ed25519.ECP_generator()
	er := ed25519.NewBIGints(ed25519.CURVE_Order)

	for i := 0; i < 10; i++ {
		rw = ed25519.NewFPrand(rng)
		WP = ed25519.ECP_map2point(rw)
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

func BenchmarkEd25519Mul(b *testing.B) {
	var rw *ed25519.FP
	var WP *ed25519.ECP
	EG := ed25519.ECP_generator()
	er := ed25519.NewBIGints(ed25519.CURVE_Order)
	es := ed25519.Randtrunc(er, 16*ed25519.AESKEY, rng)

	for i := 0; i < 10; i++ {
		rw = ed25519.NewFPrand(rng)
		WP = ed25519.ECP_map2point(rw)
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
