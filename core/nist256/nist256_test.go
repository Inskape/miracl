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
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/Inskape/miracl/core"
	"github.com/Inskape/miracl/core/nist256"
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
	t.Logf("%d bit build", nist256.CHUNK)

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

func TestNist256Ecdhe(t *testing.T) {
	//	j:=0
	pp := "M0ng00se"
	res := 0

	var sha = nist256.HASH_TYPE

	var S1 [nist256.EGS]byte
	var W0 [2*nist256.EFS + 1]byte
	var W1 [2*nist256.EFS + 1]byte
	var Z0 [nist256.EFS]byte
	var Z1 [nist256.EFS]byte
	var SALT [8]byte
	var P1 [3]byte
	var P2 [4]byte
	var V [2*nist256.EFS + 1]byte
	var M [17]byte
	var T [12]byte
	var CS [nist256.EGS]byte
	var DS [nist256.EGS]byte

	for i := 0; i < 8; i++ {
		SALT[i] = rng.GetByte()
	} // set Salt

	t.Logf("Alice's Passphrase: %s", pp)
	PW := []byte(pp)

	/* private key S0 of size MGS bytes derived from Password and Salt */

	S0 := core.PBKDF2(core.MC_SHA2, sha, PW, SALT[:], 1000, nist256.EGS)

	t.Logf("Alice's private key: 0x%s", hex.EncodeToString(S0))

	/* Generate Key pair S/W */
	nist256.ECDH_KEY_PAIR_GENERATE(nil, S0, W0[:])

	t.Logf("Alice's public key: 0x%s", hex.EncodeToString(W0[:]))

	res = nist256.ECDH_PUBLIC_KEY_VALIDATE(W0[:])
	if res != 0 {
		t.Error("ECP Public Key is invalid")
	}

	/* Random private key for other party */
	nist256.ECDH_KEY_PAIR_GENERATE(rng, S1[:], W1[:])

	t.Logf("Servers private key: 0x%s", hex.EncodeToString(S1[:]))
	t.Logf("Servers public key: 0x%s", hex.EncodeToString(W1[:]))

	res = nist256.ECDH_PUBLIC_KEY_VALIDATE(W1[:])
	if res != 0 {
		t.Error("ECP Public Key is invalid")
	}
	/* Calculate common key using DH - IEEE 1363 method */

	nist256.ECDH_ECPSVDP_DH(S0, W1[:], Z0[:], 0)
	nist256.ECDH_ECPSVDP_DH(S1[:], W0[:], Z1[:], 0)

	if !bytes.Equal(Z0[:], Z1[:]) {
		t.Error("*** ECPSVDP-DH Failed")
	}

	KEY := core.KDF2(core.MC_SHA2, sha, Z0[:], nil, nist256.AESKEY)

	t.Logf("Alice's DH Key: 0x%s", hex.EncodeToString(KEY))
	t.Logf("Servers DH Key: 0x%s", hex.EncodeToString(KEY))

	if nist256.CURVETYPE != nist256.MONTGOMERY {
		t.Log("Testing ECIES")

		P1[0] = 0x0
		P1[1] = 0x1
		P1[2] = 0x2
		P2[0] = 0x0
		P2[1] = 0x1
		P2[2] = 0x2
		P2[3] = 0x3

		for i := 0; i <= 16; i++ {
			M[i] = rng.GetByte()
		}

		C := nist256.ECDH_ECIES_ENCRYPT(sha, P1[:], P2[:], rng, W1[:], M[:], V[:], T[:])

		t.Log("Ciphertext:")
		t.Logf("V: 0x%s", hex.EncodeToString(V[:]))
		t.Logf("C: 0x%s", hex.EncodeToString(C[:]))
		t.Logf("T: 0x%s", hex.EncodeToString(T[:]))

		RM := nist256.ECDH_ECIES_DECRYPT(sha, P1[:], P2[:], V[:], C, T[:], S1[:])
		if RM == nil {
			t.Error("*** ECIES Decryption Failed")
		} else {
			t.Log("Decryption succeeded")
		}

		t.Logf("Message: 0x%s", hex.EncodeToString(RM))

		t.Log("Testing ECDSA")

		if nist256.ECDH_ECPSP_DSA(sha, rng, S0, M[:], CS[:], DS[:]) != 0 {
			t.Error("***ECDSA Signature Failed")
		}
		t.Log("Signature:")
		t.Logf("C: 0x%s", hex.EncodeToString(CS[:]))
		t.Logf("D: 0x%s", hex.EncodeToString(DS[:]))

		if nist256.ECDH_ECPVP_DSA(sha, W0[:], M[:], CS[:], DS[:]) != 0 {
			t.Error("***ECDSA Verification Failed")
		} else {
			t.Log("ECDSA Signature/Verification succeeded")
		}
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
