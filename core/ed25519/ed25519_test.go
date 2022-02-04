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

package ed25519_test

import (
	"bytes"
	"encoding/hex"
	"miracl/core/ed25519"
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
	t.Logf("%d bit build", ed25519.CHUNK)

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

func TestEd25518Ecdhe(t *testing.T) {
	//	j:=0
	pp := "M0ng00se"
	res := 0

	var sha = ed25519.HASH_TYPE

	var S1 [ed25519.EGS]byte
	var W0 [2*ed25519.EFS + 1]byte
	var W1 [2*ed25519.EFS + 1]byte
	var Z0 [ed25519.EFS]byte
	var Z1 [ed25519.EFS]byte
	var SALT [8]byte
	var P1 [3]byte
	var P2 [4]byte
	var V [2*ed25519.EFS + 1]byte
	var M [17]byte
	var T [12]byte
	var CS [ed25519.EGS]byte
	var DS [ed25519.EGS]byte

	for i := 0; i < 8; i++ {
		SALT[i] = rng.GetByte()
	} // set Salt

	t.Logf("Alice's Passphrase: %s", pp)
	PW := []byte(pp)

	/* private key S0 of size MGS bytes derived from Password and Salt */
	S0 := core.PBKDF2(core.MC_SHA2, sha, PW, SALT[:], 1000, ed25519.EGS)

	t.Logf("Alice's private key: 0x%s", hex.EncodeToString(S0))

	/* Generate Key pair S/W */
	ed25519.ECDH_KEY_PAIR_GENERATE(nil, S0, W0[:])

	t.Logf("Alice's public key: 0x%s", hex.EncodeToString(W0[:]))

	res = ed25519.ECDH_PUBLIC_KEY_VALIDATE(W0[:])
	if res != 0 {
		t.Error("ECP Public Key is invalid")
	}

	/* Random private key for other party */
	ed25519.ECDH_KEY_PAIR_GENERATE(rng, S1[:], W1[:])

	t.Logf("Servers private key: 0x%s", hex.EncodeToString(S1[:]))
	t.Logf("Servers public key: 0x%s", hex.EncodeToString(W1[:]))

	res = ed25519.ECDH_PUBLIC_KEY_VALIDATE(W1[:])
	if res != 0 {
		t.Error("ECP Public Key is invalid")
	}

	/* Calculate common key using DH - IEEE 1363 method */
	ed25519.ECDH_ECPSVDP_DH(S0, W1[:], Z0[:], 0)
	ed25519.ECDH_ECPSVDP_DH(S1[:], W0[:], Z1[:], 0)

	if !bytes.Equal(Z0[:], Z1[:]) {
		t.Error("*** ECPSVDP-DH Failed")
	}

	KEY := core.KDF2(core.MC_SHA2, sha, Z0[:], nil, ed25519.AESKEY)

	t.Logf("Alice's DH Key: 0x%s", hex.EncodeToString(KEY))
	t.Logf("Servers DH Key: 0x%s", hex.EncodeToString(KEY))

	if ed25519.CURVETYPE != ed25519.MONTGOMERY {
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

		C := ed25519.ECDH_ECIES_ENCRYPT(sha, P1[:], P2[:], rng, W1[:], M[:], V[:], T[:])

		t.Log("Ciphertext:")
		t.Logf("V: 0x%s", hex.EncodeToString(V[:]))
		t.Logf("C: 0x%s", hex.EncodeToString(C[:]))
		t.Logf("T: 0x%s", hex.EncodeToString(T[:]))

		RM := ed25519.ECDH_ECIES_DECRYPT(sha, P1[:], P2[:], V[:], C, T[:], S1[:])
		if RM == nil {
			t.Error("*** ECIES Decryption Failed")
		} else {
			t.Log("Decryption succeeded")
		}

		t.Logf("Message: 0x%s", hex.EncodeToString(RM))

		t.Log("Testing ECDSA")

		if ed25519.ECDH_ECPSP_DSA(sha, rng, S0, M[:], CS[:], DS[:]) != 0 {
			t.Error("***ECDSA Signature Failed")
		}
		t.Log("Signature:")
		t.Logf("C: 0x%s", hex.EncodeToString(CS[:]))
		t.Logf("D: 0x%s", hex.EncodeToString(DS[:]))

		if ed25519.ECDH_ECPVP_DSA(sha, W0[:], M[:], CS[:], DS[:]) != 0 {
			t.Error("***ECDSA Verification Failed")
		} else {
			t.Log("ECDSA Signature/Verification succeeded")
		}
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
