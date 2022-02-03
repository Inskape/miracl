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

package rsa2048_test

import (
	"fmt"
	"miracl/core"
	"miracl/core/rsa2048"
	"testing"
)

var (
	RAW [100]byte
	rng *core.RAND

	// PT [rsa2048.RFS]byte
	// M  [rsa2048.RFS]byte
	// CT [rsa2048.RFS]byte

	// pub  = rsa2048.New_public_key(rsa2048.FFLEN)
	// priv = rsa2048.New_private_key(rsa2048.HFLEN)
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

func TestRsa2048(t *testing.T) {
	pub := rsa2048.New_public_key(rsa2048.FFLEN)
	priv := rsa2048.New_private_key(rsa2048.HFLEN)

	var PT [rsa2048.RFS]byte
	var M [rsa2048.RFS]byte
	var CT [rsa2048.RFS]byte

	rsa2048.RSA_KEY_PAIR(rng, 65537, priv, pub)

	for i := 0; i < rsa2048.RFS; i++ {
		M[i] = byte(i % 128)
	}

	rsa2048.RSA_ENCRYPT(pub, M[:], CT[:])

	rsa2048.RSA_DECRYPT(priv, CT[:], PT[:])

	for i := 0; i < rsa2048.RFS; i++ {
		if PT[i] != M[i] {
			t.Error("FAILURE - RSA decryption")
			return
		}
	}

	fmt.Printf("All tests pass\n")
}

func BenchmarkRSA2048GenerateKeyPair(b *testing.B) {
	pub := rsa2048.New_public_key(rsa2048.FFLEN)
	priv := rsa2048.New_private_key(rsa2048.HFLEN)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		rsa2048.RSA_KEY_PAIR(rng, 65537, priv, pub)
	}
}

func BenchmarkRSA2048Encrypt(b *testing.B) {
	b.Skip("Encryption does not finish")
	pub := rsa2048.New_public_key(rsa2048.FFLEN)

	var M [rsa2048.RFS]byte
	var CT [rsa2048.RFS]byte

	for i := 0; i < rsa2048.RFS; i++ {
		M[i] = byte(i % 128)
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		rsa2048.RSA_ENCRYPT(pub, M[:], CT[:])
	}
}

func BenchmarkRSA2048Decrypt(b *testing.B) {
	b.Skip("Encryption does not finish")
	pub := rsa2048.New_public_key(rsa2048.FFLEN)
	priv := rsa2048.New_private_key(rsa2048.HFLEN)

	var PT [rsa2048.RFS]byte
	var M [rsa2048.RFS]byte
	var CT [rsa2048.RFS]byte

	for i := 0; i < rsa2048.RFS; i++ {
		M[i] = byte(i % 128)
	}

	rsa2048.RSA_ENCRYPT(pub, M[:], CT[:])

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		rsa2048.RSA_DECRYPT(priv, CT[:], PT[:])
	}
}
