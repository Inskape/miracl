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

package nist521_test

import (
	"encoding/hex"
	"testing"

	"github.com/Inskape/miracl/core"
	"github.com/Inskape/miracl/core/nist521"
)

var (
	skE [nist521.EGS]byte
	skR [nist521.EGS]byte
	skS [nist521.EGS]byte
	pkE [2*nist521.EFS + 1]byte
	pkR [2*nist521.EFS + 1]byte
	pkS [2*nist521.EFS + 1]byte

	config_id = 0xB12

	INFO, _  = hex.DecodeString("4f6465206f6e2061204772656369616e2055726e")
	psk, _   = hex.DecodeString("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82")
	pskID, _ = hex.DecodeString("456e6e796e20447572696e206172616e204d6f726961")
	PLAIN, _ = hex.DecodeString("4265617574792069732074727574682c20747275746820626561757479")
	AAD, _   = hex.DecodeString("436f756e742d30")
)

func TestNIST521HpkeMode0(t *testing.T) {
	mode := 0
	seedE, _ := hex.DecodeString("7f06ab8215105fc46aceeb2e3dc5028b44364f960426eb0d8e4026c2f8b5d7e7a986688f1591abf5ab753c357a5d6f0440414b4ed4ede71317772ac98d9239f70904")
	seedR, _ := hex.DecodeString("2ad954bbe39b7122529f7dde780bff626cd97f850d0784a432784e69d86eccaade43b6c10a8ffdb94bf943c6da479db137914ec835a7e715e36e45e29b587bab3bf1")
	nist521.DeriveKeyPair(config_id, skE[:], pkE[:], seedE)
	nist521.DeriveKeyPair(config_id, skR[:], pkR[:], seedR)

	Z := nist521.Encap(config_id, skE[:], pkE[:], pkR[:])
	t.Logf("pkE: 0x%s", hex.EncodeToString(pkE[:]))
	t.Logf("Encapsulated Z: 0x%s", hex.EncodeToString(Z[:]))

	Z = nist521.Decap(config_id, skR[:], pkE[:], pkR[:])
	t.Logf("Decapsulated Z: 0x%s", hex.EncodeToString(Z[:]))

	KEY, NONCE, EXP_SECRET := nist521.KeySchedule(config_id, mode, Z, INFO, nil, nil)
	t.Logf("Key: 0x%s", hex.EncodeToString(KEY[:]))
	t.Logf("Nonce: 0x%s", hex.EncodeToString(NONCE[:]))
	t.Logf("Exporter Secret: 0x%s", hex.EncodeToString(EXP_SECRET[:]))

	CIPHER, TAG := core.GCM_ENCRYPT(KEY, NONCE, AAD, PLAIN)
	t.Logf("Cipher: 0x%s", hex.EncodeToString(CIPHER[:]))
	t.Logf("Tag: 0x%s", hex.EncodeToString(TAG[:]))
}

func TestNIST521HpkeMode1(t *testing.T) {
	mode := 1
	seedE, _ := hex.DecodeString("f3ebfa9a69a924e672114fcd9e06fa9559e937f7eccce4181a2b506df53dbe514be12f094bb28e01de19dd345b4f7ede5ad7eaa6b9c3019592ec68eaae9a14732ce0")
	seedR, _ := hex.DecodeString("a2a2458705e278e574f835effecd18232f8a4c459e7550a09d44348ae5d3b1ea9d95c51995e657ad6f7cae659f5e186126a471c017f8f5e41da9eba74d4e0473e179")
	nist521.DeriveKeyPair(config_id, skE[:], pkE[:], seedE)
	nist521.DeriveKeyPair(config_id, skR[:], pkR[:], seedR)

	Z := nist521.Encap(config_id, skE[:], pkE[:], pkR[:])
	t.Logf("pkE: 0x%s", hex.EncodeToString(pkE[:]))
	t.Logf("Encapsulated Z: 0x%s", hex.EncodeToString(Z[:]))

	Z = nist521.Decap(config_id, skR[:], pkE[:], pkR[:])
	t.Logf("Decapsulated Z: 0x%s", hex.EncodeToString(Z[:]))

	KEY, NONCE, EXP_SECRET := nist521.KeySchedule(config_id, mode, Z, INFO, psk, pskID)
	t.Logf("Key: 0x%s", hex.EncodeToString(KEY[:]))
	t.Logf("Nonce: 0x%s", hex.EncodeToString(NONCE[:]))
	t.Logf("Exporter Secret: 0x%s", hex.EncodeToString(EXP_SECRET[:]))

	CIPHER, TAG := core.GCM_ENCRYPT(KEY, NONCE, AAD, PLAIN)
	t.Logf("Cipher: 0x%s", hex.EncodeToString(CIPHER[:]))
	t.Logf("Tag: 0x%s", hex.EncodeToString(TAG[:]))
}

func TestNIST521HpkeMode2(t *testing.T) {
	mode := 2
	seedE, _ := hex.DecodeString("fe1c589c2a05893895a537f38c7cb4300b5a7e8fef3d6ccb8f07a498029c61e90262e009dc254c7f6235f9c6b2fd6aeff0a714db131b09258c16e217b7bd2aa619b0")
	seedR, _ := hex.DecodeString("8feea0438481fc0ecd470d6adfcda334a759c6b8650452c5a5dd9b2dd2cc9be33d2bb7ee64605fc07ab4664a58bb9a8de80defe510b6c97d2daf85b92cd4bb0a66bf")
	seedS, _ := hex.DecodeString("2f66a68b85ef04822b054ef521838c00c64f8b6226935593b69e13a1a2461a4f1a74c10c836e87eed150c0db85d4e4f506cbb746149befac6f5c07dc48a615ef92db")
	nist521.DeriveKeyPair(config_id, skE[:], pkE[:], seedE)
	nist521.DeriveKeyPair(config_id, skR[:], pkR[:], seedR)
	nist521.DeriveKeyPair(config_id, skS[:], pkS[:], seedS)

	Z := nist521.AuthEncap(config_id, skE[:], skS[:], pkE[:], pkR[:], pkS[:])
	t.Logf("pkE: 0x%s", hex.EncodeToString(pkE[:]))
	t.Logf("Encapsulated Z: 0x%s", hex.EncodeToString(Z[:]))

	Z = nist521.AuthDecap(config_id, skR[:], pkE[:], pkR[:], pkS[:])
	t.Logf("Decapsulated Z: 0x%s", hex.EncodeToString(Z[:]))

	KEY, NONCE, EXP_SECRET := nist521.KeySchedule(config_id, mode, Z, INFO, nil, nil)
	t.Logf("Key: 0x%s", hex.EncodeToString(KEY[:]))
	t.Logf("Nonce: 0x%s", hex.EncodeToString(NONCE[:]))
	t.Logf("Exporter Secret: 0x%s", hex.EncodeToString(EXP_SECRET[:]))

	CIPHER, TAG := core.GCM_ENCRYPT(KEY, NONCE, AAD, PLAIN)
	t.Logf("Cipher: 0x%s", hex.EncodeToString(CIPHER[:]))
	t.Logf("Tag: 0x%s", hex.EncodeToString(TAG[:]))
}

func TestNIST521HpkeMode3(t *testing.T) {
	mode := 3
	seedE, _ := hex.DecodeString("54272797b1fbc128a6967ff1fd606e0c67868f7762ce1421439cbc9e90ce1b28d566e6c2acbce712e48eebf236696eb680849d6873e9959395b2931975d61d38bd6c")
	seedR, _ := hex.DecodeString("3db434a8bc25b27eb0c590dc64997ab1378a99f52b2cb5a5a5b2fa540888f6c0f09794c654f4468524e040e6b4eca2c9dcf229f908b9d318f960cc9e9baa92c5eee6")
	seedS, _ := hex.DecodeString("65d523d9b37e1273eb25ad0527d3a7bd33f67208dd1666d9904c6bc04969ae5831a8b849e7ff642581f2c3e56be84609600d3c6bbdaded3f6989c37d2892b1e978d5")
	nist521.DeriveKeyPair(config_id, skE[:], pkE[:], seedE)
	nist521.DeriveKeyPair(config_id, skR[:], pkR[:], seedR)
	nist521.DeriveKeyPair(config_id, skS[:], pkS[:], seedS)

	Z := nist521.AuthEncap(config_id, skE[:], skS[:], pkE[:], pkR[:], pkS[:])
	t.Logf("pkE: 0x%s", hex.EncodeToString(pkE[:]))
	t.Logf("Encapsulated Z: 0x%s", hex.EncodeToString(Z[:]))

	Z = nist521.AuthDecap(config_id, skR[:], pkE[:], pkR[:], pkS[:])
	t.Logf("Decapsulated Z: 0x%s", hex.EncodeToString(Z[:]))

	KEY, NONCE, EXP_SECRET := nist521.KeySchedule(config_id, mode, Z, INFO, psk, pskID)
	t.Logf("Key: 0x%s", hex.EncodeToString(KEY[:]))
	t.Logf("Nonce: 0x%s", hex.EncodeToString(NONCE[:]))
	t.Logf("Exporter Secret: 0x%s", hex.EncodeToString(EXP_SECRET[:]))

	CIPHER, TAG := core.GCM_ENCRYPT(KEY, NONCE, AAD, PLAIN)
	t.Logf("Cipher: 0x%s", hex.EncodeToString(CIPHER[:]))
	t.Logf("Tag: 0x%s", hex.EncodeToString(TAG[:]))
}
