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

package c25519_test

import (
	"encoding/hex"
	"miracl/core"
	"miracl/core/c25519"
	"testing"
)

var (
	skE [c25519.EGS]byte
	skR [c25519.EGS]byte
	skS [c25519.EGS]byte
	pkE [c25519.EFS]byte
	pkR [c25519.EFS]byte
	pkS [c25519.EFS]byte

	config_id = 0x520

	INFO, _  = hex.DecodeString("4f6465206f6e2061204772656369616e2055726e")
	psk, _   = hex.DecodeString("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82")
	pskID, _ = hex.DecodeString("456e6e796e20447572696e206172616e204d6f726961")
	PLAIN, _ = hex.DecodeString("4265617574792069732074727574682c20747275746820626561757479")
	AAD, _   = hex.DecodeString("436f756e742d30")
)

func TestC25519HpkeMode0(t *testing.T) {
	mode := 0
	seedE, _ := hex.DecodeString("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234")
	seedR, _ := hex.DecodeString("6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037")
	c25519.DeriveKeyPair(config_id, skE[:], pkE[:], seedE)
	c25519.DeriveKeyPair(config_id, skR[:], pkR[:], seedR)

	Z := c25519.Encap(config_id, skE[:], pkE[:], pkR[:])
	t.Logf("pkE: 0x%s", hex.EncodeToString(pkE[:]))
	t.Logf("Encapsulated Z: 0x%s", hex.EncodeToString(Z[:]))

	Z = c25519.Decap(config_id, skR[:], pkE[:], pkR[:])
	t.Logf("Decapsulated Z: 0x%s", hex.EncodeToString(Z[:]))

	KEY, NONCE, EXP_SECRET := c25519.KeySchedule(config_id, mode, Z, INFO, nil, nil)
	t.Logf("Key: 0x%s", hex.EncodeToString(KEY[:]))
	t.Logf("Nonce: 0x%s", hex.EncodeToString(NONCE[:]))
	t.Logf("Exporter Secret: 0x%s", hex.EncodeToString(EXP_SECRET[:]))

	CIPHER, TAG := core.GCM_ENCRYPT(KEY, NONCE, AAD, PLAIN)
	t.Logf("Cipher: 0x%s", hex.EncodeToString(CIPHER[:]))
	t.Logf("Tag: 0x%s", hex.EncodeToString(TAG[:]))
}

func TestC25519HpkeMode1(t *testing.T) {
	mode := 1
	seedE, _ := hex.DecodeString("78628c354e46f3e169bd231be7b2ff1c77aa302460a26dbfa15515684c00130b")
	seedR, _ := hex.DecodeString("d4a09d09f575fef425905d2ab396c1449141463f698f8efdb7accfaff8995098")
	c25519.DeriveKeyPair(config_id, skE[:], pkE[:], seedE)
	c25519.DeriveKeyPair(config_id, skR[:], pkR[:], seedR)

	Z := c25519.Encap(config_id, skE[:], pkE[:], pkR[:])
	t.Logf("pkE: 0x%s", hex.EncodeToString(pkE[:]))
	t.Logf("Encapsulated Z: 0x%s", hex.EncodeToString(Z[:]))

	Z = c25519.Decap(config_id, skR[:], pkE[:], pkR[:])
	t.Logf("Decapsulated Z: 0x%s", hex.EncodeToString(Z[:]))

	KEY, NONCE, EXP_SECRET := c25519.KeySchedule(config_id, mode, Z, INFO, psk, pskID)
	t.Logf("Key: 0x%s", hex.EncodeToString(KEY[:]))
	t.Logf("Nonce: 0x%s", hex.EncodeToString(NONCE[:]))
	t.Logf("Exporter Secret: 0x%s", hex.EncodeToString(EXP_SECRET[:]))

	CIPHER, TAG := core.GCM_ENCRYPT(KEY, NONCE, AAD, PLAIN)
	t.Logf("Cipher: 0x%s", hex.EncodeToString(CIPHER[:]))
	t.Logf("Tag: 0x%s", hex.EncodeToString(TAG[:]))
}

func TestC25519HpkeMode2(t *testing.T) {
	mode := 2
	seedE, _ := hex.DecodeString("6e6d8f200ea2fb20c30b003a8b4f433d2f4ed4c2658d5bc8ce2fef718059c9f7")
	seedR, _ := hex.DecodeString("f1d4a30a4cef8d6d4e3b016e6fd3799ea057db4f345472ed302a67ce1c20cdec")
	seedS, _ := hex.DecodeString("94b020ce91d73fca4649006c7e7329a67b40c55e9e93cc907d282bbbff386f58")
	c25519.DeriveKeyPair(config_id, skE[:], pkE[:], seedE)
	c25519.DeriveKeyPair(config_id, skR[:], pkR[:], seedR)
	c25519.DeriveKeyPair(config_id, skS[:], pkS[:], seedS)

	Z := c25519.AuthEncap(config_id, skE[:], skS[:], pkE[:], pkR[:], pkS[:])
	t.Logf("pkE: 0x%s", hex.EncodeToString(pkE[:]))
	t.Logf("Encapsulated Z: 0x%s", hex.EncodeToString(Z[:]))

	Z = c25519.AuthDecap(config_id, skR[:], pkE[:], pkR[:], pkS[:])
	t.Logf("Decapsulated Z: 0x%s", hex.EncodeToString(Z[:]))

	KEY, NONCE, EXP_SECRET := c25519.KeySchedule(config_id, mode, Z, INFO, nil, nil)
	t.Logf("Key: 0x%s", hex.EncodeToString(KEY[:]))
	t.Logf("Nonce: 0x%s", hex.EncodeToString(NONCE[:]))
	t.Logf("Exporter Secret: 0x%s", hex.EncodeToString(EXP_SECRET[:]))

	CIPHER, TAG := core.GCM_ENCRYPT(KEY, NONCE, AAD, PLAIN)
	t.Logf("Cipher: 0x%s", hex.EncodeToString(CIPHER[:]))
	t.Logf("Tag: 0x%s", hex.EncodeToString(TAG[:]))
}
func TestC25519HpkeMode3(t *testing.T) {
	mode := 3
	seedE, _ := hex.DecodeString("4303619085a20ebcf18edd22782952b8a7161e1dbae6e46e143a52a96127cf84")
	seedR, _ := hex.DecodeString("4b16221f3b269a88e207270b5e1de28cb01f847841b344b8314d6a622fe5ee90")
	seedS, _ := hex.DecodeString("62f77dcf5df0dd7eac54eac9f654f426d4161ec850cc65c54f8b65d2e0b4e345")
	c25519.DeriveKeyPair(config_id, skE[:], pkE[:], seedE)
	c25519.DeriveKeyPair(config_id, skR[:], pkR[:], seedR)
	c25519.DeriveKeyPair(config_id, skS[:], pkS[:], seedS)

	Z := c25519.AuthEncap(config_id, skE[:], skS[:], pkE[:], pkR[:], pkS[:])
	t.Logf("pkE: 0x%s", hex.EncodeToString(pkE[:]))
	t.Logf("Encapsulated Z: 0x%s", hex.EncodeToString(Z[:]))

	Z = c25519.AuthDecap(config_id, skR[:], pkE[:], pkR[:], pkS[:])
	t.Logf("Decapsulated Z: 0x%s", hex.EncodeToString(Z[:]))

	KEY, NONCE, EXP_SECRET := c25519.KeySchedule(config_id, mode, Z, INFO, psk, pskID)
	t.Logf("Key: 0x%s", hex.EncodeToString(KEY[:]))
	t.Logf("Nonce: 0x%s", hex.EncodeToString(NONCE[:]))
	t.Logf("Exporter Secret: 0x%s", hex.EncodeToString(EXP_SECRET[:]))

	CIPHER, TAG := core.GCM_ENCRYPT(KEY, NONCE, AAD, PLAIN)
	t.Logf("Cipher: 0x%s", hex.EncodeToString(CIPHER[:]))
	t.Logf("Tag: 0x%s", hex.EncodeToString(TAG[:]))
}
