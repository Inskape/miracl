// /*
//  * Copyright (c) 2012-2020 MIRACL UK Ltd.
//  *
//  * This file is part of MIRACL Core
//  * (see https://github.com/miracl/core).
//  *
//  * Licensed under the Apache License, Version 2.0 (the "License");
//  * you may not use this file except in compliance with the License.
//  * You may obtain a copy of the License at
//  *
//  *     http://www.apache.org/licenses/LICENSE-2.0
//  *
//  * Unless required by applicable law or agreed to in writing, software
//  * distributed under the License is distributed on an "AS IS" BASIS,
//  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  * See the License for the specific language governing permissions and
//  * limitations under the License.
//  */

// /* test driver and function exerciser for NewHope Simple Functions */
// // See https://eprint.iacr.org/2016/1157 (Alkim, Ducas, Popplemann and Schwabe)

package core_test

import (
	"bytes"
	"encoding/hex"
	"miracl/core"
	"testing"
)

var (
	sraw [100]byte
	srng *core.RAND

	craw [100]byte
	crng *core.RAND
)

func TestMain(m *testing.M) {
	srng = core.NewRAND()
	srng.Clean()
	for i := 0; i < 100; i++ {
		sraw[i] = byte(i)
	}
	srng.Seed(100, sraw[:])

	crng = core.NewRAND()
	crng.Clean()
	for i := 0; i < 100; i++ {
		craw[i] = byte(i)
	}
	crng.Seed(100, sraw[:])

	m.Run()
}

func TestNewHopeKeyExchange(t *testing.T) {
	var S [1792]byte

	// NewHope Simple key exchange -  - see https://eprint.iacr.org/2016/1157.pdf Protocol 1
	var SB [1824]byte
	core.NHS_SERVER_1(srng, SB[:], S[:])
	var UC [2176]byte
	var KEYB [32]byte
	core.NHS_CLIENT(crng, SB[:], UC[:], KEYB[:])

	t.Logf("Bob's Key: 0x%s", hex.EncodeToString(KEYB[:]))

	var KEYA [32]byte
	core.NHS_SERVER_2(S[:], UC[:], KEYA[:])

	t.Logf("Alice's Key: 0x%s", hex.EncodeToString(KEYA[:]))

	if !bytes.Equal(KEYA[:], KEYB[:]) {
		t.Error("Keys are not identical")
	}
}
