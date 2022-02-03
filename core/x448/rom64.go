//go:build !386 && !amd64p32 && !arm && !armbe && !mips && !mips64p32 && !mips64p32le && !mipsle && !ppc && !riscv && !s390 && !sparc
// +build !386,!amd64p32,!arm,!armbe,!mips,!mips64p32,!mips64p32le,!mipsle,!ppc,!riscv,!s390,!sparc

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
/* Fixed Data in ROM - Field and Curve parameters */

package x448

import "miracl/core"

// Base Bits= 58
var Modulus = [...]core.Chunk{0x3FFFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFF, 0x3FBFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFF, 0x3FFFFFFFFFF}
var R2modp = [...]core.Chunk{0x200000000, 0x0, 0x0, 0x0, 0x3000000, 0x0, 0x0, 0x0}
var ROI = [...]core.Chunk{0x3FFFFFFFFFFFFFE, 0x3FFFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFF, 0x3FBFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFF, 0x3FFFFFFFFFF}

const MConst core.Chunk = 0x1

const CURVE_Cof_I int = 4

var CURVE_Cof = [...]core.Chunk{0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}

const CURVE_B_I int = 0

var CURVE_B = [...]core.Chunk{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
var CURVE_Order = [...]core.Chunk{0x378C292AB5844F3, 0x3309CA37163D548, 0x1B49AED63690216, 0x3FDF3288FA7113B, 0x3FFFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFF, 0xFFFFFFFFFF}
var CURVE_Gx = [...]core.Chunk{0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
var CURVE_Gy = [...]core.Chunk{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
var CURVE_HTPC = [...]core.Chunk{0x3FFFFFFFFFFFFFE, 0x3FFFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFF, 0x3FBFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFF, 0x3FFFFFFFFFF}
