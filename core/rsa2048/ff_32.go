//go:build 386 || amd64p32 || arm || armbe || mips || mips64p32 || mips64p32le || mipsle || ppc || riscv || s390 || sparc
// +build 386 amd64p32 arm armbe mips mips64p32 mips64p32le mipsle ppc riscv s390 sparc

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

package rsa2048

func ff_pexceed(a *BIG, b *BIG) bool {
	ea := FF_EXCESS(a)
	eb := FF_EXCESS(b)
	if DChunk(ea+1)*DChunk(eb+1) > DChunk(P_FEXCESS) {
		return true
	}
	return false
}

func ff_sexceed(a *BIG) bool {
	ea := FF_EXCESS(a)
	if DChunk(ea+1)*DChunk(ea+1) > DChunk(P_FEXCESS) {
		return true
	}
	return false
}
