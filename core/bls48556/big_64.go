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

/* core BIG number class */

package bls48556

import (
	"math/bits"
)

/***************** 64-bit specific code ****************/

/* First the 32/64-bit dependent BIG code */
/* Note that because of the lack of a 128-bit integer, 32 and 64-bit code needs to be done differently */

/* return a*b as DBIG */
func mul(a *BIG, b *BIG) *DBIG {
	c := NewDBIG()
	carry := Chunk(0)

	for i := 0; i < NLEN; i++ {
		carry = 0
		for j := 0; j < NLEN; j++ {
			carry, c.w[i+j] = muladd(a.w[i], b.w[j], carry, c.w[i+j])
		}
		c.w[NLEN+i] = carry
	}

	return c
}

/* return a^2 as DBIG */
func sqr(a *BIG) *DBIG {
	c := NewDBIG()
	carry := Chunk(0)

	for i := 0; i < NLEN; i++ {
		carry = 0
		for j := i + 1; j < NLEN; j++ {
			//if a.w[i]<0 {fmt.Printf("Negative m i in sqr\n")}
			//if a.w[j]<0 {fmt.Printf("Negative m j in sqr\n")}
			carry, c.w[i+j] = muladd(2*a.w[i], a.w[j], carry, c.w[i+j])
		}
		c.w[NLEN+i] = carry
	}

	for i := 0; i < NLEN; i++ {
		//if a.w[i]<0 {fmt.Printf("Negative m s in sqr\n")}
		top, bot := muladd(a.w[i], a.w[i], 0, c.w[2*i])

		c.w[2*i] = bot
		c.w[2*i+1] += top
	}
	c.norm()
	return c
}

func monty(md *BIG, mc Chunk, d *DBIG) *BIG {
	carry := Chunk(0)
	m := Chunk(0)
	for i := 0; i < NLEN; i++ {
		if mc == -1 {
			m = (-d.w[i]) & BMASK
		} else {
			if mc == 1 {
				m = d.w[i]
			} else {
				m = (mc * d.w[i]) & BMASK
			}
		}

		carry = 0
		for j := 0; j < NLEN; j++ {
			carry, d.w[i+j] = muladd(m, md.w[j], carry, d.w[i+j])
			//if m<0 {fmt.Printf("Negative m in monty\n")}
			//if md.w[j]<0 {fmt.Printf("Negative m in monty\n")}
		}
		d.w[NLEN+i] += carry
	}

	b := NewBIG()
	for i := 0; i < NLEN; i++ {
		b.w[i] = d.w[NLEN+i]
	}
	b.norm()
	return b
}

/* set this[i]+=x*y+c, and return high part */
func muladd(a Chunk, b Chunk, c Chunk, r Chunk) (Chunk, Chunk) {

	tp, bt := bits.Mul64(uint64(a), uint64(b)) // use math/bits intrinsic
	bot := Chunk(bt & uint64(BMASK))
	top := Chunk((tp << (64 - BASEBITS)) | (bt >> BASEBITS))
	bot += c
	bot += r
	carry := bot >> BASEBITS
	bot &= BMASK
	top += carry
	return top, bot

}
