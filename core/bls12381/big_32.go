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

/* core BIG number class */

package bls12381

/***************** 32-bit specific code ****************/

/* First the 32/64-bit dependent BIG code */
/* Note that because of the lack of a 128-bit integer, 32 and 64-bit code needs to be done differently */

/* return a*b as DBIG */
func mul(a *BIG, b *BIG) *DBIG {
	c := NewDBIG()

	//	BIGMULS+=1;

	var d [NLEN]DChunk

	for i := 0; i < NLEN; i++ {
		d[i] = DChunk(a.w[i]) * DChunk(b.w[i])
	}
	s := d[0]
	t := s
	c.w[0] = Chunk(t) & BMASK
	co := t >> BASEBITS

	for k := 1; k < NLEN; k++ {
		s += d[k]
		t = co + s
		for i := k; i >= 1+k/2; i-- {
			t += DChunk(a.w[i]-a.w[k-i]) * DChunk(b.w[k-i]-b.w[i])
		}
		c.w[k] = Chunk(t) & BMASK
		co = t >> BASEBITS
	}

	for k := NLEN; k < 2*NLEN-1; k++ {
		s -= d[k-NLEN]
		t = co + s
		for i := NLEN - 1; i >= 1+k/2; i-- {
			t += DChunk(a.w[i]-a.w[k-i]) * DChunk(b.w[k-i]-b.w[i])
		}
		c.w[k] = Chunk(t) & BMASK
		co = t >> BASEBITS
	}
	c.w[2*NLEN-1] = Chunk(co)

	return c
}

/* return a^2 as DBIG */
func sqr(a *BIG) *DBIG {
	c := NewDBIG()
	//	BIGSQRS+=1;
	t := DChunk(a.w[0]) * DChunk(a.w[0])
	c.w[0] = Chunk(t) & BMASK
	co := t >> BASEBITS

	for j := 1; j < NLEN-1; {
		t = DChunk(a.w[j]) * DChunk(a.w[0])
		for i := 1; i < (j+1)/2; i++ {
			t += DChunk(a.w[j-i]) * DChunk(a.w[i])
		}
		t += t
		t += co
		c.w[j] = Chunk(t) & BMASK
		co = t >> BASEBITS
		j++
		t = DChunk(a.w[j]) * DChunk(a.w[0])
		for i := 1; i < (j+1)/2; i++ {
			t += DChunk(a.w[j-i]) * DChunk(a.w[i])
		}
		t += t
		t += co
		t += DChunk(a.w[j/2]) * DChunk(a.w[j/2])
		c.w[j] = Chunk(t) & BMASK
		co = t >> BASEBITS
		j++
	}

	for j := NLEN - 1 + (NLEN % 2); j < DNLEN-3; {
		t = DChunk(a.w[NLEN-1]) * DChunk(a.w[j-NLEN+1])
		for i := j - NLEN + 2; i < (j+1)/2; i++ {
			t += DChunk(a.w[j-i]) * DChunk(a.w[i])
		}
		t += t
		t += co
		c.w[j] = Chunk(t) & BMASK
		co = t >> BASEBITS
		j++
		t = DChunk(a.w[NLEN-1]) * DChunk(a.w[j-NLEN+1])
		for i := j - NLEN + 2; i < (j+1)/2; i++ {
			t += DChunk(a.w[j-i]) * DChunk(a.w[i])
		}
		t += t
		t += co
		t += DChunk(a.w[j/2]) * DChunk(a.w[j/2])
		c.w[j] = Chunk(t) & BMASK
		co = t >> BASEBITS
		j++
	}

	t = DChunk(a.w[NLEN-2]) * DChunk(a.w[NLEN-1])
	t += t
	t += co
	c.w[DNLEN-3] = Chunk(t) & BMASK
	co = t >> BASEBITS

	t = DChunk(a.w[NLEN-1])*DChunk(a.w[NLEN-1]) + co
	c.w[DNLEN-2] = Chunk(t) & BMASK
	co = t >> BASEBITS
	c.w[DNLEN-1] = Chunk(co)

	return c
}

func monty(m *BIG, mc Chunk, d *DBIG) *BIG {
	var dd [NLEN]DChunk

	var v [NLEN]Chunk
	b := NewBIG()

	t := DChunk(d.w[0])
	v[0] = (Chunk(t) * mc) & BMASK
	t += DChunk(v[0]) * DChunk(m.w[0])
	c := (t >> BASEBITS) + DChunk(d.w[1])
	s := DChunk(0)

	for k := 1; k < NLEN; k++ {
		t = c + s + DChunk(v[0])*DChunk(m.w[k])
		for i := k - 1; i > k/2; i-- {
			t += DChunk(v[k-i]-v[i]) * DChunk(m.w[i]-m.w[k-i])
		}
		v[k] = (Chunk(t) * mc) & BMASK
		t += DChunk(v[k]) * DChunk(m.w[0])
		c = (t >> BASEBITS) + DChunk(d.w[k+1])
		dd[k] = DChunk(v[k]) * DChunk(m.w[k])
		s += dd[k]
	}
	for k := NLEN; k < 2*NLEN-1; k++ {
		t = c + s
		for i := NLEN - 1; i >= 1+k/2; i-- {
			t += DChunk(v[k-i]-v[i]) * DChunk(m.w[i]-m.w[k-i])
		}
		b.w[k-NLEN] = Chunk(t) & BMASK
		c = (t >> BASEBITS) + DChunk(d.w[k+1])
		s -= dd[k-NLEN+1]
	}
	b.w[NLEN-1] = Chunk(c) & BMASK
	return b
}

/* set this[i]+=x*y+c, and return high part */
func muladd(a Chunk, b Chunk, c Chunk, r Chunk) (Chunk, Chunk) {
	var prod = DChunk(a)*DChunk(b) + DChunk(c) + DChunk(r)
	bot := Chunk(prod) & BMASK
	top := Chunk(prod >> BASEBITS)
	return top, bot
}
