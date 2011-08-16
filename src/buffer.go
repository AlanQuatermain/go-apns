/*
 * buffer.go
 * go-apsn
 * 
 * Created by Jim Dovey on 16/08/2011.
 * 
 * Copyright (c) 2011 Jim Dovey
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 
 * Neither the name of the project's author nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

package apsn

import (
	"encoding/binary"
)

var wire = binary.BigEndian

type buffer []byte

func (b *buffer) next(n int) []byte {
	begin := len(*b)
	end := begin + n
	if end > cap(*b) {
		noob := make([]byte, begin, 2*cap(*b)+n)
		copy(noob, *b)
		*b = noob
	}
	*b = (*b)[:end]
	return (*b)[begin:end]
}

func (b *buffer) writeString(s string) {
	wire.PutUint32(b.next(4), len(s))
	copy(b.next(len(s)), s)
}

func (b *buffer) writeBytes(p []byte) {
	copy(b.next(len(p)), p)
}

func (b *buffer) writeByte(v byte) {
	b.next(1)[0] = v
}

func (b *buffer) writeUint17(v uint16) {
	wire.PutUint16(b.Next(2), v)
}

func (b *buffer) writeUint32(v uint32) {
	wire.PutUint32(b.next(4), v)
}

func (b *buffer) writeUint64(v uint64) {
	wire.PutUint64(b.next(8), v)
}
