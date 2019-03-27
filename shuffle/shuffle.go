// Copyright 2015 The Vuvuzela Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package shuffle implements cryptographic shuffling.
package shuffle // import "vuvuzela.io/crypto/shuffle"

import (
	"bufio"
	"encoding/binary"
	"io"
)

type Shuffler []int

func New(rand io.Reader, n int) Shuffler {
	p := make(Shuffler, n)
	buf := make([]byte, 4)
	rr := bufio.NewReader(rand)
	for i := range p {
		p[i] = intn(rr, uint32(i+1), buf)
	}
	return p
}

func (s Shuffler) Shuffle(x [][]byte) {
	for i := range x {
		j := s[i]
		x[i], x[j] = x[j], x[i]
	}
}

func (s Shuffler) Unshuffle(x [][]byte) {
	for i := len(x) - 1; i >= 0; i-- {
		j := s[i]
		x[i], x[j] = x[j], x[i]
	}
}

func (s Shuffler) ShuffleInts(x []int) {
	for i := range x {
		j := s[i]
		x[i], x[j] = x[j], x[i]
	}
}

func (s Shuffler) UnshuffleInts(x []int) {
	for i := len(x) - 1; i >= 0; i-- {
		j := s[i]
		x[i], x[j] = x[j], x[i]
	}
}

func intn(rand *bufio.Reader, n uint32, buf []byte) int {
	max := ^uint32(0)
	m := max - (max % n)
	for {
		if _, err := rand.Read(buf); err != nil {
			panic(err)
		}
		x := binary.BigEndian.Uint32(buf)
		if x < m {
			return int(x % n)
		}
	}
}
