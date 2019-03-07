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

// maxMultiple returns the highest multiple of n that fits in a uint32
func maxMultiple(n uint32) uint32 {
	uint32Max := ^uint32(0)
	return uint32Max - (uint32Max % n)
}

// intn returns a random number uniformly distributed between 0 and n (not
// including n).
//
// rand should be a source of random bytes
//
// buf should be a temporary buffer with length at least 4
func intn(rand *bufio.Reader, n uint32, buf []byte) int {
	// intn does not simply take a random uint32 mod n because this is biased.
	// Consider n=3 and a random uint32 u. (2^32-2)%3 == 2, so for u from 0 to
	// 2^32-2, u%3 evenly rotates among 0, 1, and 2. However, (2^32-1)%3 == 0,
	// so there is a slight bias in favor of u%3 == 0 in the case where u ==
	// 2^32-1.
	//
	// To solve this problem, intn rejection-samples a number x between 0 and a
  // multiple of n (not including the upper bound), then takes x%n, which is
  // truly uniform.

	m := maxMultiple(n)
	for {
		if _, err := rand.Read(buf); err != nil {
			panic(err)
		}
		// Get a uniform random number in [0, 2^32)
		x := binary.BigEndian.Uint32(buf)
		if x < m {
			// Accept only random numbers in [0, m). Because m is a multiple of
			// n, x % n is uniformly distributed in [0, n).
			return int(x % n)
		}
	}
}
