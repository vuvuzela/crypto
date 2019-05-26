// Copyright 2015 The Vuvuzela Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package shuffle

import (
	"testing"

	"vuvuzela.io/crypto/rand"
)

func TestShuffle(t *testing.T) {
	n := 64
	x := make([][]byte, n)
	for i := 0; i < n; i++ {
		x[i] = []byte{byte(i)}
	}

	s := New(rand.Reader, len(x))
	s.Shuffle(x)

	allSame := true
	for i := 0; i < n; i++ {
		if x[i][0] != byte(i) {
			allSame = false
		}
	}

	if allSame {
		t.Errorf("shuffler isn't shuffling")
	}

	s.Unshuffle(x)

	for i := 0; i < n; i++ {
		if x[i][0] != byte(i) {
			t.Errorf("unshuffle does not undo shuffle")
			break
		}
	}
}

func TestMaxMultiple(t *testing.T) {
	for _, n := range []uint32{2, 3, 5, 10, 15, 1<<10} {
		m := maxMultiple(n)
		if m%n != 0 {
			t.Errorf("maxMultiple(%d) is not a multiple", n)
			continue
		}
		// note that m + n will wrap around if m is maximal; this relies on
		// uint32 modular arithmetic
		if m + n > m {
			t.Errorf("maxMultiple(%d) is not maximal", n)
			continue
		}
	}
}

func BenchmarkNew(b *testing.B) {
	for i := 0; i < b.N; i++ {
		New(rand.Reader, 50000)
	}
}
