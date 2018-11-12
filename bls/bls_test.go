// Copyright 2016 The Alpenhorn Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bls

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/sha3"
)

func TestSignVerify(t *testing.T) {
	for i := 0; i < 100; i++ {
		msg := randomMessage()
		pub, priv, err := GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("error generating key: %s", err)
		}

		sig := Sign(priv, msg)
		ok := Verify([]*PublicKey{pub}, [][]byte{msg}, sig)
		if !ok {
			t.Fatalf("expected signature to verify: msg=%q pub=%s priv=%s sig=%#v", msg, pub.gx, priv.x, sig)
		}

		compressedSig := sig.Compress()
		ok = VerifyCompressed([]*PublicKey{pub}, [][]byte{msg}, compressedSig)
		if !ok {
			t.Fatalf("expected compressed signature to verify: msg=%q pub=%s priv=%s sig=%#v", msg, pub.gx, priv.x, sig)
		}

		msg[0] = ^msg[0]
		ok = Verify([]*PublicKey{pub}, [][]byte{msg}, sig)
		if ok {
			t.Fatalf("expected signature to not verify")
		}
	}
}

func TestAggregate(t *testing.T) {
	for i := 0; i < 100; i++ {
		msg1 := randomMessage()
		msg2 := randomMessage()
		msg3 := randomMessage()

		pub1, priv1, _ := GenerateKey(rand.Reader)
		pub2, priv2, _ := GenerateKey(rand.Reader)
		pub3, priv3, _ := GenerateKey(rand.Reader)

		sig1 := Sign(priv1, msg1)
		sig2 := Sign(priv2, msg2)
		sig3 := Sign(priv3, msg3)

		sig := Aggregate(sig1, sig2, sig3)

		ok := Verify([]*PublicKey{pub1, pub2, pub3}, [][]byte{msg1, msg2, msg3}, sig)
		if !ok {
			t.Fatalf("failed to verify aggregate signature")
		}

		shortSig := sig.Compress()
		ok = VerifyCompressed([]*PublicKey{pub1, pub2, pub3}, [][]byte{msg1, msg2, msg3}, shortSig)
		if !ok {
			t.Fatalf("failed to verify compressed aggregate signature")
		}

		sigPartial := Aggregate(sig1, sig2)
		ok = Verify([]*PublicKey{pub1, pub2, pub3}, [][]byte{msg1, msg2, msg3}, sigPartial)
		if ok {
			t.Fatalf("did not expect partial signature to verify")
		}
	}
}

func randomMessage() []byte {
	msg := make([]byte, 32)
	rand.Read(msg)
	return msg
}

func TestKnownAnswer(t *testing.T) {
	msg := []byte("test message")
	// We use sha3 instead of a zeroReader because GenerateKey
	// loops forever with a zeroReader.
	_, priv, err := GenerateKey(sha3.NewShake128())
	if err != nil {
		t.Fatalf("error generating key: %s", err)
	}

	actual := Sign(priv, msg)
	expected, _ := decodeText([]byte("cAdm38gylnKd5Tq43SscV0K2ShgZ-f3-Acc-1WTV84U4QTwqCcrV47vxVl27yq2v5VGrxNJTB97V1CuQnprH1w"))
	if !bytes.Equal(actual, expected) {
		t.Fatalf("got %s, want %s", actual, expected)
	}
}

func generateTestcases(n int) (msgs [][]byte, pubs []*PublicKey, prvs []*PrivateKey, sigs []Signature) {
	msgs = make([][]byte, 0, n)
	pubs = make([]*PublicKey, 0, n)
	prvs = make([]*PrivateKey, 0, n)
	sigs = make([]Signature, 0, n)
	for i := 0; i < n; i++ {
		msg := randomMessage()
		msgs = append(msgs, msg)
		pub, prv, err := GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		pubs = append(pubs, pub)
		prvs = append(prvs, prv)

		sig := Sign(prv, msg)
		sigs = append(sigs, sig)
	}
	return
}

func BenchmarkVerifyAggregateSig(b *testing.B) {
	msgs, pubs, _, sigs := generateTestcases(100)
	b.Run("AggregateSignature", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Aggregate(sigs...)
		}
	})
	sig := Aggregate(sigs...)
	b.Run("VerifyAggregateSignature", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Verify(pubs, msgs, sig)
		}
	})
}

func BenchmarkVerifySig(b *testing.B) {
	n := 100
	msgs, pubs, _, sigs := generateTestcases(n)
	pk := make([][]*PublicKey, n)
	msg := make([][][]byte, n)
	for i := 0; i < n; i++ {
		pk[i] = []*PublicKey{pubs[i]}
		msg[i] = [][]byte{msgs[i]}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < n; j++ {
			Verify(pk[j], msg[j], sigs[j])
		}
	}
	b.StopTimer()
}
