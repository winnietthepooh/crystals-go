package kyber

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestKEMSuite(t *testing.T) {
	testKeyGenKEMRep(t, NewKyber512())
	testKeyGenKEMRep(t, NewKyber768())
	testKeyGenKEMRep(t, NewKyber1024())

	testDecaps(t, NewKyber512())
	testDecaps(t, NewKyber768())
	testDecaps(t, NewKyber1024())

	testBadSize(t, NewKyber512())
	testBadSize(t, NewKyber768())
	testBadSize(t, NewKyber1024())
}

func testKeyGenKEMRep(t *testing.T, k *Kyber) {
	seed := make([]byte, 64)
	rand.Read(seed)
	pk, sk, err := k.KeyGen(seed)
	if err != nil {
		t.Fatal("Seed in keygen failed")
	}
	pk2, sk2, err := k.KeyGen(seed)
	if !bytes.Equal(pk[:], pk2[:]) || !bytes.Equal(sk[:], sk2[:]) {
		t.Fatalf("Seed in keygen failed")
	}
	var r [32]byte
	rand.Read(r[:])
	c, ss, err := k.Encaps(pk, r[:])
	c2, ss2, err := k.Encaps(pk, r[:])
	if !bytes.Equal(c2, c) || !bytes.Equal(ss, ss2) {
		t.Fatalf("Seed in keygen failed")
	}
}

func testDecaps(t *testing.T, k *Kyber) {
	pk, sk, err := k.KeyGen(nil)
	if err != nil {
		t.Fatal("Failed to decaps")
	}
	var r [32]byte
	rand.Read(r[:])
	c, ss, err := k.Encaps(pk, r[:])
	ss2, err := k.Decaps(sk, c)
	if !bytes.Equal(ss[:], ss2[:]) {
		fmt.Printf("k %+v vs k2 %+v\n", ss, ss2)
		t.Fatal("Failed to decaps")
	}
}

func testBadSize(t *testing.T, k *Kyber) {
	c, _, err := k.Encaps(nil, nil)
	if err != nil {
		t.Fatal("Encaps should nto work with empty key.")
	}
	if c != nil {
		t.Fatal("Encaps should not work with empty key.")
	}
	ss, err := k.Decaps(nil, nil)
	if ss != nil {
		t.Fatal("Decaps should not work with empty inputs.")
	}
}
