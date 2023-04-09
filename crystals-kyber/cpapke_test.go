package kyber

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestPKESuite(t *testing.T) {
	testKeyGenRep(t, NewKyber512())
	testKeyGenRep(t, NewKyber768())
	testKeyGenRep(t, NewKyber1024())

	testEncryptRep(t, NewKyber512())
	testEncryptRep(t, NewKyber768())
	testEncryptRep(t, NewKyber1024())

	testDecrypt(t, NewKyber512())
	testDecrypt(t, NewKyber768())
	testDecrypt(t, NewKyber1024())

	testPack(t, NewKyber512())
	testPack(t, NewKyber768())
	testPack(t, NewKyber1024())

	testBadSizePKE(t, NewKyber512())
	testBadSizePKE(t, NewKyber768())
	testBadSizePKE(t, NewKyber1024())
}

func testKeyGenRep(t *testing.T, k *Kyber) {
	seed := make([]byte, 32)
	seed[0] = 34
	pk, sk := k.PKEKeyGen(seed)
	pk2, sk2 := k.PKEKeyGen(seed)
	if !bytes.Equal(pk[:], pk2[:]) || !bytes.Equal(sk[:], sk2[:]) {
		t.Fatalf("Seed in keygen failed")
	}
	var r, msg [32]byte
	rand.Read(r[:])
	rand.Read(msg[:])
	c, err := k.Encrypt(pk, msg[:], r[:])
	if err != nil {
		t.Fatal("Seed in keygen failed")
	}
	c2, err := k.Encrypt(pk, msg[:], r[:])
	if err != nil {
		t.Fatal("Seed in keygen failed")
	}
	if !bytes.Equal(c, c2) {
		t.Fatalf("Seed in keygen failed")
	}
}

func testEncryptRep(t *testing.T, k *Kyber) {
	pk, _ := k.PKEKeyGen(nil)
	var r, msg [32]byte
	rand.Read(r[:])
	rand.Read(msg[:])
	c, err := k.Encrypt(pk, msg[:], r[:])
	if err != nil {
		t.Fatal("Coins failed")
	}
	c2, err := k.Encrypt(pk, msg[:], r[:])
	if err != nil {
		t.Fatal("Coins failed")
	}
	if !bytes.Equal(c, c2) {
		t.Fatalf("Coins failed")
	}
	c3, err := k.Encrypt(pk, msg[:], nil)
	if bytes.Equal(c, c3) {
		t.Fatalf("Coins failed")
	}
}

func testDecrypt(t *testing.T, k *Kyber) {
	pk, sk := k.PKEKeyGen(nil)
	var r, msg [32]byte
	rand.Read(r[:])
	rand.Read(msg[:])
	c, err := k.Encrypt(pk, msg[:], r[:])
	if err != nil {
		t.Fatal("Failed to decrypt")
	}
	msgRecov, err := k.Decrypt(sk, c)
	if err != nil {
		t.Fatal("Failed to decrypt")
	}
	if !bytes.Equal(msg[:], msgRecov[:]) {
		t.Fatal("Failed to decrypt")
	}
}

func testPack(t *testing.T, k *Kyber) {
	pk, sk := k.PKEKeyGen(nil)
	pkUnpacked, err := k.UnpackPK(pk)
	if err != nil {
		t.Fatal("Unpack failed")
	}
	skUnpacked, err := k.UnpackSK(sk)
	if err != nil {
		t.Fatal("SK Unpack failed")
	}
	pk2 := k.PackPK(pkUnpacked)
	sk2 := k.PackSK(skUnpacked)
	if !bytes.Equal(pk[:], pk2[:]) {
		t.Fatal("Pack failed")
	}
	if !bytes.Equal(sk[:], sk2[:]) {
		t.Fatal("SK Pack failed")
	}
}

func testBadSizePKE(t *testing.T, k *Kyber) {
	msg := make([]byte, 50)
	c, err := k.Encrypt(nil, msg, nil)
	if c != nil || err != nil {
		t.Fatal("Encrypt should not work with empty key.")
	}

	c, err = k.Encrypt(nil, []byte("Short message"), nil)

	if c != nil || err != nil {
		t.Fatal("Encrypt should not work with empty inputs.")
	}

	ss, err := k.Decrypt(nil, nil)
	if ss != nil || err != nil {
		t.Fatal("Decrypt should not work with short message.")
	}
}
