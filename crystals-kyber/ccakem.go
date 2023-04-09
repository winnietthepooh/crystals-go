package kyber

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"

	"golang.org/x/crypto/sha3"
)

// KeyGen creates a public and private key pair.
// A 64 byte long seed can be given as argument. If a nil seed is given, the seed is generated using Go crypto's random number generator.
// The keys returned are packed into byte arrays.
func (k *Kyber) KeyGen(seed []byte) ([]byte, []byte, error) {
	if seed == nil || len(seed) != SIZEZ+SEEDBYTES {
		seed = make([]byte, SIZEZ+SEEDBYTES)
		_, err := rand.Read(seed)
		if err != nil {
			return nil, nil, err
		}
	}
	pk, skP := k.PKEKeyGen(seed[:SEEDBYTES])

	return pk, k.PackSK(&PrivateKey{SkP: skP, Pk: pk, Z: seed[SEEDBYTES:]}), nil
}

// Encaps generates a shared secret and the encryption of said shared secret using a given public key.
// A 32 byte long seed can be given as argument (coins). If a nil seed is given, the seed is generated using Go crypto's random number generator.
// The shared secret and ciphertext returned are packed into byte arrays.
// If an error occurs during the encaps process, nil arrays are returned.
func (k *Kyber) Encaps(packedPK, coins []byte) ([]byte, []byte, error) {
	if len(packedPK) != k.SIZEPK() {
		return nil, nil, errors.New("public key does not have the correct size")
	}
	if coins == nil || len(coins) != SEEDBYTES {
		coins = make([]byte, SEEDBYTES)
		_, err := rand.Read(coins[:])
		if err != nil {
			return nil, nil, err
		}
	}
	var m, ss [32]byte
	hState := sha3.New256()
	hState.Write(coins[:])
	copy(m[:], hState.Sum(nil))

	hpk := make([]byte, 32)
	hState.Reset()
	hState.Write(packedPK[:])
	copy(hpk[:], hState.Sum(nil))

	var kr, kc [64]byte
	gState := sha3.New512()
	gState.Write(m[:])
	gState.Write(hpk[:])
	copy(kr[:], gState.Sum(nil))
	copy(kc[:32], kr[:32])

	c, err := k.Encrypt(packedPK, m[:], kr[32:])
	if err != nil {
		return nil, nil, err
	}

	hState.Reset()
	hState.Write(c[:])
	copy(kc[32:], hState.Sum(nil))

	kdfState := sha3.NewShake256()
	_, err = kdfState.Write(kc[:])
	if err != nil {
		return nil, nil, err
	}
	_, err = kdfState.Read(ss[:])
	if err != nil {
		return nil, nil, err
	}
	return c[:], ss[:], nil
}

// Decaps decrypts a ciphertext given a secret key and checks its validity.
// The secret key and ciphertext must be give as packed byte array.
// The recovered shared secret is returned as byte array.
// If an error occurs during the decapsulation process, a nil shared secret is returned.
func (k *Kyber) Decaps(packedSK, c []byte) ([]byte, error) {
	if len(c) != k.SIZEC() || len(packedSK) != k.SIZESK() {
		return nil, errors.New("cannot decapulate, inputs do not have the correct size")
	}

	sk, err := k.UnpackSK(packedSK)
	if err != nil {
		return nil, err
	}
	m, err := k.Decrypt(sk.SkP, c)
	if err != nil {
		return nil, err
	}

	hpk := make([]byte, 32)
	hState := sha3.New256()
	hState.Write(sk.Pk[:])
	copy(hpk[:], hState.Sum(nil))

	var kr, kc [64]byte
	gState := sha3.New512()
	gState.Write(m[:])
	gState.Write(hpk[:])
	copy(kr[:], gState.Sum(nil))
	copy(kc[:], kr[:32])

	c2, err := k.Encrypt(sk.Pk, m, kr[32:])
	if err != nil {
		return nil, err
	}
	hState.Reset()
	hState.Write(c2[:])
	copy(kc[32:], hState.Sum(nil))

	subtle.ConstantTimeCopy(1-subtle.ConstantTimeCompare(c, c2), kc[:32], sk.Z[:])

	var ss [32]byte
	kdfState := sha3.NewShake256()
	_, err = kdfState.Write(kc[:])
	if err != nil {
		return nil, err
	}
	_, err = kdfState.Read(ss[:])
	if err != nil {
		return nil, err
	}

	return ss[:], nil
}
