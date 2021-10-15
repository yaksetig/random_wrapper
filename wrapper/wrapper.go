package wrapper

import (
	"crypto/rand"
	"errors"
	"github.com/cloudflare/circl/sign/ed25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
	"io"
)

// Sign receives an ED25519 secret key and a message
// returns a *deterministic* signature in []byte format
func Sign(sk []byte, msg []byte) []byte{
	return ed25519.Sign(sk, msg)
}

// HashIt receives a data slice
// returns a SHA3 digest of 224 bits
func HashIt(data []byte) []byte{
	h := sha3.New224()
	h.Write(data)

	return h.Sum(nil)
}

// G receives the desired bytes of randomness 'L'
// returns cryptographically-secure generated 'L' random bytes.
func G(L int) ([]byte, error) {

	b := make([]byte, L)
	_, err := rand.Read(b)

	// err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

// KDF receives a key 'x' and a salt value 'y'
// returns a variable-sized key output
func KDF(x, y []byte) ([]byte, error){

	// The output of the KDF has to be equal to the desired 'L' random bytes from the user
	L := len(y)

	hkdf := hkdf.New(sha3.New256, x, y, nil)

	key := make([]byte, L)

	if _, err := io.ReadFull(hkdf, key); err != nil {
		panic(err)
	}

	return key, nil
}

// PRF receives a key, a tag 'c', and an output size 'n'
// returns a flexible-size hash digest or an error if it fails
func PRF(k []byte, c []byte, n int) ([]byte, error){

	L := len(k)
	M := len(c)

	// checks if entropy is enough by checking if L >= n-M
	if L < (n-M) {
		return nil, errors.New("L is not greater or equal than (n-M)")
	}

	//
	out := make([]byte, n)

	// variable output hash
	h := sha3.NewShake256()
	h.Write(k)
	h.Write(c)
	_, err := h.Read(out)

	// check if hash produced digest without any errors
	if err != nil{
		return nil, err
	}

	return out, nil
}
