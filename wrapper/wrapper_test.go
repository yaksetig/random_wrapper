package wrapper

import (
	"bytes"
	"testing"
)
import "github.com/cloudflare/circl/sign/ed25519"

// TestSign checks if the Sign function is deterministic
func TestSign(t *testing.T) {
	// Hardcode seed
	seed := []byte("5d9a2cc153d749daa240a2ebfcac2581")

	// Generate Ed25519 secret key from a seed
	sk := ed25519.NewKeyFromSeed(seed)

	// message to be signed
	msg := []byte("Princess Peach")

	// produce two signatures on same message using same key
	s1 := Sign(sk, msg)
	s2 := Sign(sk, msg)

	if bytes.Compare(s1, s2) != 0 {
		t.Errorf("Sign(): Function produced two different signatures for one same message under same secret key")
	}
}

func TestG(t *testing.T) {

	x, errX := G(32)
	y, errY := G(32)

	if errX != nil || errY != nil {
		t.Errorf("G(): Random number generation failed ")
	}

	if len(x) != 32 || len(y) != 32 {
		t.Errorf("G(): The obtained length of the random numbers is invalid")
	}

	if bytes.Compare(x, y) == 0 {
		t.Errorf("G(): CSPRNG is poor since it generated two equal numbers")
	}
}

// TestPRF checks if the PRF is outputting
func TestPRF(t *testing.T) {
	n := 8

	k := []byte("PRF Key")
	c := []byte("Message")

	output, err := PRF(k, c, n)

	if len(output) != n {
		t.Errorf("PRF(): Output is not variable")
	}

	if err != nil{
		t.Errorf("PRF(): Something went wrong with the PRF function")
	}
}

// TestPRF2 checks if the entropy levels are acceptable
func TestPRF2(t *testing.T) {
	n := 32

	k := []byte("PRF Key")
	c := []byte("Message")

	_, err := PRF(k, c, n)


	if err == nil{
		t.Errorf("PRF(): Function should have failed because of poor entropy")
	}
}

func TestKDF(t *testing.T) {

	x := []byte("Super Mario")
	y := []byte("Princess Peach")

	key, err := KDF(x, y)

	if err != nil{
		t.Errorf("KDF(): Error ocurred during the key derivation")
	}
	if len(key) != len(y){
		t.Errorf("KDF(): The key derivation produced a key of different size than the one expected")
	}
}
