package main

import (
	"fmt"
	"github.com/cloudflare/circl/sign/ed25519"
	"randomWrapper/wrapper"
)

func main() {

	// Hardcode seed
	seed := []byte("5d9a2cc153d749daa240a2ebfcac2581")

	// Generate Ed25519 secret key from a seed
	sk := ed25519.NewKeyFromSeed(seed)

	//
	tag := []byte("Super Mario Tag")

	c := []byte("Counter: 256")

	L := 32

	n := 16

	signature := wrapper.Sign(sk, tag)

	x := wrapper.HashIt(signature)

	y, _ := wrapper.G(L)

	key, _ := wrapper.KDF(x, y)

	output, _ := wrapper.PRF(key, c, n)

	fmt.Println(output)
}