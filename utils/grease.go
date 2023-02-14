package utils

import "math/rand"

// RandomGrease returns a randomly chosen "grease" value
func RandomGrease() (grease []byte) {
	rnd := byte(rand.Int31() % 16)
	return []byte{0x0a + (rnd << 4), 0x0a + (rnd << 4)}
}
