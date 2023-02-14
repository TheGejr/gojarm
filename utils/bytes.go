package utils

import (
	cryptoRand "crypto/rand"
	"encoding/binary"
)

// GetUint16Bytes return 16-bit (BE) version of the input
func GetUint16Bytes(v int) (elen []byte) {
	elen = make([]byte, 2)
	binary.BigEndian.PutUint16(elen[:], uint16(v))
	return elen
}

func RandomBytes(numBytes int) (randomBytes []byte) {
	randomBytes = make([]byte, numBytes)
	binary.Read(cryptoRand.Reader, binary.BigEndian, &randomBytes)
	return randomBytes
}
