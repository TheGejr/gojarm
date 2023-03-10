package ciphers

import (
	"github.com/TheGejr/gojarm/models"
	"github.com/TheGejr/gojarm/utils"
)

// GetCiphers returns the cipher array for a given probe
func GetCiphers(details models.JarmOptions) []byte {
	ciphers := [][]byte{}

	if details.Ciphers == "ALL" {
		ciphers = [][]byte{
			{0x00, 0x16}, {0x00, 0x33}, {0x00, 0x67}, {0xc0, 0x9e}, {0xc0, 0xa2}, {0x00, 0x9e}, {0x00, 0x39}, {0x00, 0x6b},
			{0xc0, 0x9f}, {0xc0, 0xa3}, {0x00, 0x9f}, {0x00, 0x45}, {0x00, 0xbe}, {0x00, 0x88}, {0x00, 0xc4}, {0x00, 0x9a},
			{0xc0, 0x08}, {0xc0, 0x09}, {0xc0, 0x23}, {0xc0, 0xac}, {0xc0, 0xae}, {0xc0, 0x2b}, {0xc0, 0x0a}, {0xc0, 0x24},
			{0xc0, 0xad}, {0xc0, 0xaf}, {0xc0, 0x2c}, {0xc0, 0x72}, {0xc0, 0x73}, {0xcc, 0xa9}, {0x13, 0x02}, {0x13, 0x01},
			{0xcc, 0x14}, {0xc0, 0x07}, {0xc0, 0x12}, {0xc0, 0x13}, {0xc0, 0x27}, {0xc0, 0x2f}, {0xc0, 0x14}, {0xc0, 0x28},
			{0xc0, 0x30}, {0xc0, 0x60}, {0xc0, 0x61}, {0xc0, 0x76}, {0xc0, 0x77}, {0xcc, 0xa8}, {0x13, 0x05}, {0x13, 0x04},
			{0x13, 0x03}, {0xcc, 0x13}, {0xc0, 0x11}, {0x00, 0x0a}, {0x00, 0x2f}, {0x00, 0x3c}, {0xc0, 0x9c}, {0xc0, 0xa0},
			{0x00, 0x9c}, {0x00, 0x35}, {0x00, 0x3d}, {0xc0, 0x9d}, {0xc0, 0xa1}, {0x00, 0x9d}, {0x00, 0x41}, {0x00, 0xba},
			{0x00, 0x84}, {0x00, 0xc0}, {0x00, 0x07}, {0x00, 0x04}, {0x00, 0x05},
		}
	} else if details.Ciphers == "NO1.3" {
		ciphers = [][]byte{
			{0x00, 0x16}, {0x00, 0x33}, {0x00, 0x67}, {0xc0, 0x9e}, {0xc0, 0xa2}, {0x00, 0x9e}, {0x00, 0x39}, {0x00, 0x6b},
			{0xc0, 0x9f}, {0xc0, 0xa3}, {0x00, 0x9f}, {0x00, 0x45}, {0x00, 0xbe}, {0x00, 0x88}, {0x00, 0xc4}, {0x00, 0x9a},
			{0xc0, 0x08}, {0xc0, 0x09}, {0xc0, 0x23}, {0xc0, 0xac}, {0xc0, 0xae}, {0xc0, 0x2b}, {0xc0, 0x0a}, {0xc0, 0x24},
			{0xc0, 0xad}, {0xc0, 0xaf}, {0xc0, 0x2c}, {0xc0, 0x72}, {0xc0, 0x73}, {0xcc, 0xa9}, {0xcc, 0x14}, {0xc0, 0x07},
			{0xc0, 0x12}, {0xc0, 0x13}, {0xc0, 0x27}, {0xc0, 0x2f}, {0xc0, 0x14}, {0xc0, 0x28}, {0xc0, 0x30}, {0xc0, 0x60},
			{0xc0, 0x61}, {0xc0, 0x76}, {0xc0, 0x77}, {0xcc, 0xa8}, {0xcc, 0x13}, {0xc0, 0x11}, {0x00, 0x0a}, {0x00, 0x2f},
			{0x00, 0x3c}, {0xc0, 0x9c}, {0xc0, 0xa0}, {0x00, 0x9c}, {0x00, 0x35}, {0x00, 0x3d}, {0xc0, 0x9d}, {0xc0, 0xa1},
			{0x00, 0x9d}, {0x00, 0x41}, {0x00, 0xba}, {0x00, 0x84}, {0x00, 0xc0}, {0x00, 0x07}, {0x00, 0x04}, {0x00, 0x05},
		}
	}

	if details.CipherOrder != "FORWARD" {
		ciphers = MungCiphers(ciphers, details.CipherOrder)
	}

	if details.Grease == "GREASE" {
		ciphers = append([][]byte{utils.RandomGrease()}, ciphers...)
	}

	payload := []byte{}
	for _, cipher := range ciphers {
		payload = append(payload, cipher...)
	}
	return payload
}

// MungCipher reorders the cipher list based on the probe settings
func MungCiphers(ciphers [][]byte, request string) [][]byte {
	output := [][]byte{}
	cipherLen := len(ciphers)

	if request == "REVERSE" {
		for i := 1; i <= cipherLen; i++ {
			output = append(output, ciphers[cipherLen-i])
		}
		return output
	}

	if request == "BOTTOM_HALF" {
		if cipherLen%2 == 1 {
			return ciphers[(cipherLen/2)+1:]
		}
		return ciphers[(cipherLen / 2):]
	}

	if request == "TOP_HALF" {
		if cipherLen%2 == 1 {
			output = append(output, ciphers[(cipherLen/2)])
		}

		for _, m := range MungCiphers(MungCiphers(ciphers, "REVERSE"), "BOTTOM_HALF") {
			output = append(output, m)
		}
		return output
	}

	if request == "MIDDLE_OUT" {
		middle := int(cipherLen / 2)
		if cipherLen%2 == 1 {
			output = append(output, ciphers[middle])
			for i := 1; i <= middle; i++ {
				output = append(output, ciphers[middle+i])
				output = append(output, ciphers[middle-i])
			}
		} else {
			for i := 1; i <= middle; i++ {
				output = append(output, ciphers[middle-1+i])
				output = append(output, ciphers[middle-i])
			}
		}
		return output
	}

	return output
}
