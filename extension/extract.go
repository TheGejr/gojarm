package extension

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
)

// ExtractExtensionInfo returns parsed extension information from a server hello response
func ExtractExtensionInfo(data []byte, offset int, serverHelloLength int) string {
	if len(data) < 85 || len(data) < (offset+53) {
		return "|"
	}

	if data[offset+47] == 11 {
		return "|"
	}

	if offset+42 >= serverHelloLength {
		return "|"
	}

	if bytes.Equal(data[offset+50:offset+53], []byte{0x0e, 0xac, 0x0b}) ||
		bytes.Equal(data[82:85], []byte{0x0f, 0xf0, 0x0b}) {
		return "|"
	}

	ecnt := offset + 49
	elen := int(binary.BigEndian.Uint16(data[offset+47 : offset+49]))
	emax := elen + ecnt - 1

	etypes := [][]byte{}
	evals := [][]byte{}

	for ecnt < emax {
		if len(data) < ecnt+2 {
			break
		}

		if len(data) < ecnt+4 {
			break
		}
		etypes = append(etypes, data[ecnt:ecnt+2])

		extlen := int(binary.BigEndian.Uint16(data[ecnt+2 : ecnt+4]))
		if len(data) < ecnt+4+extlen {
			break
		}

		if extlen == 0 {
			evals = append(evals, []byte{})
		} else {
			evals = append(evals, data[ecnt+4:ecnt+4+extlen])
		}
		ecnt = ecnt + extlen + 4
	}

	alpn := string(ExtractExtensionType([]byte{0x00, 0x10}, etypes, evals))
	etypeList := []string{}
	for _, t := range etypes {
		etypeList = append(etypeList, hex.EncodeToString(t))
	}
	return alpn + "|" + strings.Join(etypeList, "-")
}

// ExtractExtensionType returns the stringified value of a given extension type
func ExtractExtensionType(ext []byte, etypes [][]byte, evals [][]byte) string {
	for i := 0; i < len(etypes); i++ {
		if !bytes.Equal(ext, etypes[i]) {
			continue
		}
		if i >= len(evals) {
			continue
		}
		eval := evals[i]
		if len(eval) < 4 {
			continue
		}
		if bytes.Equal(ext, []byte{0x00, 0x10}) {
			return string(eval[3:])
		}
		return string(hex.EncodeToString(eval))
	}
	return ""
}
