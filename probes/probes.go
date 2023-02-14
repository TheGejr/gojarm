package probes

import (
	"crypto/tls"

	"github.com/TheGejr/gojarm/ciphers"
	"github.com/TheGejr/gojarm/extension"
	"github.com/TheGejr/gojarm/models"
	"github.com/TheGejr/gojarm/utils"
)

// GetProbes returns the standard set of JARM probes in the correct order
func GetProbes(hostname string, port int) (jarmProbes []models.JarmOptions) {
	tls12Forward := models.JarmOptions{
		Hostname:       hostname,
		Port:           port,
		Version:        tls.VersionTLS12,
		Ciphers:        "ALL",
		CipherOrder:    "FORWARD",
		Grease:         "NO_GREASE",
		ALPN:           "ALPN",
		V13Mode:        "1.2_SUPPORT",
		ExtensionOrder: "REVERSE",
	}

	tls12Reverse := models.JarmOptions{
		Hostname:       hostname,
		Port:           port,
		Version:        tls.VersionTLS12,
		Ciphers:        "ALL",
		CipherOrder:    "REVERSE",
		Grease:         "NO_GREASE",
		ALPN:           "ALPN",
		V13Mode:        "1.2_SUPPORT",
		ExtensionOrder: "FORWARD",
	}

	tls12TopHalf := models.JarmOptions{
		Hostname:       hostname,
		Port:           port,
		Version:        tls.VersionTLS12,
		Ciphers:        "ALL",
		CipherOrder:    "TOP_HALF",
		Grease:         "NO_GREASE",
		ALPN:           "NO_SUPPORT",
		V13Mode:        "NO_SUPPORT",
		ExtensionOrder: "FORWARD",
	}

	tls12BottomHalf := models.JarmOptions{
		Hostname:       hostname,
		Port:           port,
		Version:        tls.VersionTLS12,
		Ciphers:        "ALL",
		CipherOrder:    "BOTTOM_HALF",
		Grease:         "NO_GREASE",
		ALPN:           "RARE_ALPN",
		V13Mode:        "NO_SUPPORT",
		ExtensionOrder: "FORWARD",
	}

	tls12MiddleOut := models.JarmOptions{
		Hostname:       hostname,
		Port:           port,
		Version:        tls.VersionTLS12,
		Ciphers:        "ALL",
		CipherOrder:    "MIDDLE_OUT",
		Grease:         "GREASE",
		ALPN:           "RARE_ALPN",
		V13Mode:        "NO_SUPPORT",
		ExtensionOrder: "REVERSE",
	}

	tls11Forward := models.JarmOptions{
		Hostname:       hostname,
		Port:           port,
		Version:        tls.VersionTLS11,
		Ciphers:        "ALL",
		CipherOrder:    "FORWARD",
		Grease:         "NO_GREASE",
		ALPN:           "ALPN",
		V13Mode:        "NO_SUPPORT",
		ExtensionOrder: "FORWARD",
	}

	tls13Forward := models.JarmOptions{
		Hostname:       hostname,
		Port:           port,
		Version:        tls.VersionTLS13,
		Ciphers:        "ALL",
		CipherOrder:    "FORWARD",
		Grease:         "NO_GREASE",
		ALPN:           "ALPN",
		V13Mode:        "1.3_SUPPORT",
		ExtensionOrder: "REVERSE",
	}

	tls13Reverse := models.JarmOptions{
		Hostname:       hostname,
		Port:           port,
		Version:        tls.VersionTLS13,
		Ciphers:        "ALL",
		CipherOrder:    "REVERSE",
		Grease:         "NO_GREASE",
		ALPN:           "ALPN",
		V13Mode:        "1.3_SUPPORT",
		ExtensionOrder: "FORWARD",
	}

	tls13Invalid := models.JarmOptions{
		Hostname:       hostname,
		Port:           port,
		Version:        tls.VersionTLS13,
		Ciphers:        "NO1.3",
		CipherOrder:    "FORWARD",
		Grease:         "NO_GREASE",
		ALPN:           "ALPN",
		V13Mode:        "1.3_SUPPORT",
		ExtensionOrder: "FORWARD",
	}

	tls13MiddleOut := models.JarmOptions{
		Hostname:       hostname,
		Port:           port,
		Version:        tls.VersionTLS13,
		Ciphers:        "ALL",
		CipherOrder:    "MIDDLE_OUT",
		Grease:         "GREASE",
		ALPN:           "ALPN",
		V13Mode:        "1.3_SUPPORT",
		ExtensionOrder: "REVERSE",
	}

	return []models.JarmOptions{
		tls12Forward,
		tls12Reverse,
		tls12TopHalf,
		tls12BottomHalf,
		tls12MiddleOut,
		tls11Forward,
		tls13Forward,
		tls13Reverse,
		tls13Invalid,
		tls13MiddleOut,
	}
}

func BuildProbe(options models.JarmOptions) (payload []byte) {
	payload = []byte{0x16}
	hello := []byte{}

	switch options.Version {
	case tls.VersionTLS13:
		payload = append(payload, 0x03, 0x01)
		hello = append(hello, 0x03, 0x03)
	case tls.VersionSSL30:
		payload = append(payload, 0x03, 0x00)
		hello = append(hello, 0x03, 0x00)
	case tls.VersionTLS10:
		payload = append(payload, 0x03, 0x01)
		hello = append(hello, 0x03, 0x01)
	case tls.VersionTLS11:
		payload = append(payload, 0x03, 0x02)
		hello = append(hello, 0x03, 0x02)
	case tls.VersionTLS12:
		payload = append(payload, 0x03, 0x03)
		hello = append(hello, 0x03, 0x03)
	}

	hello = append(hello, utils.RandomBytes(32)...)

	sessionID := utils.RandomBytes(32)
	hello = append(hello, byte(len(sessionID)))
	hello = append(hello, sessionID...)

	cipherChoice := ciphers.GetCiphers(options)
	hello = append(hello, utils.GetUint16Bytes(len(cipherChoice))...)
	hello = append(hello, cipherChoice...)

	hello = append(hello, 0x01)
	hello = append(hello, 0x00)
	hello = append(hello, extension.GetExtensions(options)...)

	innerLen := []byte{0x00}
	innerLen = append(innerLen, utils.GetUint16Bytes(len(hello))...)

	handshakeProtocol := []byte{0x01}
	handshakeProtocol = append(handshakeProtocol, innerLen...)
	handshakeProtocol = append(handshakeProtocol, hello...)

	outerLen := utils.GetUint16Bytes(len(handshakeProtocol))

	payload = append(payload, outerLen...)
	payload = append(payload, handshakeProtocol...)

	return payload
}
