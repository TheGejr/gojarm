package extension

import (
	"crypto/tls"

	"github.com/TheGejr/gojarm/ciphers"
	"github.com/TheGejr/gojarm/models"
	"github.com/TheGejr/gojarm/utils"
)

// GetExtensions returns the encoded extensions for a given probe
func GetExtensions(details models.JarmOptions) []byte {
	allExtensions := []byte{}
	grease := false

	if details.Grease == "GREASE" {
		allExtensions = append(allExtensions, utils.RandomGrease()...)
		allExtensions = append(allExtensions, 0x00, 0x00)
		grease = true
	}

	allExtensions = append(allExtensions, ExtGetServerName(details.Hostname)...)
	allExtensions = append(allExtensions, 0x00, 0x17, 0x00, 0x00)
	allExtensions = append(allExtensions, 0x00, 0x01, 0x00, 0x01, 0x01)
	allExtensions = append(allExtensions, 0xff, 0x01, 0x00, 0x01, 0x00)
	allExtensions = append(allExtensions, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19)
	allExtensions = append(allExtensions, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00)
	allExtensions = append(allExtensions, 0x00, 0x23, 0x00, 0x00)
	allExtensions = append(allExtensions, ExtGetALPN(details)...)
	allExtensions = append(allExtensions, 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01)
	allExtensions = append(allExtensions, ExtGetKeyShare(grease)...)
	allExtensions = append(allExtensions, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01)

	if details.Version == tls.VersionTLS13 || details.V13Mode == "1.2_SUPPORT" {
		allExtensions = append(allExtensions, ExtGetSupportedVersions(details, grease)...)
	}

	extensions := utils.GetUint16Bytes(len(allExtensions))
	extensions = append(extensions, allExtensions...)
	return extensions
}

// ExtGetServerName returns an encoded server name extension
func ExtGetServerName(name string) []byte {
	esni := []byte{0x00, 0x00}
	esni = append(esni, utils.GetUint16Bytes(len(name)+5)...)
	esni = append(esni, utils.GetUint16Bytes(len(name)+3)...)
	esni = append(esni, 0x00)
	esni = append(esni, utils.GetUint16Bytes(len(name))...)
	esni = append(esni, []byte(name)...)
	return esni
}

// ExtGetALPN returns an encoded ALPN extension
func ExtGetALPN(details models.JarmOptions) []byte {
	ext := []byte{0x00, 0x10}
	alpns := [][]byte{}

	if details.ALPN == "RARE_ALPN" {
		// All ALPN except H2 and HTTP/1.1
		alpns = [][]byte{
			{0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x30, 0x2e, 0x39},
			{0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x30},
			{0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x31},
			{0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x32},
			{0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x33},
			{0x03, 0x68, 0x32, 0x63},
			{0x02, 0x68, 0x71},
		}
	} else {
		// All APLN from weakest to strongest
		alpns = [][]byte{
			{0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x30, 0x2e, 0x39},
			{0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x30},
			{0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31},
			{0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x31},
			{0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x32},
			{0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x33},
			{0x02, 0x68, 0x32},
			{0x03, 0x68, 0x32, 0x63},
			{0x02, 0x68, 0x71},
		}
	}
	if details.ExtensionOrder != "FORWARD" {
		alpns = ciphers.MungCiphers(alpns, details.ExtensionOrder)
	}

	allALPNs := []byte{}
	for _, a := range alpns {
		allALPNs = append(allALPNs, a...)
	}

	ext = append(ext, utils.GetUint16Bytes(len(allALPNs)+2)...)
	ext = append(ext, utils.GetUint16Bytes(len(allALPNs))...)
	ext = append(ext, allALPNs...)
	return ext
}

// ExtGetKeyShare returns an encoded KeyShare extension
func ExtGetKeyShare(grease bool) []byte {
	ext := []byte{0x00, 0x33}
	shareExt := []byte{}
	if grease {
		shareExt = utils.RandomGrease()
		shareExt = append(shareExt, 0x00, 0x01, 0x00)
	}

	shareExt = append(shareExt, 0x00, 0x1d)
	shareExt = append(shareExt, 0x00, 0x20)
	shareExt = append(shareExt, utils.RandomBytes(32)...)
	secondLength := len(shareExt)
	firstLength := secondLength + 2
	ext = append(ext, utils.GetUint16Bytes(firstLength)...)
	ext = append(ext, utils.GetUint16Bytes(secondLength)...)
	ext = append(ext, shareExt...)
	return ext
}

// ExtGetSupportedVersions returns an encoded SupportedVersions extension
func ExtGetSupportedVersions(details models.JarmOptions, grease bool) []byte {
	tlsVersions := [][]byte{}
	if details.V13Mode == "1.2_SUPPORT" {
		tlsVersions = append(tlsVersions, []byte{0x03, 0x01})
		tlsVersions = append(tlsVersions, []byte{0x03, 0x02})
		tlsVersions = append(tlsVersions, []byte{0x03, 0x03})
	} else {
		tlsVersions = append(tlsVersions, []byte{0x03, 0x01})
		tlsVersions = append(tlsVersions, []byte{0x03, 0x02})
		tlsVersions = append(tlsVersions, []byte{0x03, 0x03})
		tlsVersions = append(tlsVersions, []byte{0x03, 0x04})
	}
	if details.ExtensionOrder != "FORWARD" {
		tlsVersions = ciphers.MungCiphers(tlsVersions, details.ExtensionOrder)
	}

	ver := []byte{}
	if grease {
		ver = append(ver, utils.RandomGrease()...)
	}
	for _, v := range tlsVersions {
		ver = append(ver, v...)
	}

	ext := []byte{0x00, 0x2b}
	ext = append(ext, utils.GetUint16Bytes(len(ver)+1)...)
	ext = append(ext, byte(len(ver)))
	ext = append(ext, ver...)
	return ext
}
