package gojarm

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"github.com/TheGejr/gojarm/ciphers"
	"github.com/TheGejr/gojarm/extension"
	"github.com/TheGejr/gojarm/models"
	"github.com/TheGejr/gojarm/probes"
	"github.com/TheGejr/gojarm/utils"
)

//////
// `gojarm` is a module-based go implementation of JARM.
// This implementation was created by Malte Gejr <malte@gejr.dk>
// With inspiration from the creators of jarm-go.
//
// Jarm is an active Transport Layer Security (TLS) server fingerprinting tool, created by SalesForce
// The original implementation can be found here: https://github.com/salesforce/jarm
//////

// Empty JARM hash
var ZeroHash = "00000000000000000000000000000000000000000000000000000000000000"

// Target struct
type Target struct {
	Host string
	Port int

	Retries int
	Backoff func(r, m int) time.Duration
}

// Result struct
type Result struct {
	Target Target
	Hash   string
	Error  error
}

// ParseServerHello returns the raw fingerprint for a server hello response
func ParseServerHello(data []byte, details models.JarmOptions) (string, error) {
	if len(data) == 0 {
		return "|||", nil
	}

	// Alert indicates a failed handshake
	if data[0] == 21 {
		return "|||", nil
	}

	// Not a Server Hello response
	if !(data[0] == 22 && len(data) > 5 && data[5] == 2) {
		return "|||", nil
	}
	// server_hello_length
	serverHelloLength := int(binary.BigEndian.Uint16(data[3:5]))

	// Too short
	if len(data) < 44 {
		return "|||", nil
	}

	counter := int(data[43])
	cipherOffset := counter + 44
	if len(data) < (cipherOffset + 2) {
		return "|||", nil
	}

	serverCip := hex.EncodeToString(data[cipherOffset : cipherOffset+2])
	serverVer := hex.EncodeToString(data[9:11])
	serverExt := extension.ExtractExtensionInfo(data, counter, serverHelloLength)

	return fmt.Sprintf("%s|%s|%s", serverCip, serverVer, serverExt), nil
}

// RawHashToFuzzyHash converts a raw hash to a JARM hash
func RawHashToFuzzyHash(raw string) string {
	if raw == "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||" {
		return ZeroHash
	}
	fhash := ""
	alpex := ""
	for _, handshake := range strings.Split(raw, ",") {
		comp := strings.Split(handshake, "|")
		if len(comp) != 4 {
			return ZeroHash
		}
		fhash = fhash + ciphers.ExtractCipherBytes(comp[0])
		fhash = fhash + ciphers.ExtractVersionByte(comp[1])
		alpex = alpex + comp[2]
		alpex = alpex + comp[3]
	}
	hash256 := sha256.Sum256([]byte(alpex))
	fhash += hex.EncodeToString(hash256[:])[0:32]
	return fhash
}

func Fingerprint(t Target) (result Result) {
	// TODO: Check if target is valid (ip and port)

	results := []string{}

	for _, probe := range probes.GetProbes(t.Host, t.Port) {
		dialer := proxy.FromEnvironmentUsing(&net.Dialer{Timeout: time.Second * 2})
		addr := net.JoinHostPort(t.Host, fmt.Sprintf("%d", t.Port))

		conn := net.Conn(nil)
		n := 0

		for conn == nil && n <= t.Retries {
			// Ignoring errors since error messages was already dropped
			// conn == nil means an error occured
			conn, _ = dialer.Dial("tcp", addr)
			if conn != nil || t.Retries == 0 {
				break
			}

			backoff := t.Backoff
			if backoff == nil {
				backoff = utils.DefualtBackoff
			}

			time.Sleep(backoff(n, t.Retries))

			n++
		}

		if conn == nil {
			return Result{
				Error: errors.New("failed to establish a connection to the host"),
			}
		}

		data := probes.BuildProbe(probe)
		conn.SetWriteDeadline(time.Now().Add(time.Second * 5))
		_, err := conn.Write(data)
		if err != nil {
			results = append(results, "")
			conn.Close()
			continue
		}

		conn.SetReadDeadline(time.Now().Add(time.Second * 5))
		buff := make([]byte, 1484)
		conn.Read(buff)
		conn.Close()

		ans, err := ParseServerHello(buff, probe)
		if err != nil {
			results = append(results, "")
			continue
		}

		results = append(results, ans)
	}

	return Result{
		Target: t,
		Hash:   RawHashToFuzzyHash(strings.Join(results, ",")),
	}
}
