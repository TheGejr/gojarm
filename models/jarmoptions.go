package models

// JarmOptions specifies the parameters for a single probe
type JarmOptions struct {
	Hostname       string
	Port           int
	Version        int
	Ciphers        string
	CipherOrder    string
	Grease         string
	ALPN           string
	V13Mode        string
	ExtensionOrder string
}
