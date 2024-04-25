package constants

import (
	"crypto/tls"
	"regexp"
)

const (
	// Default plaintext port
	PLAIN_SERVER_PORT = 5222
	// Default SSL port
	SSL_SERVER_PORT = 5223
	// Listen on IPV4. Kik requires IPV4 so it should be no issue
	SERVER_TYPE = "tcp4"
	// Client has this long to prove itself
	CLIENT_INITIAL_READ_TIMEOUT_SECONDS = 3
	// After initial read, abort if no data from client after this many seconds
	CLIENT_READ_TIMEOUT_SECONDS = 60 * 10

	// Kik uses TCP
	KIK_SERVER_TYPE = "tcp"
	// Kik XMPP port
	KIK_SERVER_PORT = "443"
	// Abort if Kik takes longer than this to send back the initial response
	KIK_INITIAL_READ_TIMEOUT_SECONDS = 5
	// Abort if a write call takes longer than this
	WRITE_TIMEOUT_SECONDS = 15

	// TLSv1.2 is recommended for compatibility reasons.
	// If you don't need to support 1.2 clients, change to `tls.VersionTLS13`
	// DO NOT use lower than 1.2, as older protocols contain security flaws.
	SERVER_TLS_VERSION = tls.VersionTLS12
)

var (
	API_KEY_REGEX *regexp.Regexp = regexp.MustCompile("^[A-Za-z0-9._-]{32,256}$")
)
