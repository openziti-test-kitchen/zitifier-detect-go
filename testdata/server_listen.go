package testdata

import (
	"net"
	"net/http"
)

func listenAndServe() {
	// Should be detected: SERVER, http.ListenAndServe
	http.ListenAndServe(":8080", nil) //nolint
}

func listenAndServeTLS() {
	// Should be detected: SERVER, http.ListenAndServeTLS
	http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil) //nolint
}

func netListen() {
	// Should be detected: SERVER, net.Listen
	ln, err := net.Listen("tcp", ":9000")
	if err != nil {
		return
	}
	_ = ln
}

func netListenUnix() {
	// Should be SKIPPED — unix not Ziti-compatible
	ln, err := net.Listen("unix", "/tmp/app.sock")
	if err != nil {
		return
	}
	_ = ln
}
