package testdata

import "net"

func dialTCP() {
	conn, err := net.Dial("tcp", "example.com:8080")
	if err != nil {
		return
	}
	_ = conn
}

func dialContext() {
	// net.DialContext also flagged
}

func dialUnix() {
	// should be SKIPPED — unix socket not Ziti-compatible
	conn, err := net.Dial("unix", "/tmp/app.sock")
	if err != nil {
		return
	}
	_ = conn
}
