package testdata

import (
	"net"
	"net/http"
	"testing"
)

// These should all be SKIPPED — they are in a _test.go file.

func TestDialInTest(t *testing.T) {
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		t.Skip()
	}
	_ = conn
}

func TestHTTPInTest(t *testing.T) {
	resp, err := http.Get("http://localhost:8065/api/v4/ping")
	if err != nil {
		t.Skip()
	}
	_ = resp
}
