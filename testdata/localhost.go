package testdata

import "net/http"

func fetchLocalhost() {
	// Should be detected with url_hint=localhost, confidence=LOW
	resp, err := http.Get("http://localhost:8065/api/v4/ping")
	if err != nil {
		return
	}
	_ = resp
}

func fetchLoopback() {
	resp, err := http.Get("http://127.0.0.1:8065/health")
	if err != nil {
		return
	}
	_ = resp
}
