package testdata

import "net/http"

func fetchExternal() {
	// Should be detected with url_hint=external, confidence=LOW
	resp, err := http.Get("https://github.com/openziti/sdk-golang/releases")
	if err != nil {
		return
	}
	_ = resp
}

func fetchGoogleAPIs() {
	resp, err := http.Get("https://googleapis.com/oauth2/v1/tokeninfo")
	if err != nil {
		return
	}
	_ = resp
}
