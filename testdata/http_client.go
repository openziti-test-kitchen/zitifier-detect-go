package testdata

import (
	"fmt"
	"net/http"
)

func httpGet(siteURL string) {
	resp, err := http.Get(fmt.Sprintf("%s/api/v4/users", siteURL))
	if err != nil {
		return
	}
	_ = resp
}

func httpPost(siteURL string) {
	resp, err := http.Post(siteURL+"/api/v4/posts", "application/json", nil)
	if err != nil {
		return
	}
	_ = resp
}

func httpClientLiteral() *http.Client {
	return &http.Client{}
}

func httpDefaultClient() {
	resp, err := http.DefaultClient.Do(nil)
	if err != nil {
		return
	}
	_ = resp
}

func newRequest(siteURL string) {
	req, err := http.NewRequest("GET", siteURL+"/api/v4/ping", nil)
	if err != nil {
		return
	}
	_ = req
}
