package main

import "net/http"

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	resp, _ := http.Get(r.URL.Query().Get("target"))
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
}

func statusCheck() (*http.Response, error) {
	return http.Get("https://status.example.com/health")
}
