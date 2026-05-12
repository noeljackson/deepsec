package main

import (
	"net/http"
	"os"
)

func readFileHandler(w http.ResponseWriter, req *http.Request) {
	f, _ := os.Open(req.URL.Query().Get("path"))
	defer f.Close()
	w.WriteHeader(http.StatusNoContent)
}

func readBanner() ([]byte, error) {
	return os.ReadFile("/etc/motd")
}
