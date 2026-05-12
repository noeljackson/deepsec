package main

import (
	"net/http"
	"os/exec"
)

func grepHandler(w http.ResponseWriter, r *http.Request) {
	term := r.URL.Query().Get("term")
	out, _ := exec.Command("sh", "-c", "grep "+term+" /var/log/app.log").Output()
	w.Write(out)
}

func uptimeHandler(w http.ResponseWriter, _ *http.Request) {
	out, _ := exec.Command("/usr/bin/uptime").Output()
	w.Write(out)
}
