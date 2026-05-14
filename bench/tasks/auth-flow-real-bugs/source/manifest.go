// Minimal repro of an unauthenticated GitHub OAuth app takeover.
// Pattern derived from a real CRITICAL Codex Cyber finding.
//
// The vulnerability: a public HTTP handler accepts a GitHub App
// manifest conversion `code`, exchanges it with GitHub, and stores
// the returned client_id/client_secret with no admin authentication,
// no state/nonce check, and no idempotency guard against re-config.
// An unauthenticated attacker can create their own GitHub App
// manifest pointing at the victim's callback, complete the flow, and
// hijack the relay's OAuth credentials.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type oauthStore interface {
	GitHubAppSet(clientID, clientSecret string) error
	GitHubAppExists() bool
}

// ManifestCallbackHandler exposes /auth/github/manifest/callback to
// the public internet with no admin gate. This is the bug.
func ManifestCallbackHandler(st oauthStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code parameter", http.StatusBadRequest)
			return
		}

		// No state / nonce check.
		// No check that st.GitHubAppExists() == false.
		// No admin session check before allowing reconfiguration.

		convURL := fmt.Sprintf("https://api.github.com/app-manifests/%s/conversions", code)
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, convURL, nil)
		req.Header.Set("Accept", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		var creds struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&creds)
		// Stores attacker-controlled credentials.
		_ = st.GitHubAppSet(creds.ClientID, creds.ClientSecret)
		w.Write([]byte("ok"))
	}
}

// ManifestCallbackHandlerSafe is the same flow with the standard
// mitigations applied. Should NOT trip the matcher: state nonce
// check, admin auth, and idempotency guard are all present.
func ManifestCallbackHandlerSafe(st oauthStore, admin func(*http.Request) bool, validState func(string) bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !admin(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		state := r.URL.Query().Get("state")
		if !validState(state) {
			http.Error(w, "bad state", http.StatusBadRequest)
			return
		}
		if st.GitHubAppExists() {
			http.Error(w, "already configured", http.StatusConflict)
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code parameter", http.StatusBadRequest)
			return
		}
		convURL := fmt.Sprintf("https://api.github.com/app-manifests/%s/conversions", code)
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, convURL, nil)
		req.Header.Set("Accept", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
		var creds struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&creds)
		_ = st.GitHubAppSet(creds.ClientID, creds.ClientSecret)
		w.Write([]byte("ok"))
	}
}
