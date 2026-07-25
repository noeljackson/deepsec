package core

import (
	"strings"
	"testing"
)

func TestRedactSecretsRemovesCommonCredentialForms(t *testing.T) {
	input := "token = \"super-secret-value\"\nAuthorization: Bearer abc.def.ghi\nkey=ghp_abcdefghijklmnopqrstuvwxyz1234567890\n-----BEGIN PRIVATE KEY-----\nprivate\n-----END PRIVATE KEY-----"
	got := RedactSecrets(input)
	for _, forbidden := range []string{"super-secret-value", "abc.def.ghi", "ghp_abcdefghijklmnopqrstuvwxyz1234567890", "private\n-----END"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("redaction leaked %q: %s", forbidden, got)
		}
	}
	if count := strings.Count(got, RedactedSecret); count < 4 {
		t.Fatalf("expected several redactions, got %d: %s", count, got)
	}
}

func TestRedactSecretsIsIdempotent(t *testing.T) {
	input := "password: hunter2"
	if got := RedactSecrets(RedactSecrets(input)); got != RedactSecrets(input) {
		t.Fatalf("redaction is not idempotent: %q", got)
	}
}
