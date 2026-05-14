package jwt

import "testing"

// These are test fixtures. The string "your-256-bit-secret" is a
// well-known placeholder from the JWT spec docs — it is not a real
// secret. The scanner's test-context demotion should catch this and
// not surface a finding.
const hmacTestSecret = "your-256-bit-secret"

func TestParseValid(t *testing.T) {
	p := Parser{ValidMethods: []string{"HS256"}}
	_, err := p.ParseWithClaims("eyJhbGciOi.eyJzdWI.sig", map[string]any{}, func(*Token) (any, error) {
		return []byte(hmacTestSecret), nil
	})
	if err == nil {
		t.Skip("missing signing method registry in fixture")
	}
}

func TestParseNoneAlgRejected(t *testing.T) {
	p := Parser{ValidMethods: []string{"HS256"}}
	_, err := p.ParseWithClaims("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.", map[string]any{}, func(*Token) (any, error) {
		return []byte("test-secret-not-real"), nil
	})
	if err == nil {
		t.Fatalf("expected reject")
	}
}
