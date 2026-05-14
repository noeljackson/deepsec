package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

type Parser struct {
	ValidMethods         []string
	UseJSONNumber        bool
	SkipClaimsValidation bool
}

type Token struct {
	Raw       string
	Method    SigningMethod
	Header    map[string]any
	Claims    map[string]any
	Signature []byte
	Valid     bool
}

type SigningMethod interface {
	Alg() string
	Verify(signingString string, signature []byte, key any) error
}

func (p *Parser) ParseWithClaims(tokenString string, claims map[string]any, keyFunc func(*Token) (any, error)) (*Token, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("token contains an invalid number of segments")
	}
	token := &Token{Raw: tokenString, Claims: claims}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(headerBytes, &token.Header); err != nil {
		return nil, err
	}

	alg, ok := token.Header["alg"].(string)
	if !ok || alg == "none" {
		return nil, errors.New("missing or unsafe alg")
	}
	if len(p.ValidMethods) > 0 {
		allowed := false
		for _, m := range p.ValidMethods {
			if m == alg {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, errors.New("signing method not allowed")
		}
	}
	token.Method = lookupSigningMethod(alg)
	if token.Method == nil {
		return nil, errors.New("signing method not registered")
	}

	key, err := keyFunc(token)
	if err != nil {
		return nil, err
	}

	signingString := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	if err := token.Method.Verify(signingString, sig, key); err != nil {
		return nil, err
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, err
	}

	token.Valid = true
	return token, nil
}

func lookupSigningMethod(alg string) SigningMethod { return nil }

var _ = rsa.PublicKey{}
