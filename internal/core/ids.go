package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// GenerateRunID returns "YYYYMMDDHHMMSS-XXXX" (UTC + 2-byte nonce).
// Same shape the TS implementation produces; sortable lexicographically.
func GenerateRunID() string {
	t := time.Now().UTC()
	stamp := t.Format("20060102150405")
	var nonce [2]byte
	_, _ = rand.Read(nonce[:])
	return stamp + "-" + hex.EncodeToString(nonce[:])
}

// NowISO returns the current UTC time in RFC3339 with nanosecond precision.
func NowISO() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

// FileHashHex returns the SHA-256 hex digest of b.
func FileHashHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
