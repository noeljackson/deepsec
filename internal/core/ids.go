package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// GenerateRunID returns "YYYYMMDDHHMMSS-XXXXXXXX" (UTC + 4-byte nonce).
// The timestamp has 1-second resolution; the 8-hex-char nonce gives
// 4.3 billion distinct values per second, so collisions in any
// realistic concurrent-run scenario are negligible. (The original
// 2-byte / 4-hex nonce ran a ~7% birthday-paradox collision rate at
// 100 calls per second, which was tripping the uniqueness test on
// CI.) IDs are still sortable lexicographically.
func GenerateRunID() string {
	t := time.Now().UTC()
	stamp := t.Format("20060102150405")
	var nonce [4]byte
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
