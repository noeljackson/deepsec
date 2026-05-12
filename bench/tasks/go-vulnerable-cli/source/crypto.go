package main

import (
	"crypto/md5"
	"fmt"
)

func weakHash(password string) string {
	sum := md5.Sum([]byte(password))
	return fmt.Sprintf("%x", sum)
}
