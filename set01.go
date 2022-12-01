package main

import (
	"encoding/base64"
	"encoding/hex"
)

// Hex encoding and Base64 encoding
// https://www.base64encoder.io/learn/
// https://datatracker.ietf.org/doc/html/rfc4648

func HexToBase64(input string) (string, error) {
	hx, err := hex.DecodeString(input)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(hx), nil
}

func FixedXOR(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("a and b should be equal!")
	}
	mk := make([]byte, len(a))
	for i := range a {
		mk[i] = a[i] ^ b[i]
	}
	return mk
}

func SingleByteXOR(input []byte, ch byte) []byte {
	xored := make([]byte, len(input))
	for i := range input {
		xored[i] = input[i] ^ ch
	}
	return xored
}

func RepeatingKeyXOR(input []byte, key []byte) []byte {
	xored := make([]byte, len(input))
	for i := range input {
		xored[i] = input[i] ^ key[i%len(key)]
	}
	return xored
}

// NOTE: 10 rounds for 128
func AES128Encrypt(input []byte) {
	// KeyExpansion
	// SubBytes
	// ShiftRows
	// MixColumns
	// AddRoundKey
}
