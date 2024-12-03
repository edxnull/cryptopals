package main

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
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
		panic("FixedXOR: a and b should be equal!")
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

func base64DecodeFile(filename string) ([]byte, error) {
	f, err := os.Open("7.txt")
	if err != nil {
		return []byte{}, err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return []byte{}, err
	}
	return base64.StdEncoding.DecodeString(string(data))
}

func AES128Encrypt(key, data []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	enc := make([]byte, len(data))

	end := aes.BlockSize
	for start := 0; start < len(data); start += aes.BlockSize {
		cipher.Encrypt(enc[start:end], data[start:end])
		end += aes.BlockSize
	}

	return enc, nil
}

func AES128Decrypt(key, data []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	dec := make([]byte, len(data))

	end := aes.BlockSize
	for start := 0; start < len(data); start += aes.BlockSize {
		cipher.Decrypt(dec[start:end], data[start:end])
		end += aes.BlockSize
	}

	return dec, nil
}
