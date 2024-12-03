package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	mrand "math/rand/v2"
)

func pkcs7(s []byte, bsize int) ([]byte, error) {
	if bsize >= 256 {
		return []byte{}, errors.New("bsize length should be <256")
	}
	if len(s) == bsize {
		return s, nil
	}
	slen := len(s)
	pad := bsize - (slen % bsize)
	m := make([]byte, slen+pad)
	copy(m, s)
	copy(m[slen:], bytes.Repeat([]byte{byte(pad)}, len(m)-slen))
	return m, nil
}

func encCBC(key []byte, plainText []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	plainText, err = pkcs7(plainText, aes.BlockSize)
	if err != nil {
		fmt.Println(err)
	}
	cipherText := make([]byte, aes.BlockSize)
	var buffer bytes.Buffer

	end := aes.BlockSize
	for start := 0; start < len(plainText); start += aes.BlockSize {
		if start == 0 {
			iv := bytes.Repeat([]byte{byte(0x0)}, aes.BlockSize) // noop?
			cipherText = FixedXOR(plainText[start:end], iv)
		} else {
			cipherText = FixedXOR(plainText[start:end], cipherText)
		}
		cipher.Encrypt(cipherText, plainText[start:end])
		end += aes.BlockSize
		buffer.Write(cipherText)
	}
	return buffer.Bytes(), nil
}

func decCBC(key []byte, cipherText []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	plainText := make([]byte, aes.BlockSize)
	var buffer bytes.Buffer

	end := aes.BlockSize
	for start := 0; start < len(cipherText); start += aes.BlockSize {
		if start == 0 {
			iv := bytes.Repeat([]byte{byte(0x0)}, aes.BlockSize) // noop?
			plainText = FixedXOR(plainText, iv)
		} else {
			plainText = FixedXOR(plainText, cipherText[start:end])
		}
		cipher.Decrypt(plainText, cipherText[start:end])
		end += aes.BlockSize
		buffer.Write(plainText)
	}
	return buffer.Bytes(), nil
}

func randAESKey() []byte {
	buf := make([]byte, 16)
	_, err := rand.Read(buf)
	if err != nil {
		log.Fatalf("error while generating random string: %s", err)
	}
	return buf
}

func randRange() []byte {
	r := mrand.IntN(10-5) + 5
	buf := make([]byte, r)
	_, err := rand.Read(buf)
	if err != nil {
		log.Fatalf("error while generating random string: %s", err)
	}
	return buf
}

func encOracle(input []byte) ([]byte, error) {
	var b bytes.Buffer
	b.Write(randRange())
	b.Write(input)
	b.Write(randRange())
	return encCBC(randAESKey(), b.Bytes())
}
