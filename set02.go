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

func encCBC(iv, key, plainText []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	plainText, err = pkcs7(plainText, aes.BlockSize)
	if err != nil {
		return []byte{}, err
	}
	cipherText := make([]byte, aes.BlockSize)
	var buffer bytes.Buffer

	end := aes.BlockSize
	var xorBlock []byte
	for start := 0; start < len(plainText); start += aes.BlockSize {
		if start == 0 {
			xorBlock = FixedXOR(plainText[start:end], iv)
		} else {
			xorBlock = FixedXOR(plainText[start:end], cipherText)
		}
		cipher.Encrypt(cipherText, xorBlock)
		_, err := buffer.Write(cipherText)
		if err != nil {
			return []byte{}, err
		}
		end += aes.BlockSize
	}
	return buffer.Bytes(), nil
}

func decCBC(iv, key, cipherText []byte) ([]byte, error) {
	var buffer bytes.Buffer
	var xorBlock []byte

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	prevBlock := iv
	decBlock := make([]byte, aes.BlockSize)
	end := aes.BlockSize
	for start := 0; start < len(cipherText); start += aes.BlockSize {
		cipher.Decrypt(decBlock, cipherText[start:end])
		xorBlock = FixedXOR(decBlock, prevBlock)
		_, err := buffer.Write(xorBlock)
		if err != nil {
			return []byte{}, err
		}
		prevBlock = cipherText[start:end]
		end += aes.BlockSize
	}

	b := buffer.Bytes()

	return b, nil
}

func randAESKey() []byte {
	buf := make([]byte, 16)
	_, err := rand.Read(buf)
	if err != nil {
		log.Fatalf("error while generating random AES key: %s", err)
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
	var (
		buff       bytes.Buffer
		err        error
		firstHalf  []byte
		secondHalf []byte
	)

	buff.Write(randRange())
	buff.Write(input)
	buff.Write(randRange())

	b := buff.Bytes()
	half := len(b) / 2

	key := randAESKey()

	if mrand.Int()%2 == 0 {
		firstHalf, err = encCBC(randAESKey(), key, b[:half])
		if err != nil {
			return []byte{}, err
		}
		secondHalf, err = AES128Encrypt(key, b[half:])
		if err != nil {
			return []byte{}, err
		}
		return bytes.Join([][]byte{firstHalf, secondHalf}, []byte("")), nil
	}

	secondHalf, err = AES128Encrypt(key, b[:half])
	if err != nil {
		return []byte{}, err
	}
	firstHalf, err = encCBC(randAESKey(), key, b[half:])
	if err != nil {
		return []byte{}, err
	}
	return bytes.Join([][]byte{secondHalf, firstHalf}, []byte("")), nil
}
