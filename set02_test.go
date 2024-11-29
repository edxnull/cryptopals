package main

import (
	"bytes"
	"crypto/aes"
	"errors"
	"fmt"
	"reflect"
	"testing"
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

func TestPKCS7(t *testing.T) {
	tests := []struct {
		in    []byte
		want  []byte
		bsize int
	}{
		{in: []byte("no"), want: []byte("no\x01"), bsize: 3},
		{in: []byte("no"), want: []byte("no"), bsize: 2},
		{in: []byte("barbaz"), want: []byte("barbaz\x02\x02"), bsize: 8},
		{in: []byte("ok"), want: []byte("ok\x08\x08\x08\x08\x08\x08\x08\x08"), bsize: 10},
		{in: []byte("YELLOW"), want: []byte("YELLOW\x04\x04\x04\x04"), bsize: 10},
		{in: []byte("YELLOW SUBMARINE"), want: []byte("YELLOW SUBMARINE\x04\x04\x04\x04"), bsize: 20},
	}

	for _, tc := range tests {
		out, _ := pkcs7(tc.in, tc.bsize)
		if !reflect.DeepEqual(tc.want, out) {
			t.Fatalf("wrong result: want '%d'\nbut got '%d'", tc.want, out)
		}
	}
}

func encCBC(key []byte, plaintext []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	plaintext, err = pkcs7(plaintext, aes.BlockSize)
	if err != nil {
		fmt.Println(err)
	}
	cipherText := make([]byte, len(plaintext))
	//for i, text := range plaintext {
	//fmt.Println(i, text)
	var blockCipher []byte
	//if i == 0 {
	iv := bytes.Repeat([]byte{byte(0x0)}, len(plaintext)) // noop?
	blockCipher = FixedXOR(plaintext, iv)
	//} else {
	//	blockCipher = FixedXOR(plaintext, cipherText)
	//}

	end := aes.BlockSize
	for start := 0; start < len(plaintext); start += aes.BlockSize {
		cipher.Encrypt(cipherText[start:end], blockCipher[start:end])
		end += aes.BlockSize
	}
	//}
	return cipherText, nil
}

func decCBC(key []byte, cipherText []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	plainText := make([]byte, len(cipherText))

	end := aes.BlockSize
	for start := 0; start < len(cipherText); start += aes.BlockSize {
		cipher.Decrypt(plainText[start:end], cipherText[start:end])
		end += aes.BlockSize
	}

	iv := bytes.Repeat([]byte{byte(0x0)}, len(cipherText)) // noop?
	plain := FixedXOR(plainText, iv)
	plen := len(plain)

	// clear padding
	padCount := 0
	padChar := plain[plen-1:][0]
	for x := plen - 1; x > 0; x-- {
		if padChar == plain[x] {
			padCount++
		} else {
			break
		}
	}
	return plain[:plen-padCount], nil
}

func TestCBCEncrypt(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	plaintext := []byte("this should be!!!!!!")
	cipherText, err := encCBC(key, plaintext)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s\n", cipherText)
}

func TestCBCDecrypt(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	plaintext := []byte("this should be!!!!!!")
	cipherText, err := encCBC(key, plaintext)
	if err != nil {
		fmt.Println(err)
	}
	out, err := decCBC(key, cipherText)
	if err != nil {
		fmt.Println(err)
	}

	if !reflect.DeepEqual(plaintext, out) {
		t.Fatalf("wrong result: want '%s'\nbut got '%s'", plaintext, out)
	}
}
