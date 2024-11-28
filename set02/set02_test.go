package main

import (
	"bytes"
	"errors"
	"testing"
)

func pkcs7(s []byte, bsize int) ([]byte, error) {
	if bsize >= 256 {
		return []byte{}, errors.New("bsize length should be <256")
	}
	slen := len(s)
	pad := bsize - (slen % bsize)
	m := make([]byte, slen+pad)
	copy(m, s)
	copy(m[slen:], bytes.Repeat([]byte{byte(pad)}, len(m)-slen))
	return m, nil
}

func TestPKCS7(t *testing.T) {
	out, _ := pkcs7([]byte("YELLOW SUBMARINE"), 20)
	want := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")

	if !bytes.Equal(out, want) {
		t.Fatalf("wrong result: want '%d'\nbut got '%d'", want, out)
	}
}
