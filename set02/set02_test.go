package main

import (
	"bytes"
	"testing"
)

func pkcs7(s []byte, bsize int) []byte {
	return []byte{}
}

func TestPKCS7(t *testing.T) {
	out := pkcs7([]byte("YELLOW SUBMARINE"), 20)
	want := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")

	if !bytes.Equal(out, want) {
		t.Fatalf("wrong result: want '%s'\nbut got '%s'", want, out)
	}
}
