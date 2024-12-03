package main

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

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

	data, err := base64DecodeFile("10.txt")
	if err != nil {
		t.Fatalf("%s", err)
	}

	out, err := decCBC(key, data)
	if err != nil {
		t.Fatalf("%s", err)
	}

	want := []byte("VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino ")
	if !bytes.Contains(out, want) {
		t.Fatalf("wrong result: want '%s'\nbut got '%s'", want, out)
	}
}

func TestCBCDecAfterEnc(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")

	data, err := base64DecodeFile("10.txt")
	if err != nil {
		t.Fatalf("%s", err)
	}

	dec, _ := decCBC(key, data)
	enc, _ := encCBC(key, dec)
	out, _ := decCBC(key, enc)

	want := []byte("VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino ")
	if !bytes.Contains(out, want) {
		t.Fatalf("wrong result: want '%s'\nbut got '%s'", want, out)
	}
}

func TestRandAESKey(t *testing.T) {
	fmt.Println(randAESKey())
}

func TestEncOracle(t *testing.T) {
	oracle, err := encOracle([]byte("gibber gabber fooo bar baz"))
	if err != nil {
		t.Fatalf("error ocucred: %s\n", err)
	}
	fmt.Printf("%s\n", oracle)
}
