package main

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"reflect"
	"strings"
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
	iv := bytes.Repeat([]byte{byte(0x0)}, aes.BlockSize) // noop?
	cipherText, err := encCBC(iv, key, plaintext)
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

	iv := bytes.Repeat([]byte{byte(0x0)}, aes.BlockSize) // noop?
	out, err := decCBC(iv, key, data)
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

	iv := bytes.Repeat([]byte{byte(0x0)}, aes.BlockSize) // noop?
	dec, _ := decCBC(iv, key, data)
	enc, _ := encCBC(iv, key, dec)
	out, _ := decCBC(iv, key, enc)

	want := []byte("VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino ")
	if !bytes.Contains(out, want) {
		t.Fatalf("wrong result: want '%s'\nbut got '%s'", want, out)
	}
}

func TestRandAESKey(t *testing.T) {
	a := randAESKey()
	b := randAESKey()
	c := randAESKey()
	ab := bytes.Equal(a, b)
	ac := bytes.Equal(a, c)
	bc := bytes.Equal(b, c)
	if ab {
		t.Fatal("randAESKey() is not random")
	} else if ac {
		t.Fatal("randAESKey() is not random")
	} else if bc {
		t.Fatal("randAESKey() is not random")
	}
}

// NOTE: normal that it is flaky, because oracle encrypts in ECB only
// half the time.
func TestEncOracle(t *testing.T) {
	oracle, err := encOracle(bytes.Repeat([]byte("a"), aes.BlockSize*3))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Compare(detectBlockCipher(oracle), "ECB") == 0 {
		fmt.Println(detectBlockCipher(oracle))
	}
}

func TestRandRange(t *testing.T) {
	r := len(randRange())
	if r < 5 || r > 10 {
		t.Fatal("unexpected random range: should be < 5 and > 10")
	}
}

func TestDecByteAtATime(t *testing.T) {
	zero, err := decByteAtATime(bytes.Repeat([]byte(""), 0))
	if err != nil {
		t.Fatal("unexpected error")
	}

	var blockSize int
	for x := range 64 {
		curr, err := decByteAtATime(bytes.Repeat([]byte("A"), x))
		if err != nil {
			t.Fatal("unexpected error")
		}

		if len(curr) != len(zero) {
			blockSize = len(curr) - len(zero)
			break
		}
	}
	_ = blockSize

	out, err := decByteAtATime(bytes.Repeat([]byte("A"), aes.BlockSize))
	if err != nil {
		t.Fatal("unexpected error")
	}
	fmt.Printf("%s\n", detectBlockCipher(out))
}
