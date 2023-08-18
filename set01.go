package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
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

// Here’s what you should know from the get-go: without the proper background,
// the AES encryption algorithm can be a tough one to understand.
// To fully appreciate its intricacies, you would probably have
// to be a maths major (at least).
func AES128Encrypt(input []byte) {
	bsize := 4
	blocks := make([][]byte, 0, 10)
	for i := range input {
		if i%bsize == 0 {
			if i+bsize > len(input) {
				last := i + bsize - len(input)
				// fmt.Printf("%s\n", input[i:i+last])
				blocks = append(blocks, input[i:i+last])
				break
			}
			blocks = append(blocks, input[i:i+bsize])
			// fmt.Printf("%s\n", input[i:i+bsize])
		}
	}

	// Rijndael's galois field only allows an 8 bit number
	// (a number from 0 to 255) to fit in it. All mathematical
	// operations defined in the field result in an 8-bit number.

	// Addition and subtraction are performed
	// by the exclusive or operation. The two operations are the same;
	// there is no difference between addition and subtraction.
	gAdd := func(a byte, b byte) byte { return a ^ b }
	gSub := func(a byte, b byte) byte { return a ^ b }
	gMul := func(a byte, b byte) byte {
		var (
			prod     byte
			hiBitSet byte
		)
		for i := 0; i < 8; i++ {
			if (b & 1) == 1 {
				prod ^= a
			}
			hiBitSet = (a & 0x80)
			a <<= 1
			if hiBitSet == 0x80 {
				a ^= 0x1b
			}
			b >>= 1
		}
		return prod
	}
	_, _, _ = gAdd, gSub, gMul
	fmt.Println(gMul(byte(7), byte(3)))

	rotate := func(b []byte) []byte {
		if len(b) != 4 {
			panic("invalid length block")
		}
		return []byte{0: b[1], 1: b[2], 2: b[3], 3: b[0]}
	}

	for i := range blocks {
		fmt.Printf("%d %d %s %x %x\n", i, len(blocks[i]),
			blocks[i], blocks[i], rotate(blocks[i]))
	}

	// KeyExpansion
	// SubBytes
	// ShiftRows
	// MixColumns
	// AddRoundKey
}

func main() {
	phrase := []byte("better late than never")
	phrase2 := []byte("extraterrestrial")
	AES128Encrypt(phrase2)
	_, _ = phrase, phrase2
}
