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

	// https://www.samiam.org/rijndael.html
	// https://www.youtube.com/watch?v=O4xNJsjtN6E
	// https://cybernews.com/resources/what-is-aes-encryption/
	// https://www.cs.rit.edu/~spr/gdn2010/sticky.pdf

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
			// fmt.Printf("%08b %d\n", b, b)
			if (b & 1) == 1 {
				prod ^= a
			}
			hiBitSet = (a & 0x80) // 0x08 = 128
			a <<= 1
			if hiBitSet == 0x80 {
				a ^= 0x1b // 0x1b = 27
			}
			b >>= 1
		}
		return prod
	}

	gRcon := func(in byte) byte {
		c := byte(1)
		if in == 0 {
			return in
		}
		for ; in != 1; in-- {
			c = gMul(c, 2)
		}
		return c
	}

	gSbox := func() {}

	_, _, _, _, _ = gAdd, gSub, gMul, gSbox, gRcon
	fmt.Println(gMul(byte(7), byte(3)))

	generator := []byte{
		0: 0x3, 1: 0x5, 2: 0x6, 3: 0x9,
		4: 0xb, 5: 0xe, 6: 0x11, 7: 0x12,
		8: 0x13, 9: 0x14, 10: 0x17, 11: 0x18,
		12: 0x19, 13: 0x1a, 14: 0x1c, 15: 0x1e,
		16: 0x1f, 17: 0x21, 18: 0x22, 19: 0x23,
		20: 0x27, 21: 0x28, 22: 0x2a, 23: 0x2c,
		24: 0x30, 25: 0x31, 26: 0x3c, 27: 0x3e,
		28: 0x3f, 29: 0x41, 30: 0x45, 31: 0x46,
		32: 0x47, 33: 0x48, 34: 0x49, 35: 0x4b,
		36: 0x4c, 37: 0x4e, 38: 0x4f, 39: 0x52,
		40: 0x54, 41: 0x56, 42: 0x57, 43: 0x58,
		44: 0x59, 45: 0x5a, 46: 0x5b, 47: 0x5f,
		48: 0x64, 49: 0x65, 50: 0x68, 51: 0x69,
		52: 0x6d, 53: 0x6e, 54: 0x70, 55: 0x71,
		56: 0x76, 57: 0x77, 58: 0x79, 59: 0x7a,
		60: 0x7b, 61: 0x7e, 62: 0x81, 63: 0x84,
		64: 0x86, 65: 0x87, 66: 0x88, 67: 0x8a,
		68: 0x8e, 69: 0x8f, 70: 0x90, 71: 0x93,
		72: 0x95, 73: 0x96, 74: 0x98, 75: 0x99,
		76: 0x9b, 77: 0x9d, 78: 0xa0, 79: 0xa4,
		80: 0xa5, 81: 0xa6, 82: 0xa7, 83: 0xa9,
		84: 0xaa, 85: 0xac, 86: 0xad, 87: 0xb2,
		88: 0xb4, 89: 0xb7, 90: 0xb8, 91: 0xb9,
		92: 0xba, 93: 0xbe, 94: 0xbf, 95: 0xc0,
		96: 0xc1, 97: 0xc4, 98: 0xc8, 99: 0xc9,
		100: 0xce, 101: 0xcf, 102: 0xd0, 103: 0xd6,
		104: 0xd7, 105: 0xda, 106: 0xdc, 107: 0xdd,
		108: 0xde, 109: 0xe2, 110: 0xe3, 111: 0xe5,
		112: 0xe6, 113: 0xe7, 114: 0xe9, 115: 0xea,
		116: 0xeb, 117: 0xee, 118: 0xf0, 119: 0xf1,
		120: 0xf4, 121: 0xf5, 122: 0xf6, 123: 0xf8,
		124: 0xfb, 125: 0xfd, 126: 0xfe, 127: 0xff,
	}
	_ = generator

	genExponents := func() []byte {
		e := make([]byte, 0, 0x100)
		elem := byte(0x1)
		e = append(e, 0x1)
		for i := 0; i < 0xFF; i++ { // 255 -> 0x100
			elem = gMul(elem, 0xe5)
			e = append(e, elem)
		}
		return e
	}

	e := genExponents()
	fmt.Printf("%x %d %d\n", e, len(e), cap(e))

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
