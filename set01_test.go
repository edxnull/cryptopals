package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"testing"
)

func hexdec(t *testing.T, s string) []byte {
	hx, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hexdec errror: %s\n", err)
	}
	return hx
}

func TestHexToBase64(t *testing.T) {
	hex := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	want := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	if r, _ := HexToBase64(hex); r != want {
		t.Errorf("hex doesn't match want")
	}
}

func TestFixedXOR(t *testing.T) {
	want := hexdec(t, "746865206b696420646f6e277420706c6179")
	if !bytes.Equal(FixedXOR(
		hexdec(t, "1c0111001f010100061a024b53535009181c"),
		hexdec(t, "686974207468652062756c6c277320657965")), want) {
		t.Fatalf("bytes are not equal!")
	}
}

func decipher(t *testing.T, input, ascii string) (byte, int) {
	var max int
	var result byte
	for i := range ascii {
		xored := SingleByteXOR(hexdec(t, input), ascii[i])
		score := 0
		for j := range xored {
			if xored[j] >= 'A' && xored[j] <= 'Z' ||
				xored[j] >= 'a' && xored[j] <= 'z' ||
				xored[j] == ' ' || xored[j] == '_' {
				score += int(xored[j])
			} else {
				score -= int(xored[j])
			}
		}
		if max < score {
			max = score
			result = ascii[i]
		}
	}
	return result, max
}

const ascii = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

func TestSingleByteXOR(t *testing.T) {
	encoded := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	cph, _ := decipher(t, encoded, ascii)
	fmt.Printf("%s\n", SingleByteXOR(hexdec(t, encoded), cph))
}

func TestDetectSingleCharacterXOR(t *testing.T) {
	f, err := os.Open("4.txt")
	if err != nil {
		t.Fatalf("%s", err)
	}
	defer f.Close()

	collectLines := func(t *testing.T, r io.Reader) []string {
		result := make([]string, 0, 328)
		buf := bufio.NewReader(r)
		line, err := buf.ReadString('\n')
		if err != nil {
			t.Fatalf("%s\n", err)
		}
		result = append(result, strings.TrimSpace(line))
		for {
			if err == io.EOF {
				break
			}
			line, err = buf.ReadString('\n')
			result = append(result, strings.TrimSpace(line))
		}
		return result
	}

	answer := struct {
		cipher byte
		score  int
		lineNr int
	}{}

	lines := collectLines(t, f)
	for i, line := range lines {
		cph, max := decipher(t, line, ascii)
		if answer.score < max {
			answer.score = max
			answer.cipher = cph
			answer.lineNr = i
		}
	}
	fmt.Printf("%c => %s", answer.cipher, SingleByteXOR(hexdec(t, lines[answer.lineNr]), answer.cipher))
}

func TestRepeatingKeyXOR(t *testing.T) {
	input := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`
	s := `0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f`
	want := hexdec(t, strings.Join(strings.Fields(s), ""))
	if xored := RepeatingKeyXOR([]byte(input), []byte("ICE")); !bytes.Equal(xored, []byte(want)) {
		t.Fatalf("want: %s\ngot %s\n", want, xored)
	}
}

func TestBreakRepeatingKeyXOR(t *testing.T) {
	f, err := os.Open("6.txt")
	if err != nil {
		t.Fatalf("%s", err)
	}
	defer f.Close()

	data, _ := io.ReadAll(f)

	a, b := "this is a test", "wokka wokka!!!"
	hamming := func(sa, sb string) int {
		diff := func(a, b byte) int {
			res := 0
			for i, c := 0, int(a^b); i < c; i++ {
				if c&(1<<i) != 0 {
					res++
				}
			}
			return res
		}

		dist := 0
		for i := range sa {
			dist += diff(sa[i], sb[i])
		}
		return dist
	}

	want := 37
	if got := hamming(a, b); got != want {
		t.Fatalf("wrong Hamming distance want: %d, got %d\n", want, got)
	}

	min, max := 2, 40
	normals := make(map[int]float64, max-min)
	for ksize := min; ksize < max+1; ksize++ {
		normals[ksize] = float64(hamming(string(data[:ksize]),
			string(data[ksize:ksize*2]))) / float64(ksize)
	}
	var average float64
	for k := 2; k <= 16; k *= 2 {
		average += float64(hamming(string(data[:k]), string(data[k:k*2]))) / float64(k)
	}
	average /= float64(4)

	var keySize int
	for k, v := range normals {
		if (math.Round(average*100) / 100) == (math.Round(v*100) / 100) {
			keySize = k
		}
	}

	toblocks := func(ksize int, s string) []string {
		b := make([]string, 0, len(s)/ksize)
		for i := range s {
			if i%ksize == 0 && i+ksize < len(s) {
				// if i+ksize > len(s) {
				//     // note: handle case where we dont have
				//     //       ksize of bytes left to copy
				//     b = append(b, s[i:])
				//     continue
				// }
				b = append(b, s[i:i+ksize])
			}
		}
		return b
	}

	transpose := func(ksize int, blocks []string) [][]byte {
		b := make([][]byte, 0, ksize)
		for i := 0; i < ksize; i++ {
			tmp := make([]byte, 0, len(strings.Join(blocks, ""))/ksize)
			for j := range blocks {
				tmp = append(tmp, blocks[j][i])
				// get the last elem length
				//if i < len(blocks[len(blocks)-1]) {
				//    tmp = append(tmp, blocks[j][i])
				//}
				//if j < len(blocks)-1 {
				//    tmp = append(tmp, blocks[j][i])
				//}
			}
			b = append(b, tmp)
		}
		return b
	}

	data, err = base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		t.Fatalf("%s", err)
	}

	newScore := func(line []byte) int {
		nwords := len(bytes.Fields(line))
		nspace := bytes.Count(line, []byte(" "))
		nbytes := 0
		for i := range line {
			isAlpha := line[i] >= 'A' && line[i] <= 'Z' || line[i] >= 'a' && line[i] <= 'z'
			if isAlpha {
				nbytes += 1
			} else {
				nbytes -= 1
			}
		}
		return nbytes + nwords + nspace
	}

	answer := make([]byte, 0, keySize)
	tblocks := transpose(keySize, toblocks(keySize, string(data)))
	for _, tb := range tblocks {
		var (
			char byte
			best int
		)
		for i := range ascii {
			xored := SingleByteXOR(tb, ascii[i])
			if score := newScore(xored); best < score {
				char = ascii[i]
				best = score
			}
		}
		answer = append(answer, char)
	}
	fmt.Printf("%s\n", answer)
	phrase := "Terminator X: Bring the noise"
	if string(answer) != phrase {
		t.Fatalf("wrong result: want '%s'\nbut got '%s'", phrase, answer)
	}

	// NOTE: Interesting to note that it doesn't matter if we ommit
	//       JwwRTWM= in our block func and transpose func.
	_ = RepeatingKeyXOR(data, answer)
}

func TestAES128Encrypt(t *testing.T) {
	f, err := os.Open("7.txt")
	if err != nil {
		t.Fatalf("%s", err)
	}
	defer f.Close()

	data, _ := io.ReadAll(f)
	data, err = base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		t.Fatalf("%s", err)
	}

	cipher, _ := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	decrypted := make([]byte, len(data))

	end := aes.BlockSize
	for start := 0; start < len(data); start += aes.BlockSize {
		cipher.Decrypt(decrypted[start:end], data[start:end])
		end += aes.BlockSize
	}

	want := []byte("I'm back and I'm ringin' the bell")
	if !bytes.Contains(decrypted, want) {
		t.Fatalf("wrong result: want '%s'\nbut got '%s'", want, decrypted[0:33])
	}
}

// In this file are a bunch of hex-encoded ciphertexts.
// One of them has been encrypted with ECB.
//
// Detect it.
//
// Remember that the problem with ECB is that it is stateless and deterministic;
// the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
//
// https://cryptopals.com/sets/1/challenges/8
// https://cryptopals.com/static/challenge-data/8.txt
func TestDetectAESinECBMode(t *testing.T) {
	f, err := os.Open("8.txt")
	if err != nil {
		t.Fatalf("%s", err)
	}
	defer f.Close()

	allCiphers := func() (candidate string, allBlocks [][]byte) {
		d, _ := io.ReadAll(f)

		list := bytes.Split(d, []byte("\n"))

		var b bytes.Buffer
		for i, line := range list {
			hx, err := hex.DecodeString(string(line))
			if err != nil {
				fmt.Println(err)
			}
			// 132 => d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a
			//fmt.Printf("%d => %x\n", i, hx)
			b.Write(hx)
		}

		m := make(map[string]int32)
		end := aes.BlockSize
		nlines := bytes.Count(d, []byte{'\n'})
		allBlocks = make([][]byte, 0, nlines)
		for start := 0; start < b.Len(); start += aes.BlockSize {
			s := string(b.Bytes()[start:end])
			if _, ok := m[s]; !ok {
				m[s] = 0
			} else {
				m[s] += 1
			}
			allBlocks = append(allBlocks, b.Bytes()[start:end])
			end += aes.BlockSize
		}
		for k, v := range m {
			if v > 1 {
				fmt.Printf("candidate: %x => %d\n", k, v)
				candidate = k
			}
		}

		return candidate, allBlocks
	}

	candidate, allBlocks := allCiphers()

	joinedBlocks := bytes.Join(allBlocks, []byte(""))
	_ = joinedBlocks
	// candidate: 08649af70dc06f4fd5d2d69c744cd283 => 3

	candidateBlock, err := aes.NewCipher([]byte(candidate))
	if err != nil {
		panic(err)
	}

	//end := aes.BlockSize
	decrypted := make([]byte, len(allBlocks))
	//for start := 0; start < len(joinedBlocks); start += aes.BlockSize {
	//	candidateBlock.Decrypt(decrypted[start:end], joinedBlocks[start:end])
	//	end += aes.BlockSize
	//}
	//fmt.Printf("%s\n", decrypted)

	fmt.Printf("%c\n", []byte(candidate))

	for _, block := range allBlocks {
		//dec := cipher.NewCBCDecrypter(candidateBlock, block)
		//dec.CryptBlocks(block, block)
		//num := bytes.Count(joinedBlocks, block)
		//fmt.Printf("%x => %d \n", block, num)
		candidateBlock.Decrypt(decrypted, block)
		//fmt.Printf("%s\n", decrypted)
	}

	// ??? is this it ???
	// 08649af70dc06f4fd5d2d69c744cd283 => 4
	// e2dd052f6b641dbf9d11b0348542bb57 => 1
	// 08649af70dc06f4fd5d2d69c744cd283 => 4
	// 9475c9dfdbc1d46597949d9c7e82bf5a => 1
	// 08649af70dc06f4fd5d2d69c744cd283 => 4
	// 97a93eab8d6aecd566489154789a6b03 => 1
	// 08649af70dc06f4fd5d2d69c744cd283 => 4
	//
	// NOTE: line 132 is the line that has all these hexes and our 08649af70dc06f4fd5d2d69c744cd283
	fmt.Println(len(decrypted))
}
