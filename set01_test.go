package main

import (
    "io"
    "os"
    "strings"
    "fmt"
    "bufio"
    "encoding/hex"
    "encoding/base64"
    "testing"
    "bytes"
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
    if r, _ := HexToBase64(hex);  r != want {
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

func cipher2(t *testing.T, input []byte, ascii string) (byte, int) {
    var max int
    var result byte
    for i := range ascii {
        xored := SingleByteXOR(input, ascii[i])
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

func cipher(t *testing.T, input, ascii string) (byte, int) {
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

const ascii = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&()*+,-\\'./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c"

func TestSingleByteXOR(t *testing.T) {
    encoded := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    cph, _ := cipher(t, encoded, ascii)
    fmt.Printf("%s\n", SingleByteXOR(hexdec(t, encoded), cph))
}

func TestDetectSingleCharacterXOR(t *testing.T) {
    // NOTE: use http.Get("") instead?
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

    // NOTE: test our new scoring mechanism! use it instead in my cipher func?
    newScore := func(line []byte) int {
        nwords := len(bytes.Fields(line))
        nspace := bytes.Count(line, []byte(" "))
        nbytes := 0
        for i := range line {
            isAlpha := line[i] >= 'A' && line[i] <= 'Z' || line [i] >= 'a' && line[i] <= 'z'
            if isAlpha {
                nbytes += 1
            } else {
                nbytes -= 1
            }
        }
        return nbytes + nwords + nspace
    }
    _ = newScore([]byte(""))

    answer := struct {
        cipher byte
        score int
        lineNr int
    }{}

    lines := collectLines(t, f)
    for i, line := range lines {
        cph, max := cipher(t, line, ascii)
        if answer.score < max {
            answer.score = max
            answer.cipher = cph
            answer.lineNr = i
        }
    }
    fmt.Printf("%s", SingleByteXOR(hexdec(t, lines[answer.lineNr]), answer.cipher))
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
    ciphertext, err := os.Open("6.txt")
    if err != nil {
        t.Fatalf("%s", err)
    }
    defer ciphertext.Close()

    data, _ := io.ReadAll(ciphertext)
    data = bytes.ReplaceAll(data, []byte("\n"), []byte(""))

    a, b := "this is a test", "wokka wokka!!!"
    hamming := func(sa, sb string) int {
        diff := func(a, b byte) int {
            res := 0
            for i, c := 0, int(a ^ b) ; i < c; i++ {
                if c & (1<<i) != 0 {
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
    normals := make(map[int]int, max-min)
    for ksize := min; ksize < max+1; ksize++ {
        normals[ksize] = hamming(string(data[:ksize]), string(data[ksize:ksize*2])) / ksize
    }
    fmt.Printf("%#v\n", normals)

    const keySize int = 2

    // TODO: Need to try this soltion as well. This is basically taking text instead of lines and
    // breaking it down in to blocks.
        // >>> [x for x in range(1, 40) if 3900 % x == 0] <- including newline chars and EOF
        // [1, 2, 3, 4, 5, 6, 10, 12, 13, 15, 20, 25, 26, 30, 39]

        // >>> [x for x in range(1, 40) if 3836 % x == 0] <- excluding newline chars and EOF
        // [1, 2, 4, 7, 14, 28]

    // >>> [x for x in range(1,56) if 56 % x == 0] <- last line case where we fail on toBlocks
    // [1, 2, 4, 7, 8, 14, 28]

    // >>> [x for x in range(1,60) if 60 % x == 0]
    // [1, 2, 3, 4, 5, 6, 10, 12, 15, 20, 30]
    //        *     *             **
    // These are the values that pass without any errors at base64 DecodeString
    // used python3: len(input) % i == 0 to generate these values
    // our answer should be one of these values

    // Does this mean that the Key is 2?
    // map[int]int{2:2, 3:2, 6:2, 7:2, 15:2, 16:2, 20:2, 24:2, 28:2, 29:2}
    // map[int]int{2:2, 3:2, 4:3, 5:3, 6:2, 7:2, 8:3, 9:3, 10:3, 11:3, 12:3,
    // 13:3, 14:3, 15:2, 16:2, 17:3, 18:3, 19:3, 20:2, 21:3, 22:3, 23:3, 24:2,
    // 25:3, 26:3, 27:3, 28:2, 29:2, 30:3, 31:3, 32:3, 33:3, 34:3, 35:3, 36:3, 37:3, 38:3, 39:3, 40:3}

    // TODO: refactor into []byte
    toBlocks := func(ksize int, s string) []string {
        b := make([]string, 0, len(s)/ksize)
        for i := range s {
            if i % ksize == 0 {
                b = append(b, s[i:i+ksize])
            }
        }
        return b
    }

    // TODO: refactor into []byte
    transpose := func(ksize int, blocks []string) [][]byte {
        b := make([][]byte, 0, ksize) // ksize because we transpose?
        for i := 0; i < ksize; i++ {
            // There is a better way than using strings.Join here to
            // calculate desired size.
            tmp := make([]byte, 0, len(strings.Join(blocks, ""))/ksize)
            for j := range blocks {
                tmp = append(tmp, blocks[j][i])
            }
            b = append(b, tmp)
        }
        return b
    }
    fmt.Println(toBlocks(keySize, data))
    fmt.Printf("%s\n\n\n\n", transpose(keySize, toBlocks(keySize, data)))

    // 7. Solve each block as if it was single-character XOR.
    // You already have code to do this.
    // tblock := transpose(keySize, toBlocks(keySize, acph))
    // repeatingXOR := make([]byte, keySize)
    // for i := 0; i < keySize; i++ {
    //     // NOTE: not sure if we need to decode it now or not
    //     // decoded, err := base64.StdEncoding.DecodeString(string(tblock[i]))
    //     // if err != nil {
    //     //     t.Errorf("error: %s\n", err)
    //     // }
    //     // fmt.Printf("%x\n", decoded)
    //     cph, _ := cipher2(t, tblock[i], ascii) // NOTE: we are using cipher2 here
    //     // cph here is either cph or keySize
    //     fmt.Printf("%c => %x\n", cph, SingleByteXOR(tblock[i], cph))
    //     repeatingXOR[i] = cph
    // }

    // 8. For each block, the single-byte XOR key that produces the best
    // looking histogram is the repeating-key XOR key byte for that block.
    // Put them together and you have the key.

    // NOTE: I'm not sure what to use her. Either `tblock` or result from `SingleByteXOR`?
    // fmt.Printf("%s\n", repeatingXOR)
    // fmt.Printf("%x\n", RepeatingKeyXOR(bytes.Join(tblock, []byte("")), repeatingXOR))

    collectLines := func(t *testing.T, r io.Reader) []string {
        result := make([]string, 0, 65)
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

    lines := collectLines(t, ciphertext)
    for i, line := range lines {
        if i == 63 { // we are skipping the last line for now! reason? It breaks toBlocks for some reason.
            break
        }
        tblock := transpose(keySize, toBlocks(keySize, line))
        // fmt.Printf("%s\n", tblock)
        repeatingXOR := make([]byte, keySize)
        for i := 0; i < keySize; i++ {
            cph, _ := cipher2(t, tblock[i], ascii) // NOTE: we are using cipher2 here
            // fmt.Printf("%c => %x\n", cph, SingleByteXOR(tblock[i], cph))
            repeatingXOR[i] = cph
        }
        // fmt.Printf("repeating XOR Key: %s\n", repeatingXOR)

        joined := bytes.Join(tblock, []byte(""))
        decoded, err := base64.StdEncoding.DecodeString(string(joined))
        if err != nil {
            t.Errorf("error: %s\n", err)
        }

        _ = decoded

        // Printing both just in case
        // fmt.Printf("%s\n", decoded)
        // fmt.Printf("%s\n", RepeatingKeyXOR(joined, repeatingXOR))
    }
}
