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
    f, err := os.Open("6.txt")
    if err != nil {
        t.Fatalf("%s", err)
    }
    defer f.Close()

    data, _ := io.ReadAll(f)
    based64, err := base64.StdEncoding.DecodeString(string(data))
    if err != nil {
        t.Fatalf("%s", err)
    }
    fmt.Println(len(based64))

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
        normals[ksize] = hamming(string(based64[:ksize]), string(based64[ksize:ksize*2])) / ksize
    }
    fmt.Printf("%#v\n", normals)

    keyRanges := func(length int) []int {
        r := make([]int, 0, 10)
        for i := 2; i < 40; i++ {
            if length % i == 0 {
                r = append(r, i)
            }
        }
        return r
    }
    fmt.Println(keyRanges(len(based64)))

    const keySize int = 2

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

    _ = toBlocks
    _ = transpose

    // for _, k := range keyRanges(len(data)) {
    tblock := transpose(keySize, toBlocks(keySize, string(based64)))
    for i := 0; i < keySize; i++ {
        // fmt.Printf("%x\n", tblock[i])
        cph, _ := cipher2(t, tblock[i], ascii) // NOTE: we are using cipher2 here
        _ = cph
        fmt.Printf("%c => %x\n", cph, SingleByteXOR(tblock[i], cph))
        // repeatingXOR[i] = cph
    }
    //     for i := 0; i < len(tblock); i++ {
    //         repeatingXOR := make([]byte, k)
    //         for i := 0; i < k; i++ {
    //             cph, _ := cipher(t, string(tblock[i]), ascii) // NOTE: we are using cipher2 here
    //             fmt.Printf("%c => %x\n", cph, SingleByteXOR(tblock[i], cph))
    //             repeatingXOR[i] = cph
    //         }
    //         // fmt.Printf("repeating XOR Key: %s\n", repeatingXOR)

    //         joined := bytes.Join(tblock, []byte(""))
    //         rpkxor := RepeatingKeyXOR(joined, repeatingXOR)
    //         decoded, err := base64.StdEncoding.DecodeString(string(rpkxor))
    //         if err != nil {
    //             t.Errorf("error: %s\n", err)
    //             continue
    //         }
    //         // _ = decoded

    //         // Printing both just in case
    //         fmt.Printf("%s\n", decoded)
    //     }
    // }
}
