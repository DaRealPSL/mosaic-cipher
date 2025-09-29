// Usage:
//   go run mosaic_decode.go "<ciphertext>"
//   go run mosaic_decode.go "<ciphertext>" "<key>"
// or build:
//   go build -o mosaic_decode mosaic_decode.go
//   ./mosaic_decode "<ciphertext>" "<key>"

package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"
)

const (
	ALPHABET        = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*_-?"
	NOISE_SET       = "abcdefghijklmnopqrstuvwxyz"
	TERM            = '~'
	BASE            = 47
	BLOCK_BYTES     = 5
	BLOCK_SYMBOLS   = 8
	CHECKSUM_PERIOD = 4
)

// build reverse map for a given alphabet string
func buildRev(alpha string) map[rune]int {
	rev := make(map[rune]int, len(alpha))
	for i, r := range alpha {
		rev[r] = i
	}
	return rev
}

var REV_BASE = buildRev(ALPHABET)

func rotationForBlock(blockIndex int) int {
	return ((blockIndex * 13) + 11) % BASE
}

func rotateAlpha(alpha string, rot int) string {
	n := len(alpha)
	if n == 0 {
		return ""
	}
	rot = ((rot % n) + n) % n
	return alpha[rot:] + alpha[:rot]
}

// base47 digits (most significant first) to 5 bytes (big-endian)
func base47DigitsTo5Bytes(digits []int) ([]byte, error) {
	if len(digits) != BLOCK_SYMBOLS {
		return nil, fmt.Errorf("expected %d digits, got %d", BLOCK_SYMBOLS, len(digits))
	}
	var val uint64 = 0
	for _, d := range digits {
		if d < 0 || d >= BASE {
			return nil, fmt.Errorf("digit out of range: %d", d)
		}
		val = val*BASE + uint64(d)
	}
	out := make([]byte, BLOCK_BYTES)
	for i := BLOCK_BYTES - 1; i >= 0; i-- {
		out[i] = byte(val & 0xFF)
		val >>= 8
	}
	return out, nil
}

func checksum47(blocksBytes [][]byte) int {
	var x byte = 0
	for _, b := range blocksBytes {
		for _, bb := range b {
			x ^= bb
		}
	}
	return int(x) % BASE
}

func isNoise(ch rune) bool {
	return strings.ContainsRune(NOISE_SET, ch)
}

func decodeMosaic(s string) ([]byte, error) {
	i := 0
	n := len(s)
	out := make([]byte, 0, 256)
	blockIndex := 0
	csWindows := make([][]byte, 0, CHECKSUM_PERIOD)
	revBase := REV_BASE

	for i < n {
		// skip whitespace
		for i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r' || s[i] == '\f' || s[i] == '\v') {
			i++
		}
		if i >= n {
			break
		}

		// trailer detection: "~~" + one base47 digit
		if i+2 < n && s[i] == byte(TERM) && s[i+1] == byte(TERM) {
			padChar := rune(s[i+2])
			index, ok := revBase[padChar]
			if !ok {
				return nil, fmt.Errorf("invalid trailer pad digit: %q", string(padChar))
			}
			padCount := index
			if padCount < 0 || padCount >= BLOCK_BYTES {
				return nil, fmt.Errorf("invalid pad_count: %d", padCount)
			}
			if padCount != 0 {
				if len(out) < padCount {
					return nil, errors.New("pad mismatch (output too small to trim)")
				}
				out = out[:len(out)-padCount]
			}
			i += 3
			if i != n {
				return nil, errors.New("extra data after trailer")
			}
			return out, nil
		}

		// prepare rotated alphabet for this block
		rot := rotationForBlock(blockIndex)
		rotated := rotateAlpha(ALPHABET, rot)
		revRot := buildRev(rotated)

		// read BLOCK_SYMBOLS digits, skipping noise characters
		digits := make([]int, 0, BLOCK_SYMBOLS)
		for k := 0; k < BLOCK_SYMBOLS; k++ {
			// skip noise characters
			for i < n && isNoise(rune(s[i])) {
				i++
			}
			if i >= n {
				return nil, errors.New("unexpected end of input while reading digits")
			}
			c := rune(s[i])
			if c == TERM {
				return nil, errors.New("unexpected terminator while expecting digit")
			}
			val, ok := revRot[c]
			if !ok {
				return nil, fmt.Errorf("invalid digit character for rotated alphabet: %q", string(c))
			}
			digits = append(digits, val)
			i++
		}

		// after digits, skip inserted noise then expect terminator
		for i < n && isNoise(rune(s[i])) {
			i++
		}
		if i >= n || s[i] != byte(TERM) {
			return nil, errors.New("missing block terminator after digits")
		}
		i++ // consume terminator

		// convert digits -> 5 bytes
		block5, err := base47DigitsTo5Bytes(digits)
		if err != nil {
			return nil, fmt.Errorf("converting digits to bytes: %w", err)
		}
		out = append(out, block5...)

		// add to checksum window
		csWindows = append(csWindows, block5)
		if len(csWindows) > CHECKSUM_PERIOD {
			csWindows = csWindows[len(csWindows)-CHECKSUM_PERIOD:]
		}

		blockIndex++

		// if checksum is due (window full)
		if len(csWindows) == CHECKSUM_PERIOD {
			// skip noise before checksum char
			for i < n && isNoise(rune(s[i])) {
				i++
			}
			if i >= n {
				return nil, errors.New("missing checksum character after block group")
			}
			chkChar := rune(s[i])
			i++
			got, ok := revBase[chkChar]
			if !ok {
				return nil, fmt.Errorf("invalid checksum char: %q", string(chkChar))
			}
			expect := checksum47(csWindows)
			if got != expect {
				return nil, fmt.Errorf("checksum mismatch: got %d expect %d", got, expect)
			}
			csWindows = csWindows[:0] // reset window
		}
	}

	return nil, errors.New("no trailer found; malformed input")
}

func xorWithKey(raw []byte, key []byte) []byte {
	if len(key) == 0 {
		return raw
	}
	out := make([]byte, len(raw))
	klen := len(key)
	for i := range raw {
		out[i] = raw[i] ^ key[i%klen]
	}
	return out
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s '<ciphertext>' [key]\n", os.Args[0])
		os.Exit(1)
	}
	s := os.Args[1]

	// match Python/C behavior: if key not provided, use fallback "default-key"
	var key string
	if len(os.Args) >= 3 {
		key = os.Args[2]
	} else {
		key = "default-key"
	}

	raw, err := decodeMosaic(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Decoding error:", err)
		os.Exit(2)
	}

	raw = xorWithKey(raw, []byte(key))

	fmt.Println("Decoded bytes (hex):", hex.EncodeToString(raw))

	if utf8.Valid(raw) {
		fmt.Println("Decoded text (utf-8):", string(raw))
	} else {
		var buf bytes.Buffer
		for _, b := range raw {
			if b >= 32 && b <= 126 {
				buf.WriteByte(b)
			} else {
				buf.WriteString(fmt.Sprintf("\\x%02x", b))
			}
		}
		fmt.Println("Decoded text:", buf.String())
	}
}
