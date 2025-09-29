#!/usr/bin/env python3

import sys

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*_-?"
NOISE_SET = "abcdefghijklmnopqrstuvwxyz"
TERM = '~'
BASE = 47
BLOCK_BYTES = 5
BLOCK_SYMBOLS = 8
CHECKSUM_PERIOD = 4

def build_rev(alpha):
    return {ch: i for i, ch in enumerate(alpha)}

REV_BASE = build_rev(ALPHABET)

def rotation_for_block(block_index):
    return ((block_index * 13) + 11) % BASE

def rotate_alpha(alpha, rot):
    n = len(alpha)
    rot = rot % n
    return ''.join(alpha[(i + rot) % n] for i in range(n))

def base47_digits_to_5bytes(digits):
    val = 0
    for d in digits:
        val = val * BASE + d
    out = bytearray(BLOCK_BYTES)
    for i in range(BLOCK_BYTES - 1, -1, -1):
        out[i] = val & 0xFF
        val >>= 8
    return bytes(out)

def checksum47(blocks_bytes):
    x = 0
    for b in blocks_bytes:
        for byte in b:
            x ^= byte
    return x % BASE

def decode_mosaic(s):
    i = 0
    n = len(s)
    out = bytearray()
    block_index = 0
    cs_windows = []
    rev_base = REV_BASE

    while i < n:
        # skip whitespace
        while i < n and s[i].isspace():
            i += 1
        if i >= n:
            break

        # trailer: "~~" + paddigit
        if i + 2 < n and s[i] == TERM and s[i+1] == TERM:
            pad_char = s[i+2]
            if pad_char not in rev_base:
                raise ValueError("Invalid trailer pad digit: %r" % pad_char)
            pad_count = rev_base[pad_char]
            if pad_count < 0 or pad_count >= BLOCK_BYTES:
                raise ValueError("Invalid pad_count: %d" % pad_count)
            if pad_count:
                if len(out) < pad_count:
                    raise ValueError("Pad mismatch (output too small to trim)")
                out = out[:-pad_count]
            i += 3
            if i != n:
                raise ValueError("Extra data after trailer")
            return bytes(out)

        rot = rotation_for_block(block_index)
        rotated = rotate_alpha(ALPHABET, rot)
        rev_rot = build_rev(rotated)

        digits = []
        for k in range(BLOCK_SYMBOLS):
            while i < n and s[i] in NOISE_SET:
                i += 1
            if i >= n:
                raise ValueError("Unexpected end while reading digits")
            c = s[i]
            if c == TERM:
                raise ValueError("Unexpected terminator while expecting digit")
            if c not in rev_rot:
                raise ValueError("Invalid digit: %r" % c)
            digits.append(rev_rot[c])
            i += 1

        while i < n and s[i] in NOISE_SET:
            i += 1
        if i >= n or s[i] != TERM:
            raise ValueError("Missing block terminator after digits")
        i += 1

        block5 = base47_digits_to_5bytes(digits)
        out.extend(block5)

        cs_windows.append(block5)
        if len(cs_windows) > CHECKSUM_PERIOD:
            cs_windows = cs_windows[-CHECKSUM_PERIOD:]

        block_index += 1

        if len(cs_windows) == CHECKSUM_PERIOD:
            while i < n and s[i] in NOISE_SET:
                i += 1
            if i >= n:
                raise ValueError("Missing checksum character after block group")
            chk_char = s[i]; i += 1
            if chk_char not in rev_base:
                raise ValueError("Invalid checksum char: %r" % chk_char)
            got = rev_base[chk_char]
            expect = checksum47(cs_windows)
            if got != expect:
                raise ValueError("Checksum mismatch: got %d expect %d" % (got, expect))
            cs_windows = []

    raise ValueError("No trailer found; malformed input")

def xor_with_key(raw, key_bytes):
    if not key_bytes:
        return raw
    out = bytearray(len(raw))
    klen = len(key_bytes)
    for i, b in enumerate(raw):
        out[i] = b ^ key_bytes[i % klen]
    return bytes(out)

def main():
    if len(sys.argv) < 2:
        print("Usage: decrypt.py '<ciphertext>' [key]")
        return 1
    s = sys.argv[1]
    # if key omitted, use same fallback as C CLI
    key = sys.argv[2] if len(sys.argv) >= 3 else "default-key"

    try:
        raw = decode_mosaic(s)
    except Exception as e:
        print("Decoding error:", e)
        return 2

    raw = xor_with_key(raw, key.encode('utf-8'))

    print("Decoded bytes (hex):", raw.hex())
    try:
        text = raw.decode('utf-8')
        print("Decoded text (utf-8):", text)
    except Exception:
        # printable fallback
        printable = ''.join((chr(b) if 32 <= b <= 126 else "\\x%02x" % b) for b in raw)
        print("Decoded text:", printable)
    return 0

if __name__ == "__main__":
    sys.exit(main())
