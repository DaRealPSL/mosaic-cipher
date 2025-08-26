#!/usr/bin/env python3

import sys

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*_-?"
NOISE_SET = "abcdefghijklmnopqrstuvwxyz"   # must be disjoint from ALPHABET
TERM = '~'
BASE = 47
BLOCK_BYTES = 5
BLOCK_SYMBOLS = 8
CHECKSUM_PERIOD = 4

def build_rev(alpha):
  rev = { }
  for i, ch in enumerate(alpha):
    rev[ch] = i
  return rev

REV_BASE = build_rev(ALPHABET)

def rotation_for_block(block_index):
  return ((block_index * 13) + 11) % BASE

def rotate_alpha(alpha, rot):
  n = len(alpha)
  rot = rot % n
  return ''.join(alpha[(i + rot) % n] for i in range(n))

def base47_digits_to_5bytes(digits):
  # digits: list of 8 integers (most significant first)
  val = 0
  for d in digits:
    val = val * BASE + d
  # produce 5 big-endian bytes
  out = bytearray(5)
  for i in range(4, -1, -1):
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
  cs_windows = []   # list of blocks (each 5-byte) in current checksum window
  rev_base = REV_BASE

  while i < n:
    # skip whitespace
    while i < n and s[i].isspace():
      i += 1
    if i >= n:
      break

    # trailer detection: "~~" + one base47 digit
    if i + 2 < n and s[i] == TERM and s[i+1] == TERM:
      pad_char = s[i+2]
      if pad_char not in rev_base:
        raise ValueError("Invalid trailer pad digit: %r" % pad_char)
      pad_count = rev_base[pad_char]
      if pad_count < 0 or pad_count >= BLOCK_BYTES:
        raise ValueError("Invalid pad_count: %d" % pad_count)
      # apply pad removal
      if pad_count:
        if len(out) < pad_count:
          raise ValueError("Pad mismatch (output too small to trim)")
        out = out[:-pad_count]
      i += 3
      # must be end of input after trailer
      if i != n:
        raise ValueError("Extra data after trailer")
      return bytes(out)

    # prepare rotated alphabet for this block
    rot = rotation_for_block(block_index)
    rotated = rotate_alpha(ALPHABET, rot)
    rev_rot = build_rev(rotated)

    # read BLOCK_SYMBOLS digits, skipping noise characters
    digits = []
    for k in range(BLOCK_SYMBOLS):
      # skip noise characters
      while i < n and s[i] in NOISE_SET:
        i += 1
      if i >= n:
        raise ValueError("Unexpected end of input while reading digits")
      c = s[i]
      if c == TERM:
        raise ValueError("Unexpected terminator while expecting digit")
      if c not in rev_rot:
        raise ValueError("Invalid digit character for rotated alphabet: %r" % c)
      digits.append(rev_rot[c])
      i += 1

    # after digits, skip inserted noise then expect terminator
    while i < n and s[i] in NOISE_SET:
      i += 1
    if i >= n or s[i] != TERM:
      raise ValueError("Missing block terminator after digits")
    i += 1  # consume terminator

    # convert digits -> 5 bytes
    block5 = base47_digits_to_5bytes(digits)
    out.extend(block5)

    # add to checksum window
    cs_windows.append(block5)
    if len(cs_windows) > CHECKSUM_PERIOD:
      cs_windows = cs_windows[-CHECKSUM_PERIOD:]

    block_index += 1

    # if checksum is due (i.e., we've just processed block number which makes window full)
    if len(cs_windows) == CHECKSUM_PERIOD:
      # skip noise before checksum char
      while i < n and s[i] in NOISE_SET:
        i += 1
      if i >= n:
        raise ValueError("Missing checksum character after block group")
      chk_char = s[i]
      i += 1
      if chk_char not in rev_base:
        raise ValueError("Invalid checksum char: %r" % chk_char)
      got = rev_base[chk_char]
      expect = checksum47(cs_windows)
      if got != expect:
        raise ValueError("Checksum mismatch: got %d expect %d" % (got, expect))
      # reset window
      cs_windows = []

  # If we exhaust without seeing trailer, fail
  raise ValueError("No trailer found; malformed input")

def main():
  if len(sys.argv) < 2:
    print("Usage: mosaic_decode.py '<ciphertext>'")
    return 1
  s = sys.argv[1]
  try:
    raw = decode_mosaic(s)
  except Exception as e:
    print("Decoding error:", e)
    return 2

  # print hex and printable text
  print("Decoded bytes (hex):", raw.hex())
  try:
    text = raw.decode('utf-8')
    print("Decoded text (utf-8):", text)
  except Exception:
    print("Decoded text: (not valid UTF-8)")

  return 0

if __name__ == "__main__":
  sys.exit(main())
