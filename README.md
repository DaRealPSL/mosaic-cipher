# Mosaic Cipher

A toy cipher written in C with a full command-line interface (CLI) for encrypting and decrypting text.  
It obfuscates messages by inserting noise, structuring output, and adding checksums for integrity.

⚠️ **Note:** This is **not cryptographically secure**. Use it for fun, experimentation, and learning only.

---

## Features

- Interactive **CLI shell** (`mosaic>`) for encryption and decryption
- Random noise characters added for obfuscation
- Built-in checksum validation
- Implemented in C for speed and portability
- Python reference decoder included for cross-checking

---

## Build

Clone and build with `make`:

```bash
git clone https://github.com/DaRealPSL/mosaic-cipher.git
cd mosaic-cipher
make
````

This produces the binary `mosaicCipher`.

---

## Usage

### Start the CLI

```bash
./mosaicCipher
```

You’ll see:

```
Welcome to Mosaic Cipher CLI!
mosaic>
```

Type `help` for a list of commands.

---

### Encrypt

```bash
mosaic> encrypt "Hello, user! How are you doing?"
Encrypted: L$DAV@8%~Y^E^9CKZ~@9MEX*E%p~EDY-D1GA~^Q2NXT?_0~3W3WC_5M~&U?6$WCJ~~~E
```

---

### Decrypt

```bash
mosaic> decrypt "L$DAV@8%~Y^E^9CKZ~@9MEX*E%p~EDY-D1GA~^Q2NXT?_0~3W3WC_5M~&U?6$WCJ~~~E"
Decrypted: Hello, user! How are you doing?
```

---

### Exit the CLI

```bash
mosaic> exit
Goodbye!
```

---

## Python Decoder

A helper script `mosaic_decode.py` is included for verification:

```bash
python3 mosaic_decode.py 'L$DAV@8%~Y^E^9CKZ~@9MEX*E%p~EDY-D1GA~^Q2NXT?_0~3W3WC_5M~&U?6$WCJ~~~E'
```

Output:

```
Decoded text (utf-8): Hello, user! How are you doing?
```

---

## License

MIT License

