# Mosaic Cipher

A toy cipher implementation with encryption/decryption capabilities across multiple programming languages. Mosaic obfuscates messages using noise insertion, rotating Base47 encoding, and checksum validation.

⚠️ **Important:** This is **not cryptographically secure**. Use it for education, experimentation, and fun only.

---

## What Makes Mosaic Unique?

- **Interactive CLI shell** with `mosaic>` prompt for easy encryption/decryption
- **Noise obfuscation** using randomly inserted lowercase characters
- **Rotating Base47 alphabet** that shifts per block for added complexity
- **Built-in checksum validation** to detect corruption
- **Multi-language support** with decoders in Python, JavaScript, Java, Rust, C++, and Swift
- **Fast and portable** core implementation in C

---

## Quick Start

### Building the CLI

```bash
git clone https://github.com/DaRealPSL/mosaic-cipher.git
cd mosaic-cipher
make
./mosaicCipher
```

You'll be greeted with:

```
Welcome to Mosaic Cipher CLI!
mosaic>
```

Type `help` to see available commands.

### Basic Usage

**Encrypt a message:**
```bash
mosaic> encrypt "Hello, user! How are you doing?"
Encrypted: L$DAV@8%~Y^E^9CKZ~@9MEX*E%p~EDY-D1GA~^Q2NXT?_0~3W3WC_5M~&U?6$WCJ~~~E
```

**Decrypt it back:**
```bash
mosaic> decrypt "L$DAV@8%~Y^E^9CKZ~@9MEX*E%p~EDY-D1GA~^Q2NXT?_0~3W3WC_5M~&U?6$WCJ~~~E"
Decrypted: Hello, user! How are you doing?
```

**Exit:**
```bash
mosaic> exit
Goodbye!
```

---

## How It Works

### Encryption Process

1. **Input text** is converted to bytes
2. **Random noise** characters (a–z) are inserted between real data
3. **Base47 encoding** converts bytes using a rotating alphabet of symbols, numbers, and uppercase letters
4. **Blocks** are terminated with `~` and grouped with checksums every 4 blocks
5. **Trailer** (`~~X`) encodes padding information

### Decryption Process

1. **Filter noise** by removing lowercase letters
2. **Rotate alphabet** per block to reverse the encoding
3. **Convert** every 8 Base47 digits back into 5 raw bytes
4. **Verify checksums** to ensure integrity
5. **Remove padding** based on trailer information
6. **Apply XOR** with key if provided
7. **Output** as hex dump and UTF-8 text

---

## Multi-Language Decoder Suite

Mosaic includes decoder implementations in seven languages, making it accessible across different ecosystems:

### 🌍 Why Seven Languages?

Each language serves a specific use case:

- **Python** 🐍 — Quick scripting and prototyping, ideal for researchers
- **JavaScript** ⚡ — Browser and Node.js support for web integrations
- **Java** ☕ — Enterprise environments and JVM portability
- **Rust** 🦀 — Memory-safe, high-performance cryptographic work
- **C++** 💻 — System-level integration with modern features
- **Swift** 🍏 — Native Apple ecosystem (iOS/macOS) applications
- **C** ⚙️ — Core reference implementation, lightweight and portable

### Using the Decoders

All decoders follow the same interface:

```bash
# Python
python3 src/decrypt/python/decrypt.py 'L$DAV@8%~Y^E^9CKZ~...' 'optional-key'

# JavaScript
node src/decrypt/js/decrypt.js 'L$DAV@8%~Y^E^9CKZ~...' 'optional-key'

# Swift
swiftc -o decrypt_swift src/decrypt/swift/decrypt.swift
./decrypt_swift 'L$DAV@8%~Y^E^9CKZ~...' 'optional-key'
```

Each outputs:
- **Hex dump** of decoded bytes
- **UTF-8 text** representation (if valid)
- **Checksum verification** status

---

## Example Workflow

```bash
# Start the CLI
./mosaicCipher

# Encrypt with default settings
mosaic> encrypt "Secret message"
Encrypted: X8%LK~MN3@P~...

# Use Python decoder to verify
python3 src/decrypt/python/decrypt.py 'X8%LK~MN3@P~...'
# Output: Decoded text (utf-8): Secret message

# Try with a custom key
mosaic> encrypt "Classified" "mykey123"
# (Decrypt requires the same key)
```

---

## Advanced Features

- **Checksum validation** catches transmission errors
- **XOR key support** for an additional layer of obfuscation
- **Noise characters** make statistical analysis harder
- **Block rotation** prevents simple pattern matching
- **Cross-language verification** ensures implementation correctness

---

## Contributing

Found a bug or want to add another language implementation? Contributions are welcome! The cipher logic is consistent across all versions, making it straightforward to port to new languages.

---

## License

[MIT License](https://github.com/DaRealPSL/mosaic-cipher/blob/main/LICENSE) - Free to use, modify, and distribute.

---

> **Remember:** Never use this for actual security needs. For real encryption, use established standards like AES, RSA, or modern libraries.
