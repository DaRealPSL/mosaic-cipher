import Foundation

let ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*_-?"
let NOISE_SET = "abcdefghijklmnopqrstuvwxyz"
let TERM: UInt8 = UInt8(ascii: "~")
let BASE = 47
let BLOCK_BYTES = 5
let BLOCK_SYMBOLS = 8
let CHECKSUM_PERIOD = 4

let REV_BASE: [UInt8: Int] = {
    var rev: [UInt8: Int] = [:]
    for (i, ch) in ALPHABET.utf8.enumerated() { rev[ch] = i }
    return rev
}()

func rotationForBlock(_ blockIndex: Int) -> Int { (blockIndex * 13 + 11) % BASE }

func rotateAlpha(_ alpha: Data, rot: Int) -> Data {
    let n = alpha.count
    let r = ((rot % n) + n) % n
    return alpha[r...] + alpha[..<r]
}

func base47DigitsTo5Bytes(_ digits: [Int]) -> Data {
    var val: UInt64 = 0
    for d in digits { val = val * UInt64(BASE) + UInt64(d) }
    var out = Data(repeating: 0, count: BLOCK_BYTES)
    for i in stride(from: 4, through: 0, by: -1) { out[i] = UInt8(val & 0xFF); val >>= 8 }
    return out
}

func checksum47(_ blocks: [Data]) -> Int {
    blocks.flatMap { $0 }.reduce(0) { $0 ^ Int($1) } % BASE
}

func decodeMosaic(_ s: String) throws -> Data {
    var out = Data()
    var csWindows: [Data] = []
    var blockIndex = 0
    var bytes = Array(s.utf8)
    var i = 0

    while i < bytes.count {
        while i < bytes.count && NOISE_SET.contains(Character(UnicodeScalar(bytes[i]))) { i += 1 }
        if i == bytes.count { break }

        if i + 2 < bytes.count, bytes[i] == TERM, bytes[i+1] == TERM {
            let padChar = bytes[i+2]
            guard let padCount = REV_BASE[padChar], padCount <= out.count else {
                throw NSError(domain: "Invalid trailer or pad mismatch", code: 1)
            }
            if padCount > 0 { out.removeLast(padCount) }
            i += 3
            guard i == bytes.count else { throw NSError(domain: "Extra data after trailer", code: 1) }
            return out
        }

        let rotatedAlpha = rotateAlpha(Data(ALPHABET.utf8), rot: rotationForBlock(blockIndex))
        var revRot: [UInt8: Int] = [:]
        for (idx, ch) in rotatedAlpha.enumerated() { revRot[ch] = idx }

        var digits: [Int] = []
        for _ in 0..<BLOCK_SYMBOLS {
            while i < bytes.count && NOISE_SET.contains(Character(UnicodeScalar(bytes[i]))) { i += 1 }
            guard i < bytes.count, let digit = revRot[bytes[i]] else { throw NSError(domain: "Invalid digit", code: 1) }
            digits.append(digit)
            i += 1
        }

        while i < bytes.count && NOISE_SET.contains(Character(UnicodeScalar(bytes[i]))) { i += 1 }
        guard i < bytes.count, bytes[i] == TERM else { throw NSError(domain: "Missing block terminator", code: 1) }
        i += 1

        let block5 = base47DigitsTo5Bytes(digits)
        out.append(block5)

        csWindows.append(block5)
        if csWindows.count > CHECKSUM_PERIOD { csWindows.removeFirst(csWindows.count - CHECKSUM_PERIOD) }
        blockIndex += 1

        if csWindows.count == CHECKSUM_PERIOD {
            while i < bytes.count && NOISE_SET.contains(Character(UnicodeScalar(bytes[i]))) { i += 1 }
            guard i < bytes.count, let got = REV_BASE[bytes[i]] else { throw NSError(domain: "Invalid checksum", code: 1) }
            i += 1
            let expect = checksum47(csWindows)
            guard got == expect else { throw NSError(domain: "Checksum mismatch", code: 1) }
            csWindows.removeAll()
        }
    }

    throw NSError(domain: "No trailer found; malformed input", code: 1)
}

func main() {
    let args = CommandLine.arguments
    guard args.count >= 2 else {
        print("Usage: \(args[0]) <ciphertext> [key]")
        return
    }

    let ciphertext = args[1]
    let keyData = args.count >= 3 ? Data(args[2].utf8) : Data()

    do {
        var raw = try decodeMosaic(ciphertext)
        if !keyData.isEmpty {
            for i in 0..<raw.count { raw[i] ^= keyData[i % keyData.count] }
        }

        print("Decoded bytes (hex):", raw.map { String(format: "%02X", $0) }.joined())
        if let text = String(data: raw, encoding: .utf8) {
            print("Decoded text (utf-8):", text)
        } else {
            print("Decoded text: (not valid UTF-8)")
        }
    } catch {
        print("Decoding error:", error.localizedDescription)
    }
}

main()
