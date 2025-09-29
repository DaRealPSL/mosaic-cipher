#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <cctype>
#include <stdexcept>
#include <ranges>

constexpr std::string_view ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*_-?";
constexpr std::string_view NOISE_SET = "abcdefghijklmnopqrstuvwxyz";
constexpr char TERM = '~';
constexpr int BASE = 47;
constexpr size_t BLOCK_BYTES = 5;
constexpr size_t BLOCK_SYMBOLS = 8;
constexpr size_t CHECKSUM_PERIOD = 4;

auto build_rev(std::string_view alpha) {
    std::unordered_map<char, int> rev;
    for (size_t i = 0; i < alpha.size(); ++i) {
        rev[alpha[i]] = static_cast<int>(i);
    }
    return rev;
}

int rotation_for_block(int block_index) {
    return (block_index * 13 + 11) % BASE;
}

std::string rotate_alpha(std::string_view alpha, int rot) {
    int n = static_cast<int>(alpha.size());
    rot = ((rot % n) + n) % n;
    std::string rotated;
    rotated.reserve(alpha.size());
    for (int i = 0; i < n; ++i) rotated.push_back(alpha[(i + rot) % n]);
    return rotated;
}

std::vector<uint8_t> base47_digits_to_5bytes(const std::vector<int>& digits) {
    uint64_t val = 0;
    for (auto d : digits) val = val * BASE + static_cast<uint64_t>(d);
    std::vector<uint8_t> out(5);
    for (int i = 4; i >= 0; --i) {
        out[i] = val & 0xFF;
        val >>= 8;
    }
    return out;
}

int checksum47(const std::vector<std::vector<uint8_t>>& blocks) {
    int x = 0;
    for (auto const& block : blocks) 
        for (auto b : block) x ^= b;
    return x % BASE;
}

std::vector<uint8_t> decode_mosaic(std::string_view s) {
    auto rev_base = build_rev(ALPHABET);
    std::vector<uint8_t> out;
    std::vector<std::vector<uint8_t>> cs_windows;
    int block_index = 0;
    size_t i = 0;

    while (i < s.size()) {
        while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) i++;
        if (i >= s.size()) break;

        // trailer detection
        if (i + 2 < s.size() && s[i] == TERM && s[i+1] == TERM) {
            char pad_char = s[i+2];
            if (!rev_base.contains(pad_char)) throw std::runtime_error("Invalid trailer pad digit");
            int pad_count = rev_base[pad_char];
            if (pad_count < 0 || static_cast<size_t>(pad_count) > out.size()) throw std::runtime_error("Invalid pad count");
            out.resize(out.size() - pad_count);
            i += 3;
            if (i != s.size()) throw std::runtime_error("Extra data after trailer");
            return out;
        }

        int rot = rotation_for_block(block_index);
        auto rotated = rotate_alpha(ALPHABET, rot);
        auto rev_rot = build_rev(rotated);

        std::vector<int> digits;
        for (size_t k = 0; k < BLOCK_SYMBOLS; ++k) {
            while (i < s.size() && NOISE_SET.contains(s[i])) i++;
            if (i >= s.size()) throw std::runtime_error("Unexpected end of input");
            char c = s[i++];
            if (c == TERM) throw std::runtime_error("Unexpected terminator");
            if (!rev_rot.contains(c)) throw std::runtime_error("Invalid digit character");
            digits.push_back(rev_rot[c]);
        }

        while (i < s.size() && NOISE_SET.contains(s[i])) i++;
        if (i >= s.size() || s[i] != TERM) throw std::runtime_error("Missing block terminator");
        i++;

        auto block5 = base47_digits_to_5bytes(digits);
        out.insert(out.end(), block5.begin(), block5.end());

        cs_windows.push_back(block5);
        if (cs_windows.size() > CHECKSUM_PERIOD)
            cs_windows.erase(cs_windows.begin(), cs_windows.end() - CHECKSUM_PERIOD);

        block_index++;

        if (cs_windows.size() == CHECKSUM_PERIOD) {
            while (i < s.size() && NOISE_SET.contains(s[i])) i++;
            if (i >= s.size()) throw std::runtime_error("Missing checksum character");
            char chk_char = s[i++];
            if (!rev_base.contains(chk_char)) throw std::runtime_error("Invalid checksum char");
            int got = rev_base[chk_char];
            int expect = checksum47(cs_windows);
            if (got != expect) throw std::runtime_error("Checksum mismatch");
            cs_windows.clear();
        }
    }

    throw std::runtime_error("No trailer found; malformed input");
}

std::vector<uint8_t> xor_with_key(const std::vector<uint8_t>& data, std::string_view key) {
    if (key.empty()) return data;
    std::vector<uint8_t> out;
    out.reserve(data.size());
    for (size_t i = 0; i < data.size(); ++i)
        out.push_back(data[i] ^ static_cast<uint8_t>(key[i % key.size()]));
    return out;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <ciphertext> [key]\n";
        return 1;
    }

    std::string_view ciphertext = argv[1];
    std::string_view key = argc >= 3 ? argv[2] : "";

    try {
        auto raw = decode_mosaic(ciphertext);
        raw = xor_with_key(raw, key);

        std::cout << "Decoded bytes (hex): ";
        for (auto b : raw) std::cout << std::hex << std::uppercase << int(b);
        std::cout << "\n";

        std::string text(raw.begin(), raw.end());
        std::cout << "Decoded text (utf-8): " << text << "\n";
    } catch (std::exception& e) {
        std::cerr << "Decoding error: " << e.what() << "\n";
        return 2;
    }
    return 0;
}
