use std::collections::HashMap;
use std::env;
use std::process;

const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*_-?";
const NOISE_SET: &str = "abcdefghijklmnopqrstuvwxyz";
const TERM: char = '~';
const BASE: u32 = 47;
const BLOCK_BYTES: usize = 5;
const BLOCK_SYMBOLS: usize = 8;
const CHECKSUM_PERIOD: usize = 4;

fn build_rev(alpha: &str) -> HashMap<char, u32> {
    let mut rev = HashMap::new();
    for (i, ch) in alpha.chars().enumerate() {
        rev.insert(ch, i as u32);
    }
    rev
}

fn rotation_for_block(block_index: u32) -> u32 {
    (block_index * 13 + 11) % BASE
}

fn rotate_alpha(alpha: &str, rot: u32) -> String {
    let n = alpha.len() as u32;
    let rot = ((rot % n) + n) % n;
    alpha.chars().cycle().skip(rot as usize).take(n as usize).collect()
}

fn base47_digits_to_5bytes(digits: &[u32]) -> [u8; 5] {
    let mut val: u64 = 0;
    for &d in digits {
        val = val * BASE as u64 + d as u64;
    }
    let mut out = [0u8; 5];
    for i in (0..5).rev() {
        out[i] = (val & 0xFF) as u8;
        val >>= 8;
    }
    out
}

fn checksum47(blocks: &[[u8; 5]]) -> u32 {
    let mut x = 0u32;
    for block in blocks {
        for &b in block.iter() {
            x ^= b as u32;
        }
    }
    x % BASE
}

fn decode_mosaic(s: &str) -> Result<Vec<u8>, String> {
    let rev_base = build_rev(ALPHABET);
    let mut out: Vec<u8> = Vec::new();
    let mut cs_windows: Vec<[u8; 5]> = Vec::new();
    let mut block_index: u32 = 0;
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        // skip whitespace
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() { break; }

        // trailer detection
        if i + 2 < chars.len() && chars[i] == TERM && chars[i+1] == TERM {
            let pad_char = chars[i+2];
            let pad_count = *rev_base.get(&pad_char)
                .ok_or_else(|| format!("Invalid trailer pad digit: {}", pad_char))?;
            if pad_count as usize >= BLOCK_BYTES || pad_count > out.len() as u32 {
                return Err(format!("Invalid pad count: {}", pad_count));
            }
            out.truncate(out.len() - pad_count as usize);
            i += 3;
            if i != chars.len() { return Err("Extra data after trailer".into()); }
            return Ok(out);
        }

        let rot = rotation_for_block(block_index);
        let rotated = rotate_alpha(ALPHABET, rot);
        let rev_rot = build_rev(&rotated);

        // read digits
        let mut digits: Vec<u32> = Vec::new();
        for _ in 0..BLOCK_SYMBOLS {
            while i < chars.len() && NOISE_SET.contains(chars[i]) {
                i += 1;
            }
            if i >= chars.len() { return Err("Unexpected end of input".into()); }
            let c = chars[i];
            if c == TERM { return Err("Unexpected terminator".into()); }
            let digit = *rev_rot.get(&c)
                .ok_or_else(|| format!("Invalid digit character: {}", c))?;
            digits.push(digit);
            i += 1;
        }

        while i < chars.len() && NOISE_SET.contains(chars[i]) { i += 1; }
        if i >= chars.len() || chars[i] != TERM { return Err("Missing block terminator".into()); }
        i += 1;

        let block5 = base47_digits_to_5bytes(&digits);
        out.extend_from_slice(&block5);

        cs_windows.push(block5);
        if cs_windows.len() > CHECKSUM_PERIOD {
            cs_windows = cs_windows[cs_windows.len()-CHECKSUM_PERIOD..].to_vec();
        }

        block_index += 1;

        if cs_windows.len() == CHECKSUM_PERIOD {
            while i < chars.len() && NOISE_SET.contains(chars[i]) { i += 1; }
            if i >= chars.len() { return Err("Missing checksum character".into()); }
            let chk_char = chars[i];
            i += 1;
            let got = *rev_base.get(&chk_char)
                .ok_or_else(|| format!("Invalid checksum char: {}", chk_char))?;
            let expect = checksum47(&cs_windows);
            if got != expect { return Err(format!("Checksum mismatch: got {} expect {}", got, expect)); }
            cs_windows.clear();
        }
    }
    Err("No trailer found; malformed input".into())
}

fn xor_with_key(data: &[u8], key: &str) -> Vec<u8> {
    if key.is_empty() { return data.to_vec(); }
    let key_bytes = key.as_bytes();
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key_bytes[i % key_bytes.len()])
        .collect()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <ciphertext> [key]", args[0]);
        process::exit(1);
    }
    let ciphertext = &args[1];
    let key = if args.len() >= 3 { &args[2] } else { "" };

    match decode_mosaic(ciphertext) {
        Ok(raw) => {
            let raw = xor_with_key(&raw, key);
            let hex: String = raw.iter().map(|b| format!("{:02x}", b)).collect();
            println!("Decoded bytes (hex): {}", hex);
            match String::from_utf8(raw.clone()) {
                Ok(text) => println!("Decoded text (utf-8): {}", text),
                Err(_) => println!("Decoded text: (not valid UTF-8)"),
            }
        }
        Err(e) => {
            eprintln!("Decoding error: {}", e);
            process::exit(2);
        }
    }
}
