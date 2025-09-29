#!/usr/bin/env node
// Usage: node decrypt.js "<ciphertext>" "<key>"
// If key omitted -> uses "default-key" to match the CLI fallback.

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*_-?";
const NOISE_SET = "abcdefghijklmnopqrstuvwxyz";
const TERM = '~';
const BASE = 47;
const BLOCK_BYTES = 5;
const BLOCK_SYMBOLS = 8;
const CHECKSUM_PERIOD = 4;

function buildRev(alpha) {
	const m = new Map();
	for (let i = 0; i < alpha.length; i++) m.set(alpha[i], i);
	return m;
}
const REV_BASE = buildRev(ALPHABET);

function rotationForBlock(blockIndex) {
	return ((blockIndex * 13) + 11) % BASE;
}

function rotateAlpha(alpha, rot) {
	const n = alpha.length;
	rot = ((rot % n) + n) % n;
	return alpha.slice(rot) + alpha.slice(0, rot);
}

function base47DigitsTo5Bytes(digits) {
	if (digits.length !== BLOCK_SYMBOLS) throw new Error("expected 8 digits");
	// Use BigInt to be safe
	let val = 0n;
	for (const d of digits) {
		if (d < 0 || d >= BASE) throw new Error("digit out of range");
		val = val * BigInt(BASE) + BigInt(d);
	}
	const out = Buffer.alloc(BLOCK_BYTES);
	for (let i = BLOCK_BYTES - 1; i >= 0; i--) {
		out[i] = Number(val & 0xFFn);
		val >>= 8n;
	}
	return out;
}

function checksum47(blocksBytes) {
	let x = 0;
	for (const b of blocksBytes) {
		for (const byte of b) x ^= byte;
	}
	return x % BASE;
}

function isNoise(ch) {
	return NOISE_SET.includes(ch);
}

function decodeMosaic(s) {
	let i = 0;
	const n = s.length;
	const outParts = [];
	let blockIndex = 0;
	let csWindows = [];
	const revBase = REV_BASE;

	while (i < n) {
		// skip whitespace
		while (i < n && /\s/.test(s[i])) i++;
		if (i >= n) break;

		// trailer detection: "~~" + one base47 digit
		if (i + 2 < n && s[i] === TERM && s[i + 1] === TERM) {
			const padChar = s[i + 2];
			if (!revBase.has(padChar)) throw new Error(`Invalid trailer pad digit: ${padChar}`);
			const padCount = revBase.get(padChar);
			if (padCount < 0 || padCount >= BLOCK_BYTES) throw new Error(`Invalid pad_count: ${padCount}`);
			// apply pad removal
			let assembled = Buffer.concat(outParts);
			if (padCount) {
				if (assembled.length < padCount) throw new Error("Pad mismatch (output too small to trim)");
				assembled = assembled.slice(0, assembled.length - padCount);
			}
			i += 3;
			if (i !== n) throw new Error("Extra data after trailer");
			return assembled;
		}

		const rot = rotationForBlock(blockIndex);
		const rotated = rotateAlpha(ALPHABET, rot);
		const revRot = buildRev(rotated);

		// read 8 digits skipping noise
		const digits = [];
		for (let k = 0; k < BLOCK_SYMBOLS; k++) {
			while (i < n && isNoise(s[i])) i++;
			if (i >= n) throw new Error("Unexpected end of input while reading digits");
			const c = s[i];
			if (c === TERM) throw new Error("Unexpected terminator while expecting digit");
			if (!revRot.has(c)) throw new Error(`Invalid digit character for rotated alphabet: ${c}`);
			digits.push(revRot.get(c));
			i++;
		}

		// skip noise then expect terminator
		while (i < n && isNoise(s[i])) i++;
		if (i >= n || s[i] !== TERM) throw new Error("Missing block terminator after digits");
		i++; // consume terminator

		const block5 = base47DigitsTo5Bytes(digits);
		outParts.push(block5);

		csWindows.push(block5);
		if (csWindows.length > CHECKSUM_PERIOD) csWindows = csWindows.slice(-CHECKSUM_PERIOD);

		blockIndex++;

		if (csWindows.length === CHECKSUM_PERIOD) {
			while (i < n && isNoise(s[i])) i++;
			if (i >= n) throw new Error("Missing checksum character after block group");
			const chkChar = s[i++];
			if (!revBase.has(chkChar)) throw new Error(`Invalid checksum char: ${chkChar}`);
			const got = revBase.get(chkChar);
			const expect = checksum47(csWindows);
			if (got !== expect) throw new Error(`Checksum mismatch: got ${got} expect ${expect}`);
			csWindows = [];
		}
	}

	throw new Error("No trailer found; malformed input");
}

function xorWithKey(rawBuf, keyBuf) {
	if (!keyBuf || keyBuf.length === 0) return rawBuf;
	const out = Buffer.alloc(rawBuf.length);
	for (let i = 0; i < rawBuf.length; i++) out[i] = rawBuf[i] ^ keyBuf[i % keyBuf.length];
	return out;
}

/* --- main --- */
function main() {
	const argv = process.argv.slice(2);
	if (argv.length < 1) {
		console.error("Usage: node mosaic_decode.js '<ciphertext>' [key]");
		process.exit(1);
	}
	const s = argv[0];
	const key = argv.length >= 2 ? argv[1] : "default-key";

	let raw;
	try {
		raw = decodeMosaic(s);
	} catch (e) {
		console.error("Decoding error:", e.message || e);
		process.exit(2);
	}

	const plain = xorWithKey(raw, Buffer.from(key, "utf8"));
	console.log("Decoded bytes (hex):", plain.toString("hex"));

	try {
		const text = plain.toString("utf8");
		// verify valid utf8 round-trip: Buffer -> string -> Buffer
		if (Buffer.from(text, "utf8").equals(plain)) {
			console.log("Decoded text (utf-8):", text);
		} else {
			throw new Error("not valid utf8");
		}
	} catch (_) {
		// escaped printable fallback
		let out = "";
		for (const b of plain) {
			if (b >= 32 && b <= 126) out += String.fromCharCode(b);
			else out += `\\x${b.toString(16).padStart(2, "0")}`;
		}
		console.log("Decoded text:", out);
	}
}

if (require.main === module) main();
