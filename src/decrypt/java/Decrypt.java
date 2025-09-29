import java.util.*;

public class Decrypt {
    static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*_-?";
    static final String NOISE_SET = "abcdefghijklmnopqrstuvwxyz";
    static final char TERM = '~';
    static final int BASE = 47;
    static final int BLOCK_BYTES = 5;
    static final int BLOCK_SYMBOLS = 8;
    static final int CHECKSUM_PERIOD = 4;

    // reverse lookup map
    static Map<Character, Integer> buildRev(String alpha) {
        Map<Character, Integer> rev = new HashMap<>();
        for (int i = 0; i < alpha.length(); i++) {
            rev.put(alpha.charAt(i), i);
        }
        return rev;
    }

    static final Map<Character, Integer> REV_BASE = buildRev(ALPHABET);

    static int rotationForBlock(int blockIndex) {
        return ((blockIndex * 13) + 11) % BASE;
    }

    static String rotateAlpha(String alpha, int rot) {
        int n = alpha.length();
        rot = ((rot % n) + n) % n;
        StringBuilder sb = new StringBuilder(n);
        for (int i = 0; i < n; i++) {
            sb.append(alpha.charAt((i + rot) % n));
        }
        return sb.toString();
    }

    static byte[] base47DigitsTo5bytes(List<Integer> digits) {
        long val = 0;
        for (int d : digits) {
            val = val * BASE + d;
        }
        byte[] out = new byte[5];
        for (int i = 4; i >= 0; i--) {
            out[i] = (byte)(val & 0xFF);
            val >>= 8;
        }
        return out;
    }

    static int checksum47(List<byte[]> blocks) {
        int x = 0;
        for (byte[] b : blocks) {
            for (byte bb : b) {
                x ^= (bb & 0xFF);
            }
        }
        return x % BASE;
    }

    static byte[] decodeMosaic(String s) {
        int i = 0;
        int n = s.length();
        List<Byte> out = new ArrayList<>();
        int blockIndex = 0;
        List<byte[]> csWindows = new ArrayList<>();

        while (i < n) {
            // skip whitespace
            while (i < n && Character.isWhitespace(s.charAt(i))) i++;
            if (i >= n) break;

            // trailer detection
            if (i + 2 < n && s.charAt(i) == TERM && s.charAt(i + 1) == TERM) {
                char padChar = s.charAt(i + 2);
                if (!REV_BASE.containsKey(padChar)) {
                    throw new IllegalArgumentException("Invalid trailer pad digit: " + padChar);
                }
                int padCount = REV_BASE.get(padChar);
                if (padCount < 0 || padCount >= BLOCK_BYTES) {
                    throw new IllegalArgumentException("Invalid pad_count: " + padCount);
                }
                if (padCount > out.size()) {
                    throw new IllegalArgumentException("Pad mismatch");
                }
                for (int k = 0; k < padCount; k++) {
                    out.remove(out.size() - 1);
                }
                i += 3;
                if (i != n) {
                    throw new IllegalArgumentException("Extra data after trailer");
                }
                byte[] result = new byte[out.size()];
                for (int k = 0; k < out.size(); k++) result[k] = out.get(k);
                return result;
            }

            // rotated alphabet
            int rot = rotationForBlock(blockIndex);
            String rotated = rotateAlpha(ALPHABET, rot);
            Map<Character, Integer> revRot = buildRev(rotated);

            // read 8 digits
            List<Integer> digits = new ArrayList<>();
            for (int k = 0; k < BLOCK_SYMBOLS; k++) {
                while (i < n && NOISE_SET.indexOf(s.charAt(i)) != -1) i++;
                if (i >= n) throw new IllegalArgumentException("Unexpected end of input (digits)");
                char c = s.charAt(i);
                if (c == TERM) throw new IllegalArgumentException("Unexpected terminator");
                if (!revRot.containsKey(c)) {
                    throw new IllegalArgumentException("Invalid digit: " + c);
                }
                digits.add(revRot.get(c));
                i++;
            }

            while (i < n && NOISE_SET.indexOf(s.charAt(i)) != -1) i++;
            if (i >= n || s.charAt(i) != TERM) {
                throw new IllegalArgumentException("Missing block terminator");
            }
            i++;

            byte[] block5 = base47DigitsTo5bytes(digits);
            for (byte b : block5) out.add(b);

            csWindows.add(block5);
            if (csWindows.size() > CHECKSUM_PERIOD) {
                csWindows = csWindows.subList(csWindows.size() - CHECKSUM_PERIOD, csWindows.size());
            }

            blockIndex++;

            if (csWindows.size() == CHECKSUM_PERIOD) {
                while (i < n && NOISE_SET.indexOf(s.charAt(i)) != -1) i++;
                if (i >= n) throw new IllegalArgumentException("Missing checksum char");
                char chkChar = s.charAt(i++);
                if (!REV_BASE.containsKey(chkChar)) {
                    throw new IllegalArgumentException("Invalid checksum char: " + chkChar);
                }
                int got = REV_BASE.get(chkChar);
                int expect = checksum47(csWindows);
                if (got != expect) {
                    throw new IllegalArgumentException("Checksum mismatch: got " + got + " expect " + expect);
                }
                csWindows.clear();
            }
        }
        throw new IllegalArgumentException("No trailer found");
    }

    static byte[] xorWithKey(byte[] data, String key) {
        if (key == null || key.isEmpty()) return data;
        byte[] keyBytes = key.getBytes();
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte)(data[i] ^ keyBytes[i % keyBytes.length]);
        }
        return out;
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java Decrypt <ciphertext> [key]");
            System.exit(1);
        }
        String ciphertext = args[0];
        String key = args.length >= 2 ? args[1] : "";

        try {
            byte[] raw = decodeMosaic(ciphertext);
            raw = xorWithKey(raw, key);

            // print hex
            StringBuilder hex = new StringBuilder();
            for (byte b : raw) {
                hex.append(String.format("%02x", b));
            }
            System.out.println("Decoded bytes (hex): " + hex);

            try {
                String text = new String(raw, "UTF-8");
                System.out.println("Decoded text (utf-8): " + text);
            } catch (Exception e) {
                System.out.println("Decoded text: (not valid UTF-8)");
            }
        } catch (Exception e) {
            System.err.println("Decoding error: " + e.getMessage());
            System.exit(2);
        }
    }
}
