package es.in2.issuer.backend.shared.domain.util;

import java.util.Arrays;
import java.util.Objects;

/**
 * Base45 encoding and decoding as RFC 9285 defines it: every two bytes are a number below 65536 written as three
 * characters of a 45-character alphabet, least significant first; a last single byte is two characters.
 *
 * <p>Replaces the EUPL-1.2 library the signing of {@code cwt_vc} used, as {@link Base58Codec} replaced a GPL one.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9285">RFC 9285, The Base45 Data Encoding</a>
 */
public final class Base45Codec {

    private static final char[] ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:".toCharArray();
    private static final int BASE = ALPHABET.length;
    private static final int BASE_SQUARED = BASE * BASE;
    private static final int[] VALUES = new int[128];

    static {
        Arrays.fill(VALUES, -1);
        for (int i = 0; i < ALPHABET.length; i++) {
            VALUES[ALPHABET[i]] = i;
        }
    }

    private Base45Codec() {
        throw new UnsupportedOperationException("Utility class");
    }

    /**
     * Encodes the given bytes as Base45.
     *
     * @param input the bytes to encode
     * @return the Base45 text, empty for no bytes
     */
    public static String encode(byte[] input) {
        Objects.requireNonNull(input, "input");
        StringBuilder text = new StringBuilder(input.length / 2 * 3 + input.length % 2 * 2);
        int pairs = input.length - input.length % 2;
        for (int i = 0; i < pairs; i += 2) {
            int value = (input[i] & 0xFF) << 8 | input[i + 1] & 0xFF;
            text.append(ALPHABET[value % BASE])
                    .append(ALPHABET[value / BASE % BASE])
                    .append(ALPHABET[value / BASE_SQUARED]);
        }
        if (pairs < input.length) {
            int value = input[pairs] & 0xFF;
            text.append(ALPHABET[value % BASE]).append(ALPHABET[value / BASE]);
        }
        return text.toString();
    }

    /**
     * Decodes Base45 text.
     *
     * @param text the Base45 text
     * @return the bytes it encodes
     * @throws IllegalArgumentException if a character is not in the alphabet, the length leaves a single character,
     *                                  or a group encodes a value that does not fit its bytes
     */
    public static byte[] decode(String text) {
        Objects.requireNonNull(text, "text");
        if (text.length() % 3 == 1) {
            throw new IllegalArgumentException("Base45 text cannot leave a single character");
        }
        byte[] bytes = new byte[text.length() / 3 * 2 + (text.length() % 3 == 2 ? 1 : 0)];
        int out = 0;
        int triplets = text.length() - text.length() % 3;
        for (int i = 0; i < triplets; i += 3) {
            int value = valueOf(text, i) + valueOf(text, i + 1) * BASE + valueOf(text, i + 2) * BASE_SQUARED;
            if (value > 0xFFFF) {
                throw new IllegalArgumentException("Base45 group at " + i + " does not fit two bytes");
            }
            bytes[out++] = (byte) (value >> 8);
            bytes[out++] = (byte) value;
        }
        if (triplets < text.length()) {
            int value = valueOf(text, triplets) + valueOf(text, triplets + 1) * BASE;
            if (value > 0xFF) {
                throw new IllegalArgumentException("Base45 group at " + triplets + " does not fit one byte");
            }
            bytes[out] = (byte) value;
        }
        return bytes;
    }

    private static int valueOf(String text, int index) {
        char character = text.charAt(index);
        int value = character < VALUES.length ? VALUES[character] : -1;
        if (value < 0) {
            throw new IllegalArgumentException("Not a Base45 character at " + index);
        }
        return value;
    }
}
