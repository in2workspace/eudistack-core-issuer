package es.in2.issuer.backend.shared.domain.util;

/**
 * Utility for Base45 encoding, as specified in RFC 9285.
 * <p>
 * Two input bytes are read big-endian as a single value in [0, 65535] and emitted
 * as three base-45 digits, least significant digit first. A trailing odd byte is
 * emitted as two digits, same ordering. Only encoding is implemented: the issuer
 * produces {@code CWT_VC} credentials but never consumes them.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9285.html">RFC 9285 — The Base45 Data Encoding</a>
 */
public final class Base45Codec {

    private static final char[] ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:".toCharArray();
    private static final int BASE = 45;
    private static final int PAIR_DIGITS = 3;
    private static final int SINGLE_DIGITS = 2;

    private Base45Codec() {
        throw new UnsupportedOperationException("Utility class");
    }

    /**
     * Encodes the given bytes as a Base45 string.
     *
     * @param input the bytes to encode; {@code null} or empty yields an empty string
     * @return the Base45 encoded string
     */
    public static String encode(byte[] input) {
        if (input == null || input.length == 0) {
            return "";
        }
        StringBuilder encoded = new StringBuilder(encodedLength(input.length));
        int index = 0;
        while (index + 1 < input.length) {
            int value = ((input[index] & 0xFF) << 8) + (input[index + 1] & 0xFF);
            appendDigits(encoded, value, PAIR_DIGITS);
            index += 2;
        }
        if (index < input.length) {
            appendDigits(encoded, input[index] & 0xFF, SINGLE_DIGITS);
        }
        return encoded.toString();
    }

    private static void appendDigits(StringBuilder target, int value, int digits) {
        int remaining = value;
        for (int i = 0; i < digits; i++) {
            target.append(ALPHABET[remaining % BASE]);
            remaining /= BASE;
        }
    }

    private static int encodedLength(int inputLength) {
        return (inputLength / 2) * PAIR_DIGITS + (inputLength % 2) * SINGLE_DIGITS;
    }

}
