package es.in2.issuer.backend.shared.domain.util;

import java.util.Arrays;

/**
 * Utility for Base58 encoding and decoding.
 * Follows Bitcoin alphabet and rules for leading zeros.
 *
 * @see <a href="https://en.wikipedia.org/wiki/Binary-to-text_encoding#Base58">Base58 Wikipedia</a>
 */
public final class Base58Codec {

    private static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
    private static final int[] INDEXES = new int[128];
    private static final int MAX_ENCODED_LENGTH = 1024;

    static {
        Arrays.fill(INDEXES, -1);
        for (int i = 0; i < ALPHABET.length; i++) {
            INDEXES[ALPHABET[i]] = i;
        }
    }

    private Base58Codec() {
        throw new UnsupportedOperationException("Utility class");
    }

    /**
     * Encodes the given bytes as a Base58 string.
     *
     * @param input the bytes to encode
     * @return the Base58 encoded string
     */
    public static String encode(byte[] input) {
        if (input == null || input.length == 0) {
            return "";
        }
        // Count leading zeros.
        int zeros = 0;
        while (zeros < input.length && input[zeros] == 0) {
            zeros++;
        }
        // Convert base.
        byte[] temp = Arrays.copyOf(input, input.length); // copy because divmod is destructive
        char[] encoded = new char[input.length * 2]; // upper bound
        int outputStart = encoded.length;
        for (int inputStart = zeros; inputStart < temp.length; ) {
            encoded[--outputStart] = ALPHABET[divmod(temp, inputStart, 256, 58)];
            if (temp[inputStart] == 0) {
                inputStart++;
            }
        }
        // Preserve leading zeros.
        while (outputStart < encoded.length && encoded[outputStart] == ALPHABET[0]) {
            outputStart++;
        }
        while (--zeros >= 0) {
            encoded[--outputStart] = ALPHABET[0];
        }
        return new String(encoded, outputStart, encoded.length - outputStart);
    }

    /**
     * Decodes the given Base58 string into bytes.
     *
     * @param input the Base58 string to decode
     * @return the decoded bytes
     * @throws IllegalArgumentException if the input is too long or contains invalid characters
     */
    public static byte[] decode(String input) {
        if (input == null || input.isEmpty()) {
            return new byte[0];
        }
        if (input.length() > MAX_ENCODED_LENGTH) {
            throw new IllegalArgumentException("Input too long");
        }
        // Count leading zeros.
        int zeros = 0;
        while (zeros < input.length() && input.charAt(zeros) == ALPHABET[0]) {
            zeros++;
        }
        // Convert base.
        byte[] decoded = new byte[input.length()];
        int outputStart = decoded.length;
        for (int i = zeros; i < input.length(); i++) {
            char c = input.charAt(i);
            int digit = c < 128 ? INDEXES[c] : -1;
            if (digit < 0) {
                throw new IllegalArgumentException("Invalid character '" + c + "' at index " + i);
            }
            int remainder = digit;
            for (int j = decoded.length - 1; j >= outputStart; j--) {
                int temp = (decoded[j] & 0xFF) * 58 + remainder;
                decoded[j] = (byte) (temp % 256);
                remainder = temp / 256;
            }
            while (remainder > 0) {
                decoded[--outputStart] = (byte) (remainder % 256);
                remainder /= 256;
            }
        }
        // Skip leading zeros in result (except those preserved by Base58 rule).
        while (outputStart < decoded.length && decoded[outputStart] == 0) {
            outputStart++;
        }
        return Arrays.copyOfRange(decoded, outputStart - zeros, decoded.length);
    }

    private static int divmod(byte[] number, int firstDigit, int base, int divisor) {
        int remainder = 0;
        for (int i = firstDigit; i < number.length; i++) {
            int digit = (int) number[i] & 0xFF;
            int temp = remainder * base + digit;
            number[i] = (byte) (temp / divisor);
            remainder = temp % divisor;
        }
        return remainder;
    }

}
