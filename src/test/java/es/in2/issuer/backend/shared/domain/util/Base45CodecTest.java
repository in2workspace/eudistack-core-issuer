package es.in2.issuer.backend.shared.domain.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class Base45CodecTest {

    private static final String ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

    @Test
    void constructor_invokedReflectively_throwsUnsupportedOperation() throws NoSuchMethodException {
        Constructor<Base45Codec> constructor = Base45Codec.class.getDeclaredConstructor();

        assertThat(Modifier.isPrivate(constructor.getModifiers())).isTrue();
        constructor.setAccessible(true);
        assertThatThrownBy(constructor::newInstance)
                .isInstanceOf(InvocationTargetException.class)
                .hasCauseInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void encode_emptyInput_returnsEmptyString() {
        assertThat(Base45Codec.encode(new byte[0])).isEmpty();
    }

    @Test
    void encode_nullInput_returnsEmptyString() {
        assertThat(Base45Codec.encode(null)).isEmpty();
    }

    /**
     * Normative vectors from RFC 9285 section 4.4. These pin the alphabet, the
     * big-endian reading of each byte pair and the least-significant-digit-first
     * ordering all at once: any of the three inverted breaks them.
     */
    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "AB      | BB8",
            "Hello!! | %69 VD92EX0",
            "base-45 | UJCLQE7W581",
            "ietf!   | QED8WEX0"
    })
    void encode_rfc9285Vector_matchesSpecification(String plainText, String expected) {
        byte[] input = plainText.trim().getBytes(StandardCharsets.US_ASCII);

        assertThat(Base45Codec.encode(input)).isEqualTo(expected);
    }

    @ParameterizedTest
    @CsvSource({
            "0x00, 00",
            "0xFF, U5",
            "0x2C, ':0'",
            "0x2D, 01"
    })
    void encode_singleByte_emitsTwoDigits(String byteValue, String expected) {
        byte[] input = {(byte) Integer.decode(byteValue).intValue()};

        assertThat(Base45Codec.encode(input)).isEqualTo(expected);
    }

    @Test
    void encode_maximumPairValue_emitsThreeDigits() {
        byte[] input = {(byte) 0xFF, (byte) 0xFF};

        assertThat(Base45Codec.encode(input)).isEqualTo("FGW");
    }

    @Test
    void encode_zeroPair_emitsThreeZeroDigits() {
        byte[] input = {0x00, 0x00};

        assertThat(Base45Codec.encode(input)).isEqualTo("000");
    }

    @Test
    void encode_arbitraryInput_emitsOnlyAlphabetCharacters() {
        Random random = new Random(20260827);

        for (int iteration = 0; iteration < 200; iteration++) {
            byte[] input = new byte[1 + random.nextInt(127)];
            random.nextBytes(input);

            String encoded = Base45Codec.encode(input);

            assertThat(encoded).as("iteration %d", iteration).isNotEmpty();
            assertThat(encoded.chars())
                    .as("iteration %d", iteration)
                    .allMatch(character -> ALPHABET.indexOf(character) >= 0);
        }
    }

    @Test
    void encode_arbitraryInput_lengthIsThreeDigitsPerPairPlusTwoForOddTail() {
        Random random = new Random(20260827);

        for (int length = 0; length < 128; length++) {
            byte[] input = new byte[length];
            random.nextBytes(input);

            String encoded = Base45Codec.encode(input);

            assertThat(encoded).hasSize(length / 2 * 3 + length % 2 * 2);
        }
    }

    @Test
    void encode_arbitraryInput_leavesTheInputArrayUntouched() {
        byte[] input = {0x01, 0x02, 0x03, 0x04, 0x05};
        byte[] pristine = Arrays.copyOf(input, input.length);

        Base45Codec.encode(input);

        assertThat(input).isEqualTo(pristine);
    }

    /**
     * Round-trips every encoding through a decoder written straight from RFC 9285
     * section 4.3. The decoder lives in test scope on purpose: production only
     * ever encodes, so shipping a decode method would be unused surface.
     */
    @Test
    void encode_arbitraryInput_roundTripsThroughTheReferenceDecoder() {
        Random random = new Random(1988);

        for (int iteration = 0; iteration < 200; iteration++) {
            byte[] input = new byte[random.nextInt(256)];
            random.nextBytes(input);

            byte[] decoded = referenceDecode(Base45Codec.encode(input));

            assertThat(decoded).as("iteration %d", iteration).isEqualTo(input);
        }
    }

    private static byte[] referenceDecode(String encoded) {
        byte[] decoded = new byte[encoded.length() / 3 * 2 + (encoded.length() % 3 == 2 ? 1 : 0)];
        int outputIndex = 0;
        int inputIndex = 0;
        while (encoded.length() - inputIndex >= 3) {
            int value = digit(encoded, inputIndex)
                    + digit(encoded, inputIndex + 1) * 45
                    + digit(encoded, inputIndex + 2) * 45 * 45;
            decoded[outputIndex++] = (byte) (value >>> 8);
            decoded[outputIndex++] = (byte) value;
            inputIndex += 3;
        }
        if (encoded.length() - inputIndex == 2) {
            decoded[outputIndex] = (byte) (digit(encoded, inputIndex) + digit(encoded, inputIndex + 1) * 45);
        }
        return decoded;
    }

    private static int digit(String encoded, int index) {
        int digit = ALPHABET.indexOf(encoded.charAt(index));
        if (digit < 0) {
            throw new IllegalArgumentException("Invalid character '" + encoded.charAt(index) + "' at index " + index);
        }
        return digit;
    }

}
