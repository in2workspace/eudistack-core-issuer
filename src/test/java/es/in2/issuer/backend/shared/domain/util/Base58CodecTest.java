package es.in2.issuer.backend.shared.domain.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class Base58CodecTest {

    @Test
    void testEmpty() {
        assertEquals("", Base58Codec.encode(new byte[0]));
        assertEquals(0, Base58Codec.decode("").length);
        assertEquals("", Base58Codec.encode(null));
        assertEquals(0, Base58Codec.decode(null).length);
    }

    @Test
    void testRoundTrip() {
        Random random = new Random(42);
        for (int i = 0; i < 100; i++) {
            byte[] input = new byte[random.nextInt(100)];
            random.nextBytes(input);
            String encoded = Base58Codec.encode(input);
            byte[] decoded = Base58Codec.decode(encoded);
            assertArrayEquals(input, decoded, "Failed at iteration " + i);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"0", "O", "I", "l", "+", "/"})
    void testInvalidCharacters(String invalid) {
        assertThrows(IllegalArgumentException.class, () -> Base58Codec.decode(invalid));
    }

    @Test
    void testTooLong() {
        String longInput = "1".repeat(1025);
        assertThrows(IllegalArgumentException.class, () -> Base58Codec.decode(longInput));
    }

    @Test
    void testLeadingZeros() {
        byte[] input = {0, 0, 1, 2, 3};
        String encoded = Base58Codec.encode(input);
        assertTrue(encoded.startsWith("11"));
        assertArrayEquals(input, Base58Codec.decode(encoded));
    }
}
