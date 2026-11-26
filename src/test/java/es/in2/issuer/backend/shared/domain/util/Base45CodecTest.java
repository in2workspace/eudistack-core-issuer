package es.in2.issuer.backend.shared.domain.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** RFC 9285: the examples of §4.3 and §4.4, the edges of each group and the text that is not Base45. */
class Base45CodecTest {

    /** RFC 9285 §4.3 (encoding) and §4.4 (decoding of "QED8WEX0"). */
    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "AB|BB8",
            "Hello!!|%69 VD92EX0",
            "base-45|UJCLQE7W581",
            "ietf!|QED8WEX0"})
    void theExamplesOfTheRfc_encodeAndDecode(String bytes, String text) {
        assertThat(Base45Codec.encode(bytes.getBytes(StandardCharsets.US_ASCII))).isEqualTo(text);
        assertThat(new String(Base45Codec.decode(text), StandardCharsets.US_ASCII)).isEqualTo(bytes);
    }

    @Test
    void noBytes_isNoText() {
        assertThat(Base45Codec.encode(new byte[0])).isEmpty();
        assertThat(Base45Codec.decode("")).isEmpty();
    }

    /** The largest value of each group: 0xFFFF is "FGW" and a last 0xFF is "U5". */
    @Test
    void theEdgesOfEachGroup() {
        assertThat(Base45Codec.encode(new byte[]{(byte) 0xFF, (byte) 0xFF})).isEqualTo("FGW");
        assertThat(Base45Codec.encode(new byte[]{(byte) 0xFF})).isEqualTo("U5");
        assertThat(Base45Codec.encode(new byte[]{0, 0})).isEqualTo("000");
        assertThat(Base45Codec.encode(new byte[]{0})).isEqualTo("00");
        assertThat(Base45Codec.decode("FGWU5")).containsExactly(0xFF, 0xFF, 0xFF);
    }

    @Test
    void anyBytes_comeBackAsTheyWere() {
        Random random = new Random(9285);
        for (int length = 0; length < 300; length++) {
            byte[] bytes = new byte[length];
            random.nextBytes(bytes);
            assertThat(Base45Codec.decode(Base45Codec.encode(bytes))).as("length %d", length).isEqualTo(bytes);
        }
    }

    /** RFC 9285 §6: "GGW" is 65536, which does not fit two bytes, and "::" is 2024, which does not fit one. */
    @ParameterizedTest
    @ValueSource(strings = {"GGW", "::", "000GGW", "000::"})
    void aGroupThatDoesNotFitItsBytes_isRefused(String text) {
        assertThatThrownBy(() -> Base45Codec.decode(text)).isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"0", "0000", "bb8", "BB#", "BBé", "BB\n"})
    void textThatIsNotBase45_isRefused(String text) {
        assertThatThrownBy(() -> Base45Codec.decode(text)).isInstanceOf(IllegalArgumentException.class);
    }
}
