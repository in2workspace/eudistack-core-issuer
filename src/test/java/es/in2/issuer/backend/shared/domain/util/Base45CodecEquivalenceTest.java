package es.in2.issuer.backend.shared.domain.util;

import nl.minvws.encoding.Base45;
import org.junit.jupiter.api.Test;

import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Before the EUPL-1.2 library leaves: {@link Base45Codec} writes exactly what it writes, so the signing of
 * {@code cwt_vc} does not change. Removed with the library.
 */
class Base45CodecEquivalenceTest {

    @Test
    void theCodecWritesWhatTheLibraryWrites() {
        Random random = new Random(45);
        for (int length = 0; length < 2048; length++) {
            byte[] bytes = new byte[length];
            random.nextBytes(bytes);
            assertThat(Base45Codec.encode(bytes)).as("length %d", length)
                    .isEqualTo(Base45.getEncoder().encodeToString(bytes));
        }
    }

    @Test
    void theCodecReadsWhatTheLibraryWrites() {
        Random random = new Random(9285);
        for (int length = 0; length < 2048; length++) {
            byte[] bytes = new byte[length];
            random.nextBytes(bytes);
            assertThat(Base45Codec.decode(Base45.getEncoder().encodeToString(bytes))).as("length %d", length)
                    .isEqualTo(bytes);
        }
    }
}
