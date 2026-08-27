package es.in2.issuer.backend.shared.domain.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Byte-for-byte regression of {@link Base45Codec} against fixtures captured out
 * of band. The corpus was produced by an independent implementation written from
 * RFC 9285 and validated against the RFC's own vectors before generating it, so a
 * silent behaviour change here fails the build even when the codec still looks
 * self-consistent.
 */
class Base45CodecGoldenVectorsTest {

    private static final int MINIMUM_CORPUS_SIZE = 200;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void encode_goldenCorpus_matchesTheCapturedOutput() throws IOException {
        JsonNode entries = readEntries("src/test/resources/fixtures/base45-golden-corpus.json");

        assertThat(entries).hasSizeGreaterThanOrEqualTo(MINIMUM_CORPUS_SIZE);
        for (JsonNode entry : entries) {
            String hexInput = entry.get("input").asText();

            assertThat(Base45Codec.encode(hexToBytes(hexInput)))
                    .as("hex input %s", hexInput)
                    .isEqualTo(entry.get("output").asText());
        }
    }

    @Test
    void encode_rfc9285KnownVectors_matchTheSpecification() throws IOException {
        JsonNode entries = readEntries("src/test/resources/fixtures/base45-known-vectors.json");

        for (JsonNode entry : entries) {
            String hexInput = entry.get("input").asText();

            assertThat(Base45Codec.encode(hexToBytes(hexInput)))
                    .as("RFC 9285 vector %s", entry.get("text").asText())
                    .isEqualTo(entry.get("output").asText());
        }
    }

    private JsonNode readEntries(String fixturePath) throws IOException {
        return objectMapper.readTree(new File(fixturePath)).get("entries");
    }

    private byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return bytes;
    }

}
