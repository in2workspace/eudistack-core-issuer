package es.in2.issuer.backend.shared.domain.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class Base58CodecGoldenVectorsTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void testGoldenCorpus() throws IOException {
        JsonNode root = objectMapper.readTree(new File("src/test/resources/fixtures/base58-golden-corpus.json"));
        JsonNode entries = root.get("entries");
        for (JsonNode entry : entries) {
            byte[] input = hexToBytes(entry.get("input").asText());
            String expectedOutput = entry.get("output").asText();
            
            assertEquals(expectedOutput, Base58Codec.encode(input), "Encoding failed for hex: " + entry.get("input").asText());
            assertArrayEquals(input, Base58Codec.decode(expectedOutput), "Decoding failed for output: " + expectedOutput);
        }
    }

    @Test
    void testKnownVectors() throws IOException {
        JsonNode root = objectMapper.readTree(new File("src/test/resources/fixtures/base58-known-vectors.json"));
        JsonNode entries = root.get("entries");
        for (JsonNode entry : entries) {
            String hexInput = entry.get("input").asText();
            byte[] input = hexToBytes(hexInput);
            String expectedOutput = entry.get("output").asText();
            String actualOutput = Base58Codec.encode(input);
            System.out.println("[DEBUG_LOG] Input: " + hexInput + ", Expected: " + expectedOutput + ", Actual: " + actualOutput);
            assertEquals(expectedOutput, actualOutput, "Encoding failed for hex: " + hexInput);
            assertArrayEquals(input, Base58Codec.decode(expectedOutput), "Decoding failed for output: " + expectedOutput);
        }
    }

    private byte[] hexToBytes(String s) {
        int len = s.length();
        if (len == 0) return new byte[0];
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
