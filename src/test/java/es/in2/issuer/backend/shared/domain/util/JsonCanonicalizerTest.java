package es.in2.issuer.backend.shared.domain.util;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

class JsonCanonicalizerTest {

    @Test
    void sha256_sameHashForDifferentKeyOrder() {
        // Arrange
        String jsonA = "{\"b\":2,\"a\":1}";
        String jsonB = "{\"a\":1,\"b\":2}";

        // Act
        String hashA = JsonCanonicalizer.sha256(jsonA);
        String hashB = JsonCanonicalizer.sha256(jsonB);

        // Assert
        assertThat(hashA).isEqualTo(hashB);
    }

    @Test
    void sha256_sameHashRegardlessOfWhitespace() {
        // Arrange
        String compact  = "{\"a\":1,\"b\":2}";
        String withSpaces = "{ \"a\" : 1 , \"b\" : 2 }";

        // Act & Assert
        assertThat(JsonCanonicalizer.sha256(withSpaces))
                .isEqualTo(JsonCanonicalizer.sha256(compact));
    }

    @Test
    void sha256_nullInputReturnsEmptyStringHash() {
        // Arrange
        String expectedEmptyHash = JsonCanonicalizer.sha256("");

        // Act & Assert
        assertThatCode(() -> {
            String result = JsonCanonicalizer.sha256(null);
            assertThat(result).isEqualTo(expectedEmptyHash);
        }).doesNotThrowAnyException();
    }

    @Test
    void sha256_nestedObjectsAreDeterministic() {
        // Arrange
        String json = "{\"outer\":{\"z\":3,\"a\":1},\"first\":true}";

        // Act
        String hash1 = JsonCanonicalizer.sha256(json);
        String hash2 = JsonCanonicalizer.sha256(json);

        // Assert
        assertThat(hash1).isEqualTo(hash2);
    }

    @Test
    void canonicalize_rfc8785MinimalVector() throws Exception {
        // Arrange
        String input    = "{\"b\":2,\"a\":1}";
        String expected = "{\"a\":1,\"b\":2}";

        // Act
        String canonical = JsonCanonicalizer.canonicalize(input);

        // Assert
        assertThat(canonical).isEqualTo(expected);
    }
}

