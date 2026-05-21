package es.in2.issuer.backend.dome.domain.model.keymigration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("EncryptedKeyEnvelope — security contract")
class EncryptedKeyEnvelopeTest {

    @Test
    @DisplayName("toString must not expose ciphertext bytes")
    void toString_MustNotExposeCiphertext() {
        // Arrange
        byte[] ciphertext = "super-secret-key-material".getBytes();
        String wrappingAlgorithm = "RSA_AES_KEY_WRAP_SHA_256_AES_256";
        String importToken = "sample-import-token";
        EncryptedKeyEnvelope envelope = new EncryptedKeyEnvelope(ciphertext, wrappingAlgorithm, importToken);

        String base64Encoded = Base64.getEncoder().encodeToString(ciphertext);
        String hexEncoded = bytesToHex(ciphertext);
        String rawString = new String(ciphertext);

        // Act
        String result = envelope.toString();

        // Assert
        assertThat(result)
                .doesNotContain(base64Encoded)
                .doesNotContain(hexEncoded)
                .doesNotContain(rawString)
                .contains("REDACTED")
                .contains(wrappingAlgorithm);
    }

    @Test
    @DisplayName("toString must include wrappingAlgorithm in output")
    void toString_MustIncludeWrappingAlgorithm() {
        // Arrange
        byte[] ciphertext = new byte[]{0x01, 0x02, 0x03};
        String wrappingAlgorithm = "RSA_AES_KEY_WRAP_SHA_1_AES_128";
        EncryptedKeyEnvelope envelope = new EncryptedKeyEnvelope(ciphertext, wrappingAlgorithm, "token");

        // Act
        String result = envelope.toString();

        // Assert
        assertThat(result).contains(wrappingAlgorithm);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

