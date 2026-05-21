package es.in2.issuer.backend.dome.domain.model.keymigration;

/**
 * Holds an encrypted key envelope produced by a Vault transit export operation.
 * <p>
 * NFR-07: {@link #toString()} MUST NOT expose the raw ciphertext bytes.
 */
public record EncryptedKeyEnvelope(byte[] ciphertext, String wrappingAlgorithm, String importToken) {

    @Override
    public String toString() {
        return "EncryptedKeyEnvelope[ciphertext=REDACTED, wrappingAlgorithm=" + wrappingAlgorithm + "]";
    }
}

