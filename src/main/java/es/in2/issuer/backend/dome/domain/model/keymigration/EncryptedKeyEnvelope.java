package es.in2.issuer.backend.dome.domain.model.keymigration;

public record EncryptedKeyEnvelope(byte[] ciphertext, String wrappingAlgorithm, String importToken) {

    @Override
    public String toString() {
        return "EncryptedKeyEnvelope[ciphertext=REDACTED, wrappingAlgorithm=" + wrappingAlgorithm + "]";
    }
}

