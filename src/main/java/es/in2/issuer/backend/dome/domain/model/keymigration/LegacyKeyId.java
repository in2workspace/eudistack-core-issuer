package es.in2.issuer.backend.dome.domain.model.keymigration;

public record LegacyKeyId(String value) {

    public LegacyKeyId {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("LegacyKeyId value must not be blank");
        }
        if (value.length() > 255) {
            throw new IllegalArgumentException("LegacyKeyId value must not exceed 255 characters");
        }
    }
}

