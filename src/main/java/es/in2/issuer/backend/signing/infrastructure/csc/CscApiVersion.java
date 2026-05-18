package es.in2.issuer.backend.signing.infrastructure.csc;

import java.util.Arrays;
import java.util.Optional;

public enum CscApiVersion {

    V1("v1");

    private final String value;

    CscApiVersion(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static CscApiVersion fromValue(String value) {
        if (value == null || value.isBlank()) {
            return V1;
        }
        return Arrays.stream(values())
                .filter(v -> v.value.equalsIgnoreCase(value.trim()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unsupported CSC API version: " + value));
    }

    public static Optional<CscApiVersion> parseOptional(String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        return Arrays.stream(values())
                .filter(v -> v.value.equalsIgnoreCase(value.trim()))
                .findFirst();
    }
}
