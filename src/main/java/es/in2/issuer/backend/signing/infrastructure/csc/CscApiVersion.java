package es.in2.issuer.backend.signing.infrastructure.csc;

import lombok.Getter;

import java.util.Arrays;

@Getter
public enum CscApiVersion {

    V1("v2");

    private final String value;

    CscApiVersion(String value) {
        this.value = value;
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
}
