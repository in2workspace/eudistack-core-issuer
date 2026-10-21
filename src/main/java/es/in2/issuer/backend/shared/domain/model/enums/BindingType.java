package es.in2.issuer.backend.shared.domain.model.enums;

import java.util.Arrays;
import java.util.Optional;

/**
 * Holder binding of a credential type, with the values of {@code bindingType} of the Attestation
 * Registry (EUD-256). A tenant's catalog can configure only {@link #KEY} and {@link #NONE}; a type
 * needing {@link #CLAIM} or {@link #BIOMETRIC} binding is not {@link #isSupported() supported}.
 */
public enum BindingType {
    KEY("key"),
    NONE("none"),
    CLAIM("claim"),
    BIOMETRIC("biometric");

    public final String value;

    BindingType(String value) {
        this.value = value;
    }

    /** {@code true} for the bindings the issuer implements: a holder key, or no binding at all. */
    public boolean isSupported() {
        return this == KEY || this == NONE;
    }

    public static Optional<BindingType> fromValue(String value) {
        return Arrays.stream(values()).filter(type -> type.value.equals(value)).findFirst();
    }
}
