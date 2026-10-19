package es.in2.issuer.backend.shared.domain.model.enums;

/**
 * Holder binding a credential type requires, as far as a tenant's catalog can configure it.
 * Types needing any other binding (claim or biometric) are {@link #UNSUPPORTED}.
 */
public enum BindingType {
    KEY,
    NONE,
    UNSUPPORTED
}
