package es.in2.issuer.backend.statuslist.domain.model;

/** A field of a revocation request that breaks the contract, and why. */
public record RevocationRequestViolation(String field, String message) {
}
