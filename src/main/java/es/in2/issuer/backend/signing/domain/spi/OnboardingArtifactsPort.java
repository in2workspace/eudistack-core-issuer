package es.in2.issuer.backend.signing.domain.spi;

import es.in2.issuer.backend.signing.domain.onboarding.PreparedOnboarding;

import java.time.Instant;

/**
 * Where {@code prepare} leaves what the customer and the later {@code import} need. Nothing written
 * here is secret: the customer wraps its private key with the public key, and the import token is
 * useless without the wrapped material.
 */
public interface OnboardingArtifactsPort {

    /**
     * @param prepared             the state {@code import} reads back
     * @param wrappingPublicKeyDer DER SubjectPublicKeyInfo to wrap the private key with; {@code null} on a renewal
     * @param importToken          token that goes with the wrapped key material; {@code null} on a renewal
     */
    void write(PreparedOnboarding prepared, byte[] wrappingPublicKeyDer, byte[] importToken);

    /** Marks the state of a preparation as consumed by a successful {@code import}, so that it is never used again. */
    void markImported(PreparedOnboarding prepared, Instant importedAt);

    /** Marks the state of a preparation as discarded, so that {@code import} refuses it. */
    void markDiscarded(PreparedOnboarding prepared, Instant discardedAt);

    /**
     * The state of a preparation as it is kept now, read again: another run may have marked it since the caller read
     * it. Read under the lock of the operation, it tells whether that run already imported or discarded it.
     */
    PreparedOnboarding current(PreparedOnboarding prepared);
}
