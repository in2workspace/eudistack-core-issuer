package es.in2.issuer.backend.signing.domain.spi;

import es.in2.issuer.backend.signing.domain.onboarding.PreparedOnboarding;

/**
 * Where {@code prepare} leaves what the customer and the later {@code import} need. Nothing written
 * here is secret: the customer wraps its private key with the public key, and the import token is
 * useless without the wrapped material.
 */
public interface OnboardingArtifactsPort {

    /**
     * @param prepared             the state {@code import} reads back
     * @param wrappingPublicKeyDer DER SubjectPublicKeyInfo to wrap the private key with
     * @param importToken          token that goes with the wrapped key material
     */
    void write(PreparedOnboarding prepared, byte[] wrappingPublicKeyDer, byte[] importToken);
}
