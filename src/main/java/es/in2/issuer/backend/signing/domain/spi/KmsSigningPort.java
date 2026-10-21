package es.in2.issuer.backend.signing.domain.spi;

import reactor.core.publisher.Mono;

/**
 * Signs with an asymmetric key held in a KMS. Digest-only: the caller hashes (SHA-256) and the
 * KMS signs the digest with ECDSA_SHA_256 (MessageType=DIGEST). No user token or authorization
 * step is involved (AC-04). Failures surface as
 * {@link es.in2.issuer.backend.signing.domain.exception.KmsSigningException}.
 */
public interface KmsSigningPort {

    /**
     * @param keyRef       key identifier understood by the KMS (id, ARN or alias)
     * @param sha256Digest the 32-byte SHA-256 digest to sign
     * @return the ECDSA signature, ASN.1 DER encoded
     */
    Mono<byte[]> sign(String keyRef, byte[] sha256Digest);

    /**
     * @param keyRef key identifier understood by the KMS
     * @return the public key as DER SubjectPublicKeyInfo
     */
    Mono<byte[]> publicKey(String keyRef);
}
