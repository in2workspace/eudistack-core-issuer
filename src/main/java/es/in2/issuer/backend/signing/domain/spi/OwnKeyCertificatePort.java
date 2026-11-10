package es.in2.issuer.backend.signing.domain.spi;

import reactor.core.publisher.Mono;

/**
 * Where infra publishes the certificate of each own-key tenant. The Issuer only reads it.
 */
public interface OwnKeyCertificatePort {

    /**
     * @param tenant tenant id, without environment suffix (for example {@code cgcom})
     * @return the current certificate chain of the tenant in PEM, leaf first and root excluded, or empty
     *         when the tenant has none
     */
    Mono<String> findCertificateChainPem(String tenant);
}
