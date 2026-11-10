package es.in2.issuer.backend.signing.domain.service;

import es.in2.issuer.backend.signing.domain.model.OwnKeySigningConfig;
import reactor.core.publisher.Mono;

/**
 * Builds the own-key signing configuration of a tenant from the certificate infra publishes for it.
 */
public interface OwnKeySigningConfigLoader {

    /**
     * Must run in the Reactor context of the tenant: the organization the certificate must belong to is
     * read from that tenant's configuration.
     *
     * @param tenant tenant id of the request
     * @return the configuration; fails with {@code NO_CONFIGURATION} when the tenant has no certificate or
     *         its certificate belongs to another organization, and with {@code CERTIFICATE_INVALID} when the
     *         certificate cannot be used
     */
    Mono<OwnKeySigningConfig> load(String tenant);
}
