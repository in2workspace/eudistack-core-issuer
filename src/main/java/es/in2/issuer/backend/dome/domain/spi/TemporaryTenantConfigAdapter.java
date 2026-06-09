package es.in2.issuer.backend.dome.domain.spi;

import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Temporary implementation of TenantConfigPort used by EUDISTACK-144.
 *
 * The DOME recovery workflow requires a TenantConfigPort bean, but the
 * real tenant configuration validation implementation is not available
 * in the current branch.
 *
 * This adapter acts as a temporary placeholder to allow Spring Boot
 * startup and local development.
 *
 * TODO: Remove this class once the real TenantConfigPort implementation isintegrated.
 */
@Component
public class TemporaryTenantConfigAdapter implements TenantConfigPort {

    @Override
    public Mono<Void> requireConfig(String tenant) {
        return Mono.empty();
    }
}