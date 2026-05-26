package es.in2.issuer.backend.dome.domain.spi;

import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * TODO: Temporary implementation to allow Spring Boot to start locally (EUDISTACK-144).
 * Since the real TenantConfigPort implementation is not present in this branch,
 * I use this dummy adapter as a fallback.
 * REMOVE this class once the real tenant validation code is integrated.
 */
@Component
public class DummyTenantConfigAdapter implements TenantConfigPort {

    @Override
    public Mono<Void> requireConfig(String tenant) {
        return Mono.empty();
    }
}