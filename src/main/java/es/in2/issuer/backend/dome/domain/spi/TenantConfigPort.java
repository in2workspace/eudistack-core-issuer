package es.in2.issuer.backend.dome.domain.spi;

import reactor.core.publisher.Mono;

public interface TenantConfigPort {

    Mono<Void> requireConfig(String tenant);
}
