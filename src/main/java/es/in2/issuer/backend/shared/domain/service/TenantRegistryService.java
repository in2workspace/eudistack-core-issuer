package es.in2.issuer.backend.shared.domain.service;

import reactor.core.publisher.Mono;

import java.util.List;

public interface TenantRegistryService {

    Mono<List<String>> getActiveTenantSchemas();

}
