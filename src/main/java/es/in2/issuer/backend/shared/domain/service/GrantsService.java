package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.GrantsResult;
import reactor.core.publisher.Mono;

public interface GrantsService {

    Mono<GrantsResult> generateGrants(String processId, Mono<String> procedureIdMono);

}
