package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.AccessTokenContext;
import es.in2.issuer.backend.shared.domain.model.dto.OrgContext;
import reactor.core.publisher.Mono;

public interface AccessTokenService {
    Mono<String> getCleanBearerToken(String authorizationHeader);
    Mono<String> getOrganizationId(String authorizationHeader);
    Mono<OrgContext> getOrganizationContext(String authorizationHeader);
    Mono<String> getOrganizationIdFromCurrentSession();
    Mono<AccessTokenContext> resolveAccessTokenContext(String authorizationHeader);

}
