package es.in2.issuer.backend.issuance.domain.service;

import reactor.core.publisher.Mono;

/** Which organizations belong to the tenant of the request (platform model MP-01, MP-09). */
public interface TenantOrganizationService {

    /**
     * Completes when {@code organizationIdentifier} is an organization of the tenant of the request, and
     * fails with {@code UnknownOrganizationException} when it is not (EUD-254 FR-12, AC-18).
     */
    Mono<Void> requireOrganizationOfTenant(String organizationIdentifier);
}
