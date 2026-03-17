package es.in2.issuer.backend.shared.domain.policy.service;

import com.fasterxml.jackson.databind.JsonNode;
import reactor.core.publisher.Mono;

public interface IssuancePdpService {
    Mono<Void> authorize(String credentialConfigurationId, JsonNode payload, String idToken);

    /**
     * Validates tenant access for read-only endpoints (GET).
     * Runs RequireTenantMatchRule against the current security context and tenant domain.
     */
    Mono<Void> validateTenantAccess();
}
