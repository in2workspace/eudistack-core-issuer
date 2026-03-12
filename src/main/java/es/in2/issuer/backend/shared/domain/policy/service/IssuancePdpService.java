package es.in2.issuer.backend.shared.domain.policy.service;

import com.fasterxml.jackson.databind.JsonNode;
import reactor.core.publisher.Mono;

public interface IssuancePdpService {
    Mono<Void> authorize(String credentialConfigurationId, JsonNode payload, String idToken);
}
