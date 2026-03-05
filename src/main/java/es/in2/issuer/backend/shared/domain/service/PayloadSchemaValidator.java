package es.in2.issuer.backend.shared.domain.service;

import com.fasterxml.jackson.databind.JsonNode;
import reactor.core.publisher.Mono;

public interface PayloadSchemaValidator {
    Mono<Void> validate(String credentialConfigurationId, JsonNode payload);
}
