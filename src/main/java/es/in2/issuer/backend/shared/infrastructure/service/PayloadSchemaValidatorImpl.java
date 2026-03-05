package es.in2.issuer.backend.shared.infrastructure.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;
import es.in2.issuer.backend.shared.domain.exception.PayloadValidationException;
import es.in2.issuer.backend.shared.domain.service.PayloadSchemaValidator;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static es.in2.issuer.backend.shared.domain.util.Constants.JWT_VC_JSON;

@Slf4j
@Service
public class PayloadSchemaValidatorImpl implements PayloadSchemaValidator {

    private final CredentialProfileRegistry credentialProfileRegistry;
    private final JsonSchemaFactory schemaFactory;
    private final Map<String, JsonSchema> schemaCache = new ConcurrentHashMap<>();

    public PayloadSchemaValidatorImpl(CredentialProfileRegistry credentialProfileRegistry) {
        this.credentialProfileRegistry = credentialProfileRegistry;
        this.schemaFactory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012);
    }

    @Override
    public Mono<Void> validate(String credentialConfigurationId, JsonNode payload) {
        return Mono.fromCallable(() -> {
            JsonSchema mandateSchema = schemaCache.computeIfAbsent(
                    credentialConfigurationId,
                    this::buildMandateSchema
            );

            if (mandateSchema == null) {
                log.warn("No mandate schema found for '{}', skipping payload validation", credentialConfigurationId);
                return null;
            }

            Set<ValidationMessage> errors = mandateSchema.validate(payload);
            if (!errors.isEmpty()) {
                var violations = errors.stream()
                        .map(e -> new PayloadValidationException.Violation(
                                e.getInstanceLocation().toString(),
                                e.getMessage()
                        ))
                        .toList();
                throw new PayloadValidationException(
                        "Payload validation failed for " + credentialConfigurationId, violations);
            }
            return null;
        }).then();
    }

    private JsonSchema buildMandateSchema(String credentialConfigurationId) {
        JsonNode rawProfile = credentialProfileRegistry.getRawProfile(credentialConfigurationId);
        if (rawProfile == null) {
            return null;
        }

        var profile = credentialProfileRegistry.getByConfigurationId(credentialConfigurationId);
        String format = profile != null ? profile.format() : JWT_VC_JSON;

        // Extract the mandate sub-schema from the profile
        // W3C: properties.credentialSubject.properties.mandate
        // SD-JWT: properties.mandate
        JsonNode mandateSchemaNode;
        if (JWT_VC_JSON.equals(format)) {
            mandateSchemaNode = rawProfile.at("/properties/credentialSubject/properties/mandate");
        } else {
            mandateSchemaNode = rawProfile.at("/properties/mandate");
        }

        if (mandateSchemaNode.isMissingNode()) {
            log.warn("No mandate schema found in profile '{}'", credentialConfigurationId);
            return null;
        }

        return schemaFactory.getSchema(mandateSchemaNode);
    }
}
