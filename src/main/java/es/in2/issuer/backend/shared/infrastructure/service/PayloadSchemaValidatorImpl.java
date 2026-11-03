package es.in2.issuer.backend.shared.infrastructure.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import es.in2.issuer.backend.shared.domain.exception.PayloadValidationException;
import es.in2.issuer.backend.shared.domain.service.PayloadSchemaValidator;
import es.in2.issuer.backend.shared.domain.util.sdjwt.SdJwtReservedClaims;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
public class PayloadSchemaValidatorImpl implements PayloadSchemaValidator {

    private final PayloadSubschemaResolver payloadSubschemaResolver;
    private final JsonSchemaFactory schemaFactory;
    private final Map<String, PayloadSchema> schemaCache = new ConcurrentHashMap<>();

    public PayloadSchemaValidatorImpl(PayloadSubschemaResolver payloadSubschemaResolver) {
        this.payloadSubschemaResolver = payloadSubschemaResolver;
        this.schemaFactory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012);
    }

    @Override
    public Mono<Void> validate(String credentialConfigurationId, JsonNode payload) {
        return Mono.fromCallable(() -> {
            PayloadSchema payloadSchema = schemaCache.computeIfAbsent(
                    credentialConfigurationId,
                    this::buildPayloadSchema
            );

            if (payloadSchema == null) {
                log.warn("No payload schema found for '{}', skipping payload validation", credentialConfigurationId);
                return null;
            }

            List<PayloadValidationException.Violation> violations = new ArrayList<>(
                    payloadSchema.schema().validate(payload).stream()
                            .map(e -> new PayloadValidationException.Violation(
                                    e.getInstanceLocation().toString(),
                                    e.getMessage()
                            ))
                            .toList());
            if (payloadSchema.claimsAtRoot()) {
                payload.fieldNames().forEachRemaining(name -> {
                    if (SdJwtReservedClaims.isReserved(name)) {
                        violations.add(new PayloadValidationException.Violation(
                                "$." + name, "'" + name + "' is a reserved claim name"));
                    }
                });
            }
            if (!violations.isEmpty()) {
                throw new PayloadValidationException(
                        "Payload validation failed for " + credentialConfigurationId, violations);
            }
            return null;
        }).then();
    }

    private PayloadSchema buildPayloadSchema(String credentialConfigurationId) {
        return payloadSubschemaResolver.resolve(credentialConfigurationId)
                .map(subschema -> new PayloadSchema(schemaFactory.getSchema(subschema.schema()), subschema.claimsAtRoot()))
                .orElse(null);
    }

    private record PayloadSchema(JsonSchema schema, boolean claimsAtRoot) {}
}
