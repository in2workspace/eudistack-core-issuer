package es.in2.issuer.backend.shared.infrastructure.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import es.in2.issuer.backend.shared.domain.exception.PayloadValidationException;
import es.in2.issuer.backend.shared.domain.service.PayloadSchemaValidator;
import es.in2.issuer.backend.shared.domain.util.sdjwt.SdJwtReservedClaims;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static es.in2.issuer.backend.shared.domain.util.Constants.DC_SD_JWT;
import static es.in2.issuer.backend.shared.domain.util.Constants.JWT_VC_JSON;

@Slf4j
@Service
public class PayloadSchemaValidatorImpl implements PayloadSchemaValidator {

    private static final String DIRECT_STRATEGY = "direct";

    private final CredentialProfileRegistry credentialProfileRegistry;
    private final JsonSchemaFactory schemaFactory;
    private final Map<String, PayloadSchema> schemaCache = new ConcurrentHashMap<>();

    public PayloadSchemaValidatorImpl(CredentialProfileRegistry credentialProfileRegistry) {
        this.credentialProfileRegistry = credentialProfileRegistry;
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
        JsonNode rawProfile = credentialProfileRegistry.getRawProfile(credentialConfigurationId);
        if (rawProfile == null) {
            return null;
        }

        var profile = credentialProfileRegistry.getByConfigurationId(credentialConfigurationId);
        String format = profile != null ? profile.format() : JWT_VC_JSON;
        boolean directSubject = profile != null && DIRECT_STRATEGY.equals(profile.credentialSubjectStrategy());
        boolean claimsAtRoot = DC_SD_JWT.equals(format) && directSubject;

        // W3C: properties.credentialSubject.properties.mandate
        // SD-JWT with direct subject: the profile root, as the claims sit at the top level
        // SD-JWT with mandate wrapper: properties.mandate
        JsonNode schemaNode;
        if (JWT_VC_JSON.equals(format)) {
            schemaNode = rawProfile.at("/properties/credentialSubject/properties/mandate");
        } else if (claimsAtRoot) {
            schemaNode = rawProfile;
        } else {
            schemaNode = rawProfile.at("/properties/mandate");
        }

        if (schemaNode.isMissingNode()) {
            log.warn("No payload schema found in profile '{}'", credentialConfigurationId);
            return null;
        }

        return new PayloadSchema(schemaFactory.getSchema(schemaNode), claimsAtRoot);
    }

    private record PayloadSchema(JsonSchema schema, boolean claimsAtRoot) {}
}
