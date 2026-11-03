package es.in2.issuer.backend.shared.infrastructure.service;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Optional;

import static es.in2.issuer.backend.shared.domain.util.Constants.DC_SD_JWT;
import static es.in2.issuer.backend.shared.domain.util.Constants.JWT_VC_JSON;

/**
 * Single place that decides which part of a credential profile describes the business payload sent
 * to the issuance endpoint, so the validator and the normalizer always look at the same subschema.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class PayloadSubschemaResolver {

    private static final String DIRECT_STRATEGY = "direct";

    private final CredentialProfileRegistry credentialProfileRegistry;

    public Optional<PayloadSubschema> resolve(String credentialConfigurationId) {
        JsonNode rawProfile = credentialProfileRegistry.getRawProfile(credentialConfigurationId);
        if (rawProfile == null) {
            return Optional.empty();
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
            return Optional.empty();
        }

        return Optional.of(new PayloadSubschema(schemaNode, claimsAtRoot));
    }

    public record PayloadSubschema(JsonNode schema, boolean claimsAtRoot) {}
}
