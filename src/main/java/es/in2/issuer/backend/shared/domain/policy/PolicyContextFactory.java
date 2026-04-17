package es.in2.issuer.backend.shared.domain.policy;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialFormatException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;

/**
 * Creates a PolicyContext from a JWT access token with flat claims.
 * The access token contains top-level claims: credential_type, mandator, power, tenant.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class PolicyContextFactory {

    private static final String CREDENTIAL_TYPE_CLAIM = "credential_type";
    private static final String POWER_CLAIM = "power";
    private static final String MANDATOR_CLAIM = "mandator";
    private static final String ORG_ID_FIELD = "organizationIdentifier";
    private static final String TENANT_CLAIM = "tenant";

    private final JWTService jwtService;
    private final ObjectMapper objectMapper;
    private final IssuerProperties appConfig;
    private final CredentialProfileRegistry credentialProfileRegistry;
    private final TenantConfigService tenantConfigService;

    /**
     * Creates a PolicyContext from a JWT token for Issuance and StatusList PDPs.
     */
    public Mono<PolicyContext> fromTokenSimple(String token, String tenantDomain) {
        return Mono.fromCallable(() -> jwtService.parseJWT(token))
                .flatMap(signedJWT -> {
                    String credentialType = extractCredentialType(signedJWT.getPayload());
                    CredentialProfile profile = resolveProfile(credentialType);
                    List<Power> powers = extractPowers(signedJWT.getPayload());
                    String orgId = extractOrganizationId(signedJWT.getPayload());
                    String tokenTenant = extractTokenTenant(signedJWT.getPayload());
                    JsonNode credential = buildCredentialNode(signedJWT.getPayload());

                    log.info("User organization identifier: {}", orgId);

                    boolean isSysAdmin = hasSysAdminPower(powers);

                    return resolveTenantAdmin(orgId, powers)
                            .map(isTenantAdmin -> new PolicyContext(
                                    orgId, powers, credential, profile, credentialType,
                                    isSysAdmin, isTenantAdmin, tenantDomain, tokenTenant
                            ));
                });
    }

    /**
     * Creates a PolicyContext from a JWT token for IssuancePdpService.
     * Validates that the emitter's credential type is allowed to issue the target credential,
     * using the target profile's issuance_policy.required_emitter_config_ids.
     */
    public Mono<PolicyContext> fromTokenForIssuance(String token, String credentialConfigurationId, String tenantDomain) {
        return Mono.fromCallable(() -> jwtService.parseJWT(token))
                .flatMap(signedJWT -> {
                    String credentialType = extractCredentialType(signedJWT.getPayload());

                    return checkIfEmitterIsAllowedToIssue(credentialType, credentialConfigurationId)
                            .flatMap(resolvedType -> {
                                CredentialProfile profile = resolveProfile(credentialType);
                                List<Power> powers = extractPowers(signedJWT.getPayload());
                                String orgId = extractOrganizationId(signedJWT.getPayload());
                                String tokenTenant = extractTokenTenant(signedJWT.getPayload());
                                JsonNode credential = buildCredentialNode(signedJWT.getPayload());

                                boolean isSysAdmin = hasSysAdminPower(powers);

                                return resolveTenantAdmin(orgId, powers)
                                        .map(isTenantAdmin -> new PolicyContext(
                                                orgId, powers, credential, profile, resolvedType,
                                                isSysAdmin, isTenantAdmin, tenantDomain, tokenTenant
                                        ));
                            });
                });
    }

    /**
     * Extracts the credential_type claim from the token payload.
     * The claim is a plain string like "learcredential.employee.w3c.4".
     * getClaimFromPayload serializes via ObjectMapper, so strings come back with surrounding quotes.
     */
    private String extractCredentialType(com.nimbusds.jose.Payload payload) {
        String raw = jwtService.getClaimFromPayload(payload, CREDENTIAL_TYPE_CLAIM);
        return stripJsonQuotes(raw);
    }

    /**
     * Extracts the power array from the token payload and deserializes to List of Power.
     */
    private List<Power> extractPowers(com.nimbusds.jose.Payload payload) {
        try {
            String powerJson = jwtService.getClaimFromPayload(payload, POWER_CLAIM);
            return objectMapper.readValue(powerJson, new TypeReference<>() {});
        } catch (Exception e) {
            log.debug("No power claim found in token or failed to parse: {}", e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Extracts the organization identifier from the mandator claim.
     * The mandator is a JSON object with an organizationIdentifier field.
     */
    private String extractOrganizationId(com.nimbusds.jose.Payload payload) {
        try {
            String mandatorJson = jwtService.getClaimFromPayload(payload, MANDATOR_CLAIM);
            JsonNode mandatorNode = objectMapper.readTree(mandatorJson);
            JsonNode orgIdNode = mandatorNode.path(ORG_ID_FIELD);
            return orgIdNode.isMissingNode() || orgIdNode.isNull() ? null : orgIdNode.asText();
        } catch (Exception e) {
            log.debug("No mandator claim found in token or failed to parse: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Extracts the tenant claim from the token payload.
     * The verifier injects this claim based on the OIDC client's tenant configuration.
     */
    private String extractTokenTenant(com.nimbusds.jose.Payload payload) {
        try {
            String raw = jwtService.getClaimFromPayload(payload, TENANT_CLAIM);
            return stripJsonQuotes(raw);
        } catch (Exception e) {
            log.debug("No tenant claim found in token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Builds a JsonNode from the flat token claims to serve as the credential field in PolicyContext.
     * Includes credential_type, mandator, and power claims.
     */
    private JsonNode buildCredentialNode(com.nimbusds.jose.Payload payload) {
        ObjectNode node = objectMapper.createObjectNode();
        try {
            String credentialType = jwtService.getClaimFromPayload(payload, CREDENTIAL_TYPE_CLAIM);
            node.put(CREDENTIAL_TYPE_CLAIM, stripJsonQuotes(credentialType));
        } catch (Exception e) {
            // credential_type missing, leave empty
        }
        try {
            String mandatorJson = jwtService.getClaimFromPayload(payload, MANDATOR_CLAIM);
            node.set(MANDATOR_CLAIM, objectMapper.readTree(mandatorJson));
        } catch (Exception e) {
            // mandator missing, leave empty
        }
        try {
            String powerJson = jwtService.getClaimFromPayload(payload, POWER_CLAIM);
            node.set(POWER_CLAIM, objectMapper.readTree(powerJson));
        } catch (Exception e) {
            // power missing, leave empty
        }
        return node;
    }

    private CredentialProfile resolveProfile(String credentialType) {
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(credentialType);
        if (profile == null) {
            throw new InvalidCredentialFormatException(
                    "No profile found for credential type: " + credentialType);
        }
        return profile;
    }

    /**
     * Checks that the emitter's credential type is in the target profile's required_emitter_config_ids.
     * If no issuance_policy is defined, accepts the emitter type directly.
     */
    private Mono<String> checkIfEmitterIsAllowedToIssue(String emitterCredentialType, String credentialConfigurationId) {
        CredentialProfile targetProfile = credentialProfileRegistry.getByConfigurationId(credentialConfigurationId);
        if (targetProfile != null && targetProfile.issuancePolicy() != null
                && targetProfile.issuancePolicy().requiredEmitterConfigIds() != null) {
            List<String> required = targetProfile.issuancePolicy().requiredEmitterConfigIds();
            if (required.contains(emitterCredentialType)) {
                return Mono.just(emitterCredentialType);
            }
            return Mono.error(new InsufficientPermissionException(
                    "Unauthorized: Emitter credential type [" + emitterCredentialType
                            + "] is not allowed to issue " + credentialConfigurationId
                            + ". Required: " + required));
        }
        // No issuance policy restriction: accept the emitter type
        return Mono.just(emitterCredentialType);
    }

    /**
     * Strips surrounding JSON quotes from a serialized string value.
     * getClaimFromPayload returns "\"value\"" for string claims.
     */
    private String stripJsonQuotes(String value) {
        if (value != null && value.startsWith("\"") && value.endsWith("\"")) {
            return value.substring(1, value.length() - 1);
        }
        return value;
    }

    private Mono<Boolean> resolveTenantAdmin(String orgId, List<Power> powers) {
        if (orgId == null) return Mono.just(false);
        boolean hasDomainPower = powers.stream().anyMatch(p ->
                "Onboarding".equals(p.function()) && PolicyContext.hasAction(p, "Execute"));
        if (!hasDomainPower) return Mono.just(false);

        return tenantConfigService.getStringOrDefault("admin_organization_id", appConfig.getAdminOrganizationId())
                .map(adminOrgId -> orgId.equals(adminOrgId));
    }

    private boolean hasSysAdminPower(List<Power> powers) {
        return powers.stream().anyMatch(p ->
                "organization".equals(p.type())
                && "EUDISTACK".equals(p.domain())
                && "System".equals(p.function())
                && PolicyContext.hasAction(p, "Administration"));
    }
}
