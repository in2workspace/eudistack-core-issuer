package es.in2.issuer.backend.shared.domain.policy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.util.DynamicCredentialParser;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.StreamSupport;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

/**
 * Creates a PolicyContext from a JWT token. This is the SINGLE place where token parsing happens.
 * Uses DynamicCredentialParser to extract fields via profile-driven paths.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class PolicyContextFactory {

    private final JWTService jwtService;
    private final ObjectMapper objectMapper;
    private final IssuerProperties appConfig;
    private final DynamicCredentialParser credentialParser;
    private final CredentialProfileRegistry credentialProfileRegistry;

    /**
     * Creates a PolicyContext from a JWT token for Issuance and StatusList PDPs.
     */
    public Mono<PolicyContext> fromTokenSimple(String token, String tenantDomain) {
        return Mono.fromCallable(() -> jwtService.parseJWT(token))
                .flatMap(signedJWT -> {
                    String vcClaim = jwtService.getClaimFromPayload(signedJWT.getPayload(), VC);
                    log.debug("VC claim: {}", vcClaim);

                    var parsed = credentialParser.parse(vcClaim);
                    List<Power> powers = credentialParser.extractPowers(parsed.node(), parsed.profile());
                    String orgId = credentialParser.extractOrganizationId(parsed.node(), parsed.profile());

                    log.info("User organization identifier: {}", orgId);

                    boolean isSysAdmin = orgId != null
                            && orgId.equals(appConfig.getAdminOrganizationId())
                            && hasOnboardingExecutePower(powers);

                    return Mono.just(new PolicyContext(
                            orgId,
                            powers,
                            parsed.node(),
                            parsed.profile(),
                            parsed.credentialType(),
                            isSysAdmin,
                            tenantDomain
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
                    String vcClaim = jwtService.getClaimFromPayload(signedJWT.getPayload(), VC);

                    return checkIfEmitterIsAllowedToIssue(vcClaim, credentialConfigurationId)
                            .map(resolvedType -> {
                                var parsed = credentialParser.parse(vcClaim);
                                List<Power> powers = credentialParser.extractPowers(parsed.node(), parsed.profile());
                                String orgId = credentialParser.extractOrganizationId(parsed.node(), parsed.profile());

                                boolean isSysAdmin = orgId != null
                                        && orgId.equals(appConfig.getAdminOrganizationId())
                                        && hasOnboardingExecutePower(powers);

                                return new PolicyContext(
                                        orgId,
                                        powers,
                                        parsed.node(),
                                        parsed.profile(),
                                        resolvedType,
                                        isSysAdmin,
                                        tenantDomain
                                );
                            });
                });
    }

    /**
     * Checks that the emitter's credential type is in the target profile's required_emitter_config_ids.
     * If no issuance_policy is defined, falls back to accepting any known credential type.
     */
    private Mono<String> checkIfEmitterIsAllowedToIssue(String vcClaim, String credentialConfigurationId) {
        try {
            JsonNode vcJsonNode = objectMapper.readTree(vcClaim);
            List<String> emitterTypes = extractCredentialTypes(vcJsonNode);

            CredentialProfile targetProfile = credentialProfileRegistry.getByConfigurationId(credentialConfigurationId);
            if (targetProfile != null && targetProfile.issuancePolicy() != null
                    && targetProfile.issuancePolicy().requiredEmitterConfigIds() != null) {
                return determineAllowedEmitterType(emitterTypes, targetProfile.issuancePolicy().requiredEmitterConfigIds(), credentialConfigurationId);
            }

            // Fallback: accept any known credential type from the emitter
            return findFirstKnownType(emitterTypes);
        } catch (Exception e) {
            return Mono.error(new InsufficientPermissionException("Error extracting credential type"));
        }
    }

    private Mono<String> determineAllowedEmitterType(List<String> emitterTypes, List<String> requiredEmitterConfigIds, String targetConfigId) {
        return Mono.fromCallable(() -> {
            for (String emitterType : emitterTypes) {
                if (requiredEmitterConfigIds.contains(emitterType)) {
                    return emitterType;
                }
            }
            throw new InsufficientPermissionException(
                    "Unauthorized: Emitter credential type " + emitterTypes + " is not allowed to issue " + targetConfigId
                            + ". Required: " + requiredEmitterConfigIds);
        });
    }

    private Mono<String> findFirstKnownType(List<String> types) {
        return Mono.fromCallable(() -> {
            for (String type : types) {
                if (!VERIFIABLE_CREDENTIAL.equals(type) && !VERIFIABLE_ATTESTATION.equals(type)) {
                    return type;
                }
            }
            throw new InsufficientPermissionException(
                    "Unauthorized: No recognized credential type found in emitter credential.");
        });
    }

    private List<String> extractCredentialTypes(JsonNode vcJsonNode) {
        JsonNode typeNode = vcJsonNode.get("type");
        if (typeNode == null) {
            throw new IllegalArgumentException(
                    "The credential type is missing, the credential is invalid.");
        }
        if (typeNode.isTextual()) {
            return List.of(typeNode.asText());
        } else if (typeNode.isArray()) {
            return StreamSupport.stream(typeNode.spliterator(), false)
                    .map(JsonNode::asText)
                    .toList();
        } else {
            throw new IllegalArgumentException("Invalid format for credential type.");
        }
    }

    private boolean hasOnboardingExecutePower(List<Power> powers) {
        return powers.stream().anyMatch(p ->
                "Onboarding".equals(p.function()) && PolicyContext.hasAction(p, "Execute"));
    }
}
