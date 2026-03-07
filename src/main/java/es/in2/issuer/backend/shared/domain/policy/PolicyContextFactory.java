package es.in2.issuer.backend.shared.domain.policy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.util.DynamicCredentialParser;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
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
     * The VC may be Employee or Machine type; the allowed type depends on the schema being issued.
     */
    public Mono<PolicyContext> fromTokenForIssuance(String token, String credentialType, String tenantDomain) {
        return Mono.fromCallable(() -> jwtService.parseJWT(token))
                .flatMap(signedJWT -> {
                    String vcClaim = jwtService.getClaimFromPayload(signedJWT.getPayload(), VC);

                    return checkIfCredentialTypeIsAllowedToIssue(vcClaim, credentialType)
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

    private Mono<String> checkIfCredentialTypeIsAllowedToIssue(String vcClaim, String credentialType) {
        try {
            JsonNode vcJsonNode = objectMapper.readTree(vcClaim);
            List<String> types = extractCredentialTypes(vcJsonNode);
            return determineAllowedCredentialType(types, credentialType);
        } catch (Exception e) {
            return Mono.error(new InsufficientPermissionException("Error extracting credential type"));
        }
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

    private Mono<String> determineAllowedCredentialType(List<String> types, String credentialType) {
        return Mono.fromCallable(() -> {
            if (LABEL_CREDENTIAL.equals(credentialType)) {
                if (types.contains(LEAR_CREDENTIAL_MACHINE)) {
                    return LEAR_CREDENTIAL_MACHINE;
                } else {
                    throw new InsufficientPermissionException(
                            "Unauthorized: Credential type 'LEARCredentialMachine' is required for verifiable certification.");
                }
            } else if (LEAR_CREDENTIAL_MACHINE.equals(credentialType)) {
                if (types.contains(LEAR_CREDENTIAL_EMPLOYEE)) {
                    return LEAR_CREDENTIAL_EMPLOYEE;
                } else {
                    throw new InsufficientPermissionException(
                            "Unauthorized: Credential type 'LEARCredentialEmployee' is required for LEARCredentialMachine.");
                }
            } else {
                if (types.contains(LEAR_CREDENTIAL_EMPLOYEE)) {
                    return LEAR_CREDENTIAL_EMPLOYEE;
                } else if (types.contains(LEAR_CREDENTIAL_MACHINE)) {
                    return LEAR_CREDENTIAL_MACHINE;
                } else {
                    throw new InsufficientPermissionException(
                            "Unauthorized: Credential type 'LEARCredentialEmployee' or 'LEARCredentialMachine' is required.");
                }
            }
        });
    }
}
