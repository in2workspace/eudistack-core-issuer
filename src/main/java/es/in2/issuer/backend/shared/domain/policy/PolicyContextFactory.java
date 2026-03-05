package es.in2.issuer.backend.shared.domain.policy;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.exception.ParseErrorException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.LEARCredential;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialMachineFactory;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.StreamSupport;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.util.Utils.extractPowers;

/**
 * Creates a PolicyContext from a JWT token. This is the SINGLE place where token parsing happens.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class PolicyContextFactory {

    private final JWTService jwtService;
    private final ObjectMapper objectMapper;
    private final IssuerProperties appConfig;
    private final LEARCredentialEmployeeFactory learCredentialEmployeeFactory;
    private final LEARCredentialMachineFactory learCredentialMachineFactory;

    /**
     * Creates a PolicyContext from a JWT token for Backoffice and StatusList PDPs.
     * These PDPs always expect a LEARCredentialEmployee in the VC claim.
     */
    public Mono<PolicyContext> fromTokenSimple(String token, String tenantDomain) {
        return Mono.fromCallable(() -> jwtService.parseJWT(token))
                .flatMap(signedJWT -> {
                    String vcClaim = jwtService.getClaimFromPayload(signedJWT.getPayload(), VC);
                    log.debug("VC claim: {}", vcClaim);

                    var learCredentialEmployee = learCredentialEmployeeFactory
                            .mapStringToLEARCredentialEmployee(vcClaim);

                    String orgId = learCredentialEmployee
                            .credentialSubject()
                            .mandate()
                            .mandator()
                            .organizationIdentifier();

                    log.info("User organization identifier: {}", orgId);

                    List<Power> powers = learCredentialEmployee
                            .credentialSubject()
                            .mandate()
                            .power();

                    boolean isSysAdmin = orgId.equals(appConfig.getAdminOrganizationId())
                            && hasOnboardingExecutePower(powers);

                    return Mono.just(new PolicyContext(
                            orgId,
                            powers,
                            learCredentialEmployee,
                            LEAR_CREDENTIAL_EMPLOYEE,
                            isSysAdmin,
                            tenantDomain
                    ));
                });
    }

    /**
     * Creates a PolicyContext from a JWT token for IssuancePdpService.
     * This handles the case where:
     * - The VC may be Employee or Machine type
     * - The allowed credential type depends on the schema being issued
     */
    public Mono<PolicyContext> fromTokenForIssuance(String token, String credentialType, String tenantDomain) {
        return Mono.fromCallable(() -> jwtService.parseJWT(token))
                .flatMap(signedJWT -> {
                    String vcClaim = jwtService.getClaimFromPayload(signedJWT.getPayload(), VC);

                    return checkIfCredentialTypeIsAllowedToIssue(vcClaim, credentialType)
                            .flatMap(resolvedType -> mapVcToLEARCredential(vcClaim, resolvedType)
                                    .map(credential -> {
                                        String orgId = resolveOrganizationIdentifier(credential);
                                        List<Power> powers = extractPowers(credential);
                                        boolean isSysAdmin = orgId != null
                                                && orgId.equals(appConfig.getAdminOrganizationId())
                                                && hasOnboardingExecutePower(powers);

                                        return new PolicyContext(
                                                orgId,
                                                powers,
                                                credential,
                                                resolvedType,
                                                isSysAdmin,
                                                tenantDomain
                                        );
                                    }));
                });
    }

    private String resolveOrganizationIdentifier(LEARCredential credential) {
        if (credential.type() != null && credential.type().contains(LEAR_CREDENTIAL_MACHINE)) {
            var m = es.in2.issuer.backend.shared.domain.util.Utils
                    .extractMandatorLearCredentialMachine(credential);
            return (m != null) ? m.organizationIdentifier() : null;
        } else {
            var m = es.in2.issuer.backend.shared.domain.util.Utils
                    .extractMandatorLearCredentialEmployee(credential);
            return (m != null) ? m.organizationIdentifier() : null;
        }
    }

    private Mono<LEARCredential> mapVcToLEARCredential(String vcClaim, String credentialType) {
        if (LEAR_CREDENTIAL_EMPLOYEE.equals(credentialType)) {
            return Mono.fromCallable(() ->
                    learCredentialEmployeeFactory
                            .mapStringToLEARCredentialEmployee(vcClaim));
        } else if (LEAR_CREDENTIAL_MACHINE.equals(credentialType)) {
            return Mono.fromCallable(() ->
                    learCredentialMachineFactory
                            .mapStringToLEARCredentialMachine(vcClaim));
        } else {
            return Mono.error(new InsufficientPermissionException(
                    "Unsupported credential type: " + credentialType));
        }
    }

    private Mono<String> checkIfCredentialTypeIsAllowedToIssue(String vcClaim, String credentialType) {
        return Mono.fromCallable(() -> objectMapper.readTree(vcClaim))
                .flatMap(vcJsonNode ->
                        extractCredentialTypes(vcJsonNode)
                                .flatMap(types -> determineAllowedCredentialType(types, credentialType))
                )
                .onErrorMap(JsonProcessingException.class,
                        e -> new ParseErrorException("Error extracting credential type"));
    }

    private Mono<List<String>> extractCredentialTypes(JsonNode vcJsonNode) {
        return Mono.fromCallable(() -> {
            JsonNode typeNode = vcJsonNode.get("type");
            if (typeNode == null) {
                throw new InsufficientPermissionException(
                        "The credential type is missing, the credential is invalid.");
            }
            if (typeNode.isTextual()) {
                return List.of(typeNode.asText());
            } else if (typeNode.isArray()) {
                return StreamSupport.stream(typeNode.spliterator(), false)
                        .map(JsonNode::asText)
                        .toList();
            } else {
                throw new InsufficientPermissionException("Invalid format for credential type.");
            }
        });
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
