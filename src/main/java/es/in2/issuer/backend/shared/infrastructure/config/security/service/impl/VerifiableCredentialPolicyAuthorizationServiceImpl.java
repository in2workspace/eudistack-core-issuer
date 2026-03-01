package es.in2.issuer.backend.shared.infrastructure.config.security.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.exception.ParseErrorException;
import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.LEARCredential;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Mandator;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.machine.LEARCredentialMachine;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.machine.LEARCredentialMachine.CredentialSubject.Mandate;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyContextFactory;
import es.in2.issuer.backend.shared.domain.policy.PolicyEnforcer;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.domain.util.factory.CredentialFactory;
import es.in2.issuer.backend.shared.infrastructure.config.security.service.VerifiableCredentialPolicyAuthorizationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.List;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.LER;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.SYS_ADMIN;
import static es.in2.issuer.backend.shared.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.util.Utils.extractMandatorLearCredentialEmployee;
import static es.in2.issuer.backend.shared.domain.util.Utils.extractPowers;

@Service
@Slf4j
@RequiredArgsConstructor
public class VerifiableCredentialPolicyAuthorizationServiceImpl implements VerifiableCredentialPolicyAuthorizationService {

    private final PolicyContextFactory policyContextFactory;
    private final PolicyEnforcer policyEnforcer;
    private final ObjectMapper objectMapper;
    private final JWTService jwtService;
    private final CredentialFactory credentialFactory;
    private final VerifierService verifierService;

    @Override
    public Mono<Void> authorize(String token, String schema, JsonNode payload, String idToken) {
        return policyContextFactory.fromTokenForIssuance(token, schema)
                .flatMap(ctx -> {
                    String role = ctx.role();
                    if (role != null) {
                        return authorizeByRole(ctx, schema, payload, idToken);
                    } else {
                        return checkPolicies(ctx, schema, payload, idToken);
                    }
                });
    }

    private Mono<Void> authorizeByRole(PolicyContext ctx, String schema, JsonNode payload, String idToken) {
        String role = ctx.role();
        if (role == null || role.isBlank()) {
            return Mono.error(new UnauthorizedRoleException("Access denied: Role is empty"));
        }
        if (LABEL_CREDENTIAL.equals(schema)) {
            return Mono.error(new UnauthorizedRoleException("Access denied: Unauthorized Role '" + role + "'"));
        }
        return switch (role) {
            case SYS_ADMIN, LER -> Mono.error(new UnauthorizedRoleException("The request is invalid. " +
                    "The roles 'SYSADMIN' and 'LER' currently have no defined permissions."));
            case LEAR -> checkPolicies(ctx, schema, payload, idToken);
            default -> Mono.error(new UnauthorizedRoleException("Access denied: Unauthorized Role '" + role + "'"));
        };
    }

    private Mono<Void> checkPolicies(PolicyContext ctx, String schema, JsonNode payload, String idToken) {
        LEARCredential learCredential = ctx.credential();
        return switch (schema) {
            case LEAR_CREDENTIAL_EMPLOYEE -> authorizeLearCredentialEmployee(ctx, learCredential, payload);
            case LEAR_CREDENTIAL_MACHINE -> authorizeLearCredentialMachine(ctx, learCredential, payload);
            case LABEL_CREDENTIAL -> authorizeLabelCredential(learCredential, idToken);
            default -> Mono.error(new InsufficientPermissionException("Unauthorized: Unsupported schema"));
        };
    }

    private Mono<Void> authorizeLearCredentialEmployee(PolicyContext ctx, LEARCredential learCredential, JsonNode payload) {
        return policyEnforcer.enforceAny(ctx, payload,
                "Unauthorized: LEARCredentialEmployee does not meet any issuance policies.",
                (context, p) -> isSignerIssuancePolicyValid(context)
                        ? Mono.empty()
                        : Mono.error(new InsufficientPermissionException("Signer policy not met")),
                (context, p) -> isMandatorIssuancePolicyValid(context.credential(), p)
                        ? Mono.empty()
                        : Mono.error(new InsufficientPermissionException("Mandator policy not met"))
        );
    }

    private Mono<Void> authorizeLabelCredential(LEARCredential learCredential, String idToken) {
        return isVerifiableCertificationPolicyValid(learCredential, idToken)
                .flatMap(valid -> Boolean.TRUE.equals(valid)
                        ? Mono.empty()
                        : Mono.error(new InsufficientPermissionException("Unauthorized: VerifiableCertification does not meet the issuance policy.")));
    }

    private Mono<Void> authorizeLearCredentialMachine(PolicyContext ctx, LEARCredential learCredential, JsonNode payload) {
        return policyEnforcer.enforceAny(ctx, payload,
                "Unauthorized: LEARCredentialMachine does not meet any issuance policies.",
                (context, p) -> isSignerIssuancePolicyValid(context)
                        ? Mono.empty()
                        : Mono.error(new InsufficientPermissionException("Signer policy not met")),
                (context, p) -> isMandatorIssuancePolicyValidLEARCredentialMachine(context.credential(), p)
                        ? Mono.empty()
                        : Mono.error(new InsufficientPermissionException("Mandator policy not met"))
        );
    }

    // Checks if signer is admin org and has Onboarding/Execute power
    private boolean isSignerIssuancePolicyValid(PolicyContext ctx) {
        return ctx.sysAdmin() && ctx.hasPowerFunctionAndAction("Onboarding", "Execute");
    }

    private boolean isMandatorIssuancePolicyValid(LEARCredential learCredential, JsonNode payload) {
        if (!hasOnboardingExecutePower(extractPowers(learCredential))) {
            return false;
        }

        LEARCredentialEmployee.CredentialSubject.Mandate mandate = objectMapper.convertValue(payload, LEARCredentialEmployee.CredentialSubject.Mandate.class);
        return mandate != null &&
                mandate.mandator().organizationIdentifier().equals(extractMandatorLearCredentialEmployee(learCredential).organizationIdentifier())
                && payloadPowersOnlyIncludeProductOffering(mandate.power());
    }

    private boolean isMandatorIssuancePolicyValidLEARCredentialMachine(LEARCredential learCredential, JsonNode payload) {
        if (!hasOnboardingExecutePower(extractPowers(learCredential))) {
            return false;
        }
        LEARCredentialMachine.CredentialSubject.Mandate mandate = objectMapper.convertValue(payload, LEARCredentialMachine.CredentialSubject.Mandate.class);
        if (mandate == null) {
            return false;
        }
        final Mandator learCredentialMandator = extractMandatorLearCredentialEmployee(learCredential);
        final Mandate.Mandator payloadMandator = mandate.mandator();
        return payloadMandator.organization().equals(learCredentialMandator.organization()) &&
                payloadMandator.country().equals(learCredentialMandator.country()) &&
                payloadMandator.commonName().equals(learCredentialMandator.commonName()) &&
                payloadMandator.serialNumber().equals(learCredentialMandator.serialNumber()) &&
                payloadPowersOnlyIncludeOnboarding(mandate.power());
    }

    private Mono<Boolean> isVerifiableCertificationPolicyValid(LEARCredential learCredential, String idToken) {
        boolean credentialValid = containsCertificationAndAttest(extractPowers(learCredential));
        return validateIdToken(idToken)
                .map(learCredentialFromIdToken -> containsCertificationAndAttest(extractPowers(learCredentialFromIdToken)))
                .map(idTokenValid -> credentialValid && idTokenValid);
    }

    private Mono<LEARCredential> validateIdToken(String idToken) {
        return verifierService.verifyTokenWithoutExpiration(idToken)
                .then(Mono.fromCallable(() -> jwtService.parseJWT(idToken)))
                .flatMap(idSignedJWT -> {
                    String idVcClaim = jwtService.getClaimFromPayload(idSignedJWT.getPayload(), "vc_json");
                    try {
                        String processedVc = objectMapper.readValue(idVcClaim, String.class);
                        LEARCredentialEmployee credentialEmployee = credentialFactory.learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee(processedVc);
                        return Mono.just(credentialEmployee);
                    } catch (JsonProcessingException e) {
                        return Mono.error(new ParseErrorException("Error parsing id_token credential: " + e));
                    }
                });
    }

    private boolean containsCertificationAndAttest(List<Power> powers) {
        return powers.stream().anyMatch(p -> "Certification".equals(p.function())) &&
                powers.stream().anyMatch(p -> PolicyContext.hasAction(p, "Attest"));
    }

    private boolean hasOnboardingExecutePower(List<Power> powers) {
        return powers.stream().anyMatch(p -> "Onboarding".equals(p.function())) &&
                powers.stream().anyMatch(p -> PolicyContext.hasAction(p, "Execute"));
    }

    private boolean payloadPowersOnlyIncludeProductOffering(List<Power> powers) {
        return powers.stream().allMatch(power -> "ProductOffering".equals(power.function()));
    }

    private boolean payloadPowersOnlyIncludeOnboarding(List<Power> powers) {
        return powers.stream().allMatch(power -> "Onboarding".equals(power.function()));
    }
}
