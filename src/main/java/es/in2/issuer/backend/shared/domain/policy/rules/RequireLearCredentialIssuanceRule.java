package es.in2.issuer.backend.shared.domain.policy.rules;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.LearIssuancePolicyException;
import es.in2.issuer.backend.shared.domain.exception.LearIssuancePolicyException.Reason;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyRule;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Unified issuance rule for LEARCredentialEmployee and LEARCredentialMachine.
 * See ADR-002 for the model rationale.
 *
 * <p>Passes if <b>all</b> of these hold (SysAdmin bypasses the whole rule):
 *
 * <ol>
 *   <li><b>Power base</b>: operator has {@code Onboarding/Execute}.</li>
 *   <li><b>Escalation prevention</b>:
 *       {@code Onboarding/Execute} — only delegable by TenantAdmin in {@code multi_org} tenant,
 *       exclusively on-behalf (payload mandator org ≠ operator org).
 *       {@code Certification/Attest} — only delegable by TenantAdmin in {@code multi_org} tenant.</li>
 *   <li><b>Org scope</b>: either same-org
 *       (payload mandator org == operator mandator org), or on-behalf only if
 *       operator is TenantAdmin AND tenant type is {@code multi_org}.</li>
 * </ol>
 */
@Slf4j
@RequiredArgsConstructor
public class RequireLearCredentialIssuanceRule implements PolicyRule<JsonNode> {

    private static final String FN_ONBOARDING = "Onboarding";
    private static final String FN_CERTIFICATION = "Certification";
    private static final String ACT_EXECUTE = "Execute";
    private static final String ACT_ATTEST = "Attest";

    private final ObjectMapper objectMapper;

    @Override
    public Mono<Void> evaluate(PolicyContext context, JsonNode payload) {
        log.debug("evaluate: credentialType='{}', sysAdmin={}, tenantAdmin={}, tenantType='{}', tenantDomain='{}', operatorOrgId='{}'",
                context.credentialType(), context.sysAdmin(), context.tenantAdmin(),
                context.tenantType(), context.tenantDomain(), context.organizationIdentifier());

        if (context.sysAdmin()) {
            log.debug("LEAR issuance rule met: SysAdmin bypass.");
            return Mono.empty();
        }

        if (!hasOnboardingExecute(context.powers())) {
            return deny(Reason.OPERATOR_LACKS_ONBOARDING, "operator lacks Onboarding/Execute power");
        }

        Denial denial = checkEscalationPrevention(context, payload);
        if (denial != null) {
            return deny(denial.reason(), denial.message());
        }

        return checkOrgScope(context, payload);
    }

    private boolean hasOnboardingExecute(List<Power> powers) {
        return powers.stream().anyMatch(p ->
                FN_ONBOARDING.equals(p.function()) && PolicyContext.hasAction(p, ACT_EXECUTE));
    }

    private Denial checkEscalationPrevention(PolicyContext context, JsonNode payload) {
        JsonNode powerArray = payload.path("power");
        log.debug("checkEscalationPrevention: payloadPowerArray={}", powerArray);

        if (powerArray.isMissingNode() || !powerArray.isArray()) {
            log.debug("checkEscalationPrevention: no power array in payload, skipping");
            return null;
        }
        List<Power> payloadPowers = objectMapper.convertValue(powerArray, new TypeReference<>() {});
        for (Power p : payloadPowers) {
            Denial denial = checkPowerDelegation(context, payload, p);
            if (denial != null) {
                return denial;
            }
        }
        return null;
    }

    private Denial checkPowerDelegation(PolicyContext context, JsonNode payload, Power p) {
        if (FN_ONBOARDING.equals(p.function()) && PolicyContext.hasAction(p, ACT_EXECUTE)) {
            return checkOnboardingDelegation(context, payload);
        }
        if (FN_CERTIFICATION.equals(p.function()) && PolicyContext.hasAction(p, ACT_ATTEST)) {
            return checkTenantAdminInMultiOrg(context, "Certification/Attest",
                    Reason.CERTIFICATION_DELEGATION_REQUIRES_TENANT_ADMIN,
                    Reason.CERTIFICATION_DELEGATION_REQUIRES_MULTI_ORG);
        }
        return null;
    }

    private Denial checkOnboardingDelegation(PolicyContext context, JsonNode payload) {
        Denial denial = checkTenantAdminInMultiOrg(context, "Onboarding/Execute",
                Reason.ONBOARDING_DELEGATION_REQUIRES_TENANT_ADMIN,
                Reason.ONBOARDING_DELEGATION_REQUIRES_MULTI_ORG);
        if (denial != null) {
            return denial;
        }
        String payloadMandatorOrgId = payload.path("mandator").path("organizationIdentifier").asText(null);
        String operatorOrgId = context.organizationIdentifier();
        boolean mandatorMissingOrSameAsOperator = payloadMandatorOrgId == null || payloadMandatorOrgId.equals(operatorOrgId);
        log.debug("checkOnboardingDelegation: on-behalf check — operatorOrgId='{}', payloadMandatorOrgId='{}', mandatorMissingOrSameAsOperator={}",
                operatorOrgId, payloadMandatorOrgId, mandatorMissingOrSameAsOperator);
        if (mandatorMissingOrSameAsOperator) {
            return new Denial(Reason.ONBOARDING_DELEGATION_SAME_ORG,
                    "Onboarding/Execute delegation only allowed on-behalf (payload mandator org must differ from operator org '"
                    + operatorOrgId + "')");
        }
        return null;
    }

    /** Delegating {@code powerLabel} requires a TenantAdmin operator in a {@code multi_org} tenant. */
    private Denial checkTenantAdminInMultiOrg(PolicyContext context, String powerLabel,
                                              Reason requiresTenantAdmin, Reason requiresMultiOrg) {
        if (!context.tenantAdmin()) {
            return new Denial(requiresTenantAdmin, powerLabel + " delegation requires TenantAdmin");
        }
        if (!PolicyContext.TENANT_TYPE_MULTI_ORG.equals(context.tenantType())) {
            return new Denial(requiresMultiOrg, powerLabel + " delegation only allowed in multi_org tenant (current: '"
                    + context.tenantType() + "')");
        }
        return null;
    }

    private Mono<Void> checkOrgScope(PolicyContext context, JsonNode payload) {
        String payloadOrgId = payload.path("mandator").path("organizationIdentifier").asText(null);

        if (payloadOrgId == null) {
            return deny(Reason.MANDATOR_ORGANIZATION_MISSING, "payload mandator.organizationIdentifier missing");
        }

        String operatorOrgId = context.organizationIdentifier();

        if (payloadOrgId.equals(operatorOrgId)) {
            return Mono.empty();
        }

        if (!context.tenantAdmin()) {
            return deny(Reason.ON_BEHALF_REQUIRES_TENANT_ADMIN, "on-behalf issuance requires TenantAdmin (payload org='" + payloadOrgId
                    + "', operator org='" + operatorOrgId + "')");
        }

        if (!PolicyContext.TENANT_TYPE_MULTI_ORG.equals(context.tenantType())) {
            return deny(Reason.ON_BEHALF_REQUIRES_MULTI_ORG, "on-behalf issuance not allowed in tenant of type '" + context.tenantType() + "'");
        }

        return Mono.empty();
    }

    private Mono<Void> deny(Reason reason, String message) {
        log.debug("LEAR issuance rule denied ({}): {}", reason.getCode(), message);
        return Mono.error(new LearIssuancePolicyException(reason,
                "LEAR issuance policy not met: " + message));
    }

    private record Denial(Reason reason, String message) {}
}
