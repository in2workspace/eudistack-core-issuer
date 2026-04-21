package es.in2.issuer.backend.shared.domain.policy.rules;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyRule;
import es.in2.issuer.backend.shared.domain.util.DynamicCredentialParser;
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
 *   <li><b>Escalation prevention</b>: payload powers contain neither
 *       {@code Onboarding/Execute} nor {@code Certification/Attest}.</li>
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
    private final DynamicCredentialParser credentialParser;

    @Override
    public Mono<Void> evaluate(PolicyContext context, JsonNode payload) {
        if (context.sysAdmin()) {
            log.info("LEAR issuance rule met: SysAdmin bypass.");
            return Mono.empty();
        }

        if (!hasOnboardingExecute(context.powers())) {
            return deny("operator lacks Onboarding/Execute power");
        }

        String denyReason = checkEscalationPrevention(payload);
        if (denyReason != null) {
            return deny(denyReason);
        }

        return checkOrgScope(context, payload);
    }

    private boolean hasOnboardingExecute(List<Power> powers) {
        return powers.stream().anyMatch(p ->
                FN_ONBOARDING.equals(p.function()) && PolicyContext.hasAction(p, ACT_EXECUTE));
    }

    private String checkEscalationPrevention(JsonNode payload) {
        JsonNode powerArray = payload.path("power");
        if (powerArray.isMissingNode() || !powerArray.isArray()) {
            return null;
        }
        List<Power> payloadPowers = objectMapper.convertValue(powerArray, new TypeReference<>() {});
        for (Power p : payloadPowers) {
            if (FN_ONBOARDING.equals(p.function()) && PolicyContext.hasAction(p, ACT_EXECUTE)) {
                return "payload delegates non-delegable power Onboarding/Execute";
            }
            if (FN_CERTIFICATION.equals(p.function()) && PolicyContext.hasAction(p, ACT_ATTEST)) {
                return "payload delegates non-delegable power Certification/Attest";
            }
        }
        return null;
    }

    private Mono<Void> checkOrgScope(PolicyContext context, JsonNode payload) {
        String payloadOrgId = payload.path("mandator").path("organizationIdentifier").asText(null);
        if (payloadOrgId == null) {
            return deny("payload mandator.organizationIdentifier missing");
        }

        String operatorOrgId = credentialParser.extractOrganizationId(context.credential(), context.profile());
        if (payloadOrgId.equals(operatorOrgId)) {
            return Mono.empty();
        }

        // On-behalf path
        if (!context.tenantAdmin()) {
            return deny("on-behalf issuance requires TenantAdmin (payload org='" + payloadOrgId
                    + "', operator org='" + operatorOrgId + "')");
        }
        if (!PolicyContext.TENANT_TYPE_MULTI_ORG.equals(context.tenantType())) {
            return deny("on-behalf issuance not allowed in tenant of type '" + context.tenantType() + "'");
        }
        return Mono.empty();
    }

    private Mono<Void> deny(String reason) {
        return Mono.error(new InsufficientPermissionException(
                "LEAR issuance policy not met: " + reason));
    }
}
