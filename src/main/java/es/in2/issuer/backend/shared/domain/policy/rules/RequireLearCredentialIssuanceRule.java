package es.in2.issuer.backend.shared.domain.policy.rules;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyRule;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
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
    private final TenantConfigService tenantConfigService;

    @Override
    public Mono<Void> evaluate(PolicyContext context, JsonNode payload) {
        log.debug("evaluate: credentialType='{}', sysAdmin={}, tenantAdmin={}, tenantType='{}', tenantDomain='{}', operatorOrgId='{}'",
                context.credentialType(), context.sysAdmin(), context.tenantAdmin(),
                context.tenantType(), context.tenantDomain(), context.organizationIdentifier());

        if (context.sysAdmin()) {
            log.info("LEAR issuance rule met: SysAdmin bypass.");
            return Mono.empty();
        }

        if (!hasOnboardingExecute(context.powers())) {
            log.debug("evaluate: operator powers={}", context.powers());
            return deny("operator lacks Onboarding/Execute power");
        }

        String denyReason = checkEscalationPrevention(context, payload);
        if (denyReason != null) {
            log.debug("evaluate: escalation prevention denied — {}", denyReason);
            return deny(denyReason);
        }

        return checkOrgScope(context, payload);
    }

    private boolean hasOnboardingExecute(List<Power> powers) {
        return powers.stream().anyMatch(p ->
                FN_ONBOARDING.equals(p.function()) && PolicyContext.hasAction(p, ACT_EXECUTE));
    }

    private String checkEscalationPrevention(PolicyContext context, JsonNode payload) {
        JsonNode powerArray = payload.path("power");
        log.debug("checkEscalationPrevention: payloadPowerArray={}", powerArray);
        if (powerArray.isMissingNode() || !powerArray.isArray()) {
            log.debug("checkEscalationPrevention: no power array in payload, skipping");
            return null;
        }
        List<Power> payloadPowers = objectMapper.convertValue(powerArray, new TypeReference<>() {});
        for (Power p : payloadPowers) {
            log.debug("checkEscalationPrevention: evaluating power function='{}' action='{}'", p.function(), p.action());
            if (FN_ONBOARDING.equals(p.function()) && PolicyContext.hasAction(p, ACT_EXECUTE)) {
                log.debug("checkEscalationPrevention: Onboarding/Execute found — tenantAdmin={}, tenantType='{}'",
                        context.tenantAdmin(), context.tenantType());
                if (!context.tenantAdmin()) {
                    return "Onboarding/Execute delegation requires TenantAdmin";
                }
                if (!PolicyContext.TENANT_TYPE_MULTI_ORG.equals(context.tenantType())) {
                    return "Onboarding/Execute delegation only allowed in multi_org tenant (current: '"
                            + context.tenantType() + "')";
                }
                String payloadMandatorOrgId = payload.path("mandator").path("organizationIdentifier").asText(null);
                String operatorOrgId = context.organizationIdentifier();
                log.debug("checkEscalationPrevention: on-behalf check — operatorOrgId='{}', payloadMandatorOrgId='{}', sameOrg={}",
                        operatorOrgId, payloadMandatorOrgId, payloadMandatorOrgId != null && payloadMandatorOrgId.equals(operatorOrgId));
                if (payloadMandatorOrgId == null || payloadMandatorOrgId.equals(operatorOrgId)) {
                    return "Onboarding/Execute delegation only allowed on-behalf (payload mandator org must differ from operator org '"
                            + operatorOrgId + "')";
                }
            }
            if (FN_CERTIFICATION.equals(p.function()) && PolicyContext.hasAction(p, ACT_ATTEST)) {
                log.debug("checkEscalationPrevention: Certification/Attest found — tenantAdmin={}, tenantType='{}'",
                        context.tenantAdmin(), context.tenantType());
                if (!context.tenantAdmin()) {
                    return "Certification/Attest delegation requires TenantAdmin";
                }
                if (!PolicyContext.TENANT_TYPE_MULTI_ORG.equals(context.tenantType())) {
                    return "Certification/Attest delegation only allowed in multi_org tenant (current: '"
                            + context.tenantType() + "')";
                }
            }
        }
        log.debug("checkEscalationPrevention: passed");
        return null;
    }

    private Mono<Void> checkOrgScope(PolicyContext context, JsonNode payload) {
        String payloadOrgId = payload.path("mandator").path("organizationIdentifier").asText(null);
        log.debug("checkOrgScope: payloadOrgId='{}', operatorOrgId='{}'", payloadOrgId, context.organizationIdentifier());
        if (payloadOrgId == null) {
            return deny("payload mandator.organizationIdentifier missing");
        }

        String operatorOrgId = context.organizationIdentifier();

        return tenantConfigService.getStringOrThrow("admin_organization_id")
                .doOnNext(adminOrgId -> log.debug(
                        "checkOrgScope: tenantDomain='{}', adminOrganizationId='{}', operatorOrgId='{}', payloadOrgId='{}', sameOrg={}, tenantAdmin={}, tenantType='{}'",
                        context.tenantDomain(), adminOrgId, operatorOrgId, payloadOrgId,
                        payloadOrgId.equals(operatorOrgId), context.tenantAdmin(), context.tenantType()))
                .flatMap(adminOrgId -> {
                    if (payloadOrgId.equals(operatorOrgId)) {
                        log.debug("checkOrgScope: same-org issuance, passed");
                        return Mono.<Void>empty();
                    }
                    log.debug("checkOrgScope: on-behalf path — tenantAdmin={}, tenantType='{}'",
                            context.tenantAdmin(), context.tenantType());
                    if (!context.tenantAdmin()) {
                        return deny("on-behalf issuance requires TenantAdmin (payload org='" + payloadOrgId
                                + "', operator org='" + operatorOrgId + "')");
                    }
                    if (!PolicyContext.TENANT_TYPE_MULTI_ORG.equals(context.tenantType())) {
                        return deny("on-behalf issuance not allowed in tenant of type '" + context.tenantType() + "'");
                    }
                    log.debug("checkOrgScope: on-behalf issuance in multi_org tenant, passed");
                    return Mono.<Void>empty();
                });
    }

    private Mono<Void> deny(String reason) {
        return Mono.error(new InsufficientPermissionException(
                "LEAR issuance policy not met: " + reason));
    }
}
