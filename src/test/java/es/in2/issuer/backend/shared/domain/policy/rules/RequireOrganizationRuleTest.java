package es.in2.issuer.backend.shared.domain.policy.rules;

import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import java.util.List;

class RequireOrganizationRuleTest {

    private final RequireOrganizationRule rule = new RequireOrganizationRule();

    @Test
    void evaluate_succeedsWhenOrganizationMatches() {
        PolicyContext ctx = new PolicyContext("ORG-123", List.of(), null, null, null, false, false, null, null, null);

        StepVerifier.create(rule.evaluate(ctx, "ORG-123"))
                .verifyComplete();
    }

    @Test
    void evaluate_succeedsWhenSysAdmin() {
        PolicyContext ctx = new PolicyContext("ADMIN_ORG", List.of(), null, null, null, true, false, null, null, null);

        StepVerifier.create(rule.evaluate(ctx, "COMPLETELY_DIFFERENT_ORG"))
                .verifyComplete();
    }

    @Test
    void evaluate_failsWhenOrganizationDoesNotMatchAndNotSysAdmin() {
        PolicyContext ctx = new PolicyContext("ORG-123", List.of(), null, null, null, false, false, null, null, null);

        StepVerifier.create(rule.evaluate(ctx, "ORG-456"))
                .expectErrorMatches(e ->
                        e instanceof UnauthorizedRoleException &&
                                e.getMessage().contains("Access denied: Unauthorized organization identifier"))
                .verify();
    }

    @Test
    void evaluate_sysAdminBypassesOrgCheck() {
        PolicyContext ctx = new PolicyContext("ADMIN_ORG", List.of(), null, null, null, true, false, null, null, null);

        // Even though orgs don't match, sys-admin bypasses the check
        StepVerifier.create(rule.evaluate(ctx, "ANY_ORG"))
                .verifyComplete();
    }

    @Test
    void evaluate_tenantAdminBypassesOrgCheck() {
        PolicyContext ctx = new PolicyContext("TENANT_ADMIN_ORG", List.of(), null, null, null, false, true, null, null, null);

        StepVerifier.create(rule.evaluate(ctx, "DIFFERENT_ORG"))
                .verifyComplete();
    }

    @Test
    void evaluate_failsWhenNotSysAdminNotTenantAdminAndOrgMismatch() {
        PolicyContext ctx = new PolicyContext("ORG-A", List.of(), null, null, null, false, false, null, null, null);

        StepVerifier.create(rule.evaluate(ctx, "ORG-B"))
                .expectErrorMatches(e ->
                        e instanceof UnauthorizedRoleException &&
                                e.getMessage().contains("Access denied"))
                .verify();
    }
}
