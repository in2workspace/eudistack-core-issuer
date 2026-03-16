package es.in2.issuer.backend.shared.domain.policy.rules;

import es.in2.issuer.backend.shared.domain.exception.TenantMismatchException;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import reactor.test.StepVerifier;

import java.util.List;

class RequireTenantMatchRuleTest {

    private final RequireTenantMatchRule rule = new RequireTenantMatchRule();

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    void evaluate_rejectsWhenTenantDomainIsNullOrBlank(String tenantDomain) {
        PolicyContext ctx = new PolicyContext("ORG-123", List.of(), null, null, null, false, tenantDomain);

        StepVerifier.create(rule.evaluate(ctx, "ignored"))
                .expectErrorMatches(e ->
                        e instanceof TenantMismatchException &&
                                e.getMessage().contains("X-Tenant-Domain header is required"))
                .verify();
    }

    @Test
    void evaluate_succeedsWhenTenantDomainMatchesOrganization() {
        PolicyContext ctx = new PolicyContext("ORG-123", List.of(), null, null, null, false, "ORG-123");

        StepVerifier.create(rule.evaluate(ctx, "ignored"))
                .verifyComplete();
    }

    @Test
    void evaluate_failsWhenTenantDomainDoesNotMatchOrganization() {
        PolicyContext ctx = new PolicyContext("ORG-123", List.of(), null, null, null, false, "ORG-456");

        StepVerifier.create(rule.evaluate(ctx, "ignored"))
                .expectErrorMatches(e ->
                        e instanceof TenantMismatchException &&
                                e.getMessage().contains("does not match tenant header"))
                .verify();
    }
}
