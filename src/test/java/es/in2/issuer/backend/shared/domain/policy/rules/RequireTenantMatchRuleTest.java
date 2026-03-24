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
    void evaluate_rejectsWhenTenantDomainHeaderIsNullOrBlank(String tenantDomain) {
        PolicyContext ctx = new PolicyContext("ORG-123", List.of(), null, null, null, false, tenantDomain, "altia");

        StepVerifier.create(rule.evaluate(ctx, "ignored"))
                .expectErrorMatches(e ->
                        e instanceof TenantMismatchException &&
                                e.getMessage().contains("X-Tenant-Domain header is required"))
                .verify();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    void evaluate_rejectsWhenTokenTenantClaimIsNullOrBlank(String tokenTenant) {
        PolicyContext ctx = new PolicyContext("ORG-123", List.of(), null, null, null, false, "altia", tokenTenant);

        StepVerifier.create(rule.evaluate(ctx, "ignored"))
                .expectErrorMatches(e ->
                        e instanceof TenantMismatchException &&
                                e.getMessage().contains("Access token missing 'tenant' claim"))
                .verify();
    }

    @Test
    void evaluate_succeedsWhenTokenTenantMatchesHeader() {
        PolicyContext ctx = new PolicyContext("ORG-123", List.of(), null, null, null, false, "altia", "altia");

        StepVerifier.create(rule.evaluate(ctx, "ignored"))
                .verifyComplete();
    }

    @Test
    void evaluate_succeedsWhenTokenTenantMatchesHeaderCaseInsensitive() {
        PolicyContext ctx = new PolicyContext("ORG-123", List.of(), null, null, null, false, "ALTIA", "altia");

        StepVerifier.create(rule.evaluate(ctx, "ignored"))
                .verifyComplete();
    }

    @Test
    void evaluate_failsWhenTokenTenantDoesNotMatchHeader() {
        PolicyContext ctx = new PolicyContext("ORG-123", List.of(), null, null, null, false, "cgcom", "altia");

        StepVerifier.create(rule.evaluate(ctx, "ignored"))
                .expectErrorMatches(e ->
                        e instanceof TenantMismatchException &&
                                e.getMessage().contains("does not match tenant header"))
                .verify();
    }
}
