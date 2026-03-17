package es.in2.issuer.backend.shared.domain.policy.rules;

import es.in2.issuer.backend.shared.domain.exception.TenantMismatchException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import reactor.test.StepVerifier;

import java.util.List;

class RequireTenantMatchRuleTest {

    private final RequireTenantMatchRule rule = new RequireTenantMatchRule();

    @Nested
    @DisplayName("Header validation")
    class HeaderValidation {

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {"   ", "\t"})
        void evaluate_rejectsWhenTenantDomainHeaderMissing(String tenantDomain) {
            PolicyContext ctx = ctx("ORG-123", List.of(), false, tenantDomain, "altia");

            StepVerifier.create(rule.evaluate(ctx, "ignored"))
                    .expectErrorMatches(e ->
                            e instanceof TenantMismatchException
                                    && e.getMessage().contains("X-Tenant-Domain header is required"))
                    .verify();
        }
    }

    @Nested
    @DisplayName("Token tenant claim validation")
    class TokenTenantValidation {

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {"   "})
        void evaluate_rejectsWhenTokenTenantClaimMissing(String tokenTenant) {
            PolicyContext ctx = ctx("ORG-123", List.of(), false, "altia", tokenTenant);

            StepVerifier.create(rule.evaluate(ctx, "ignored"))
                    .expectErrorMatches(e ->
                            e instanceof TenantMismatchException
                                    && e.getMessage().contains("tenant claim is required"))
                    .verify();
        }

        @Test
        void evaluate_rejectsWhenTokenTenantDoesNotMatchHeader() {
            PolicyContext ctx = ctx("ORG-123", List.of(), false, "altia", "dome");

            StepVerifier.create(rule.evaluate(ctx, "ignored"))
                    .expectErrorMatches(e ->
                            e instanceof TenantMismatchException
                                    && e.getMessage().contains("Token tenant 'dome' does not match tenant header 'altia'"))
                    .verify();
        }
    }

    @Nested
    @DisplayName("SysAdmin bypass")
    class SysAdminBypass {

        @Test
        void evaluate_permitsSysAdminWithoutPowerDomainCheck() {
            // sysAdmin=true, no Onboarding/Execute power — should still pass
            PolicyContext ctx = ctx("ADMIN-ORG", List.of(), true, "altia", "altia");

            StepVerifier.create(rule.evaluate(ctx, "ignored"))
                    .verifyComplete();
        }
    }

    @Nested
    @DisplayName("Power-domain validation")
    class PowerDomainValidation {

        @Test
        void evaluate_permitsWithMatchingOnboardingExecutePowerDomain() {
            Power power = new Power(List.of("Execute"), "altia", "Onboarding", null);
            PolicyContext ctx = ctx("ORG-123", List.of(power), false, "altia", "altia");

            StepVerifier.create(rule.evaluate(ctx, "ignored"))
                    .verifyComplete();
        }

        @Test
        void evaluate_rejectsWhenPowerDomainDoesNotMatchTenant() {
            Power power = new Power(List.of("Execute"), "dome", "Onboarding", null);
            PolicyContext ctx = ctx("ORG-123", List.of(power), false, "altia", "altia");

            StepVerifier.create(rule.evaluate(ctx, "ignored"))
                    .expectErrorMatches(e ->
                            e instanceof TenantMismatchException
                                    && e.getMessage().contains("No Onboarding-Execute power for tenant 'altia'"))
                    .verify();
        }

        @Test
        void evaluate_rejectsWhenNoPowers() {
            PolicyContext ctx = ctx("ORG-123", List.of(), false, "altia", "altia");

            StepVerifier.create(rule.evaluate(ctx, "ignored"))
                    .expectErrorMatches(e ->
                            e instanceof TenantMismatchException
                                    && e.getMessage().contains("No Onboarding-Execute power"))
                    .verify();
        }

        @Test
        void evaluate_rejectsWhenWrongFunction() {
            Power power = new Power(List.of("Execute"), "altia", "Certification", null);
            PolicyContext ctx = ctx("ORG-123", List.of(power), false, "altia", "altia");

            StepVerifier.create(rule.evaluate(ctx, "ignored"))
                    .expectErrorMatches(e -> e instanceof TenantMismatchException)
                    .verify();
        }

        @Test
        void evaluate_rejectsWhenWrongAction() {
            Power power = new Power(List.of("Attest"), "altia", "Onboarding", null);
            PolicyContext ctx = ctx("ORG-123", List.of(power), false, "altia", "altia");

            StepVerifier.create(rule.evaluate(ctx, "ignored"))
                    .expectErrorMatches(e -> e instanceof TenantMismatchException)
                    .verify();
        }

        @Test
        void evaluate_permitsWhenOnePowerMatchesAmongMultiple() {
            Power irrelevant = new Power(List.of("Attest"), "dome", "Certification", null);
            Power matching = new Power(List.of("Execute"), "altia", "Onboarding", null);
            PolicyContext ctx = ctx("ORG-123", List.of(irrelevant, matching), false, "altia", "altia");

            StepVerifier.create(rule.evaluate(ctx, "ignored"))
                    .verifyComplete();
        }

        @Test
        void evaluate_permitsWithStringAction() {
            // action as String instead of List
            Power power = new Power("Execute", "altia", "Onboarding", null);
            PolicyContext ctx = ctx("ORG-123", List.of(power), false, "altia", "altia");

            StepVerifier.create(rule.evaluate(ctx, "ignored"))
                    .verifyComplete();
        }
    }

    private PolicyContext ctx(String orgId, List<Power> powers, boolean sysAdmin,
                              String tenantDomain, String tokenTenant) {
        return new PolicyContext(orgId, powers, null, null, null, sysAdmin, tenantDomain, tokenTenant);
    }
}