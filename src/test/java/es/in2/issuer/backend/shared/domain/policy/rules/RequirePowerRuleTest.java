package es.in2.issuer.backend.shared.domain.policy.rules;

import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import java.util.List;

class RequirePowerRuleTest {

    private final RequirePowerRule<Object> rule = RequirePowerRule.of("Onboarding", "Execute");

    @Test
    void evaluate_succeedsWhenPowerMatches() {
        Power power = Power.builder()
                .function("Onboarding").action("Execute").domain("DOME").build();
        PolicyContext ctx = new PolicyContext("ORG-1", List.of(power), null, null, null, false, false, "DOME", null);

        StepVerifier.create(rule.evaluate(ctx, new Object()))
                .verifyComplete();
    }

    @Test
    void evaluate_succeedsWhenSysAdmin() {
        PolicyContext ctx = new PolicyContext("ORG-1", List.of(), null, null, null, true, false, "DOME", null);

        StepVerifier.create(rule.evaluate(ctx, new Object()))
                .verifyComplete();
    }

    @Test
    void evaluate_failsWhenFunctionDoesNotMatch() {
        Power power = Power.builder()
                .function("Certification").action("Execute").domain("DOME").build();
        PolicyContext ctx = new PolicyContext("ORG-1", List.of(power), null, null, null, false, false, "DOME", null);

        StepVerifier.create(rule.evaluate(ctx, new Object()))
                .expectErrorMatches(e ->
                        e instanceof UnauthorizedRoleException &&
                                e.getMessage().contains("Access denied: Required power not found"))
                .verify();
    }

    @Test
    void evaluate_failsWhenActionDoesNotMatch() {
        Power power = Power.builder()
                .function("Onboarding").action("Read").domain("DOME").build();
        PolicyContext ctx = new PolicyContext("ORG-1", List.of(power), null, null, null, false, false, "DOME", null);

        StepVerifier.create(rule.evaluate(ctx, new Object()))
                .expectErrorMatches(e ->
                        e instanceof UnauthorizedRoleException &&
                                e.getMessage().contains("Access denied: Required power not found"))
                .verify();
    }

    @Test
    void evaluate_failsWhenDomainDoesNotMatch() {
        Power power = Power.builder()
                .function("Onboarding").action("Execute").domain("OTHER").build();
        PolicyContext ctx = new PolicyContext("ORG-1", List.of(power), null, null, null, false, false, "DOME", null);

        StepVerifier.create(rule.evaluate(ctx, new Object()))
                .expectErrorMatches(e ->
                        e instanceof UnauthorizedRoleException &&
                                e.getMessage().contains("Access denied: Required power not found"))
                .verify();
    }

    @Test
    void evaluate_failsWhenNoPowersPresent() {
        PolicyContext ctx = new PolicyContext("ORG-1", List.of(), null, null, null, false, false, "DOME", null);

        StepVerifier.create(rule.evaluate(ctx, new Object()))
                .expectErrorMatches(e ->
                        e instanceof UnauthorizedRoleException &&
                                e.getMessage().contains("Access denied: Required power not found"))
                .verify();
    }

    @Test
    void evaluate_failsWhenTenantDomainIsNull() {
        PolicyContext ctx = new PolicyContext("ORG-1", List.of(), null, null, null, false, false, null, null);

        StepVerifier.create(rule.evaluate(ctx, new Object()))
                .expectErrorMatches(e ->
                        e instanceof UnauthorizedRoleException &&
                                e.getMessage().contains("Tenant domain is not configured"))
                .verify();
    }

    @Test
    void evaluate_worksWithActionAsList() {
        Power power = Power.builder()
                .function("Onboarding").action(List.of("Execute", "Read")).domain("DOME").build();
        PolicyContext ctx = new PolicyContext("ORG-1", List.of(power), null, null, null, false, false, "DOME", null);

        StepVerifier.create(rule.evaluate(ctx, new Object()))
                .verifyComplete();
    }
}
