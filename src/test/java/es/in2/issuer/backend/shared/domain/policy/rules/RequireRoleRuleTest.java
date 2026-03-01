package es.in2.issuer.backend.shared.domain.policy.rules;

import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import java.util.List;

class RequireRoleRuleTest {

    @Test
    void evaluate_succeedsWhenRoleMatches() {
        RequireRoleRule<Void> rule = RequireRoleRule.of("LEAR");
        PolicyContext ctx = new PolicyContext("LEAR", "ORG1", List.of(), null, null, false);

        StepVerifier.create(rule.evaluate(ctx, null))
                .verifyComplete();
    }

    @Test
    void evaluate_failsWhenRoleDoesNotMatch() {
        RequireRoleRule<Void> rule = RequireRoleRule.of("LEAR");
        PolicyContext ctx = new PolicyContext("LER", "ORG1", List.of(), null, null, false);

        StepVerifier.create(rule.evaluate(ctx, null))
                .expectErrorMatches(e ->
                        e instanceof UnauthorizedRoleException &&
                                e.getMessage().contains("Access denied: Unauthorized role to perform this credential action"))
                .verify();
    }

    @Test
    void evaluate_failsWhenRoleIsNull() {
        RequireRoleRule<Void> rule = RequireRoleRule.of("LEAR");
        PolicyContext ctx = new PolicyContext(null, "ORG1", List.of(), null, null, false);

        StepVerifier.create(rule.evaluate(ctx, null))
                .expectError(UnauthorizedRoleException.class)
                .verify();
    }

    @Test
    void evaluate_failsWhenRoleIsEmpty() {
        RequireRoleRule<Void> rule = RequireRoleRule.of("LEAR");
        PolicyContext ctx = new PolicyContext("", "ORG1", List.of(), null, null, false);

        StepVerifier.create(rule.evaluate(ctx, null))
                .expectError(UnauthorizedRoleException.class)
                .verify();
    }

    @Test
    void evaluate_worksWithGenericTypeParameter() {
        RequireRoleRule<String> rule = RequireRoleRule.of("LEAR");
        PolicyContext ctx = new PolicyContext("LEAR", "ORG1", List.of(), null, null, false);

        StepVerifier.create(rule.evaluate(ctx, "some-target"))
                .verifyComplete();
    }
}
