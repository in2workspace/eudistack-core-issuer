package es.in2.issuer.backend.shared.domain.policy;

import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;

class PolicyEnforcerTest {

    private PolicyEnforcer enforcer;

    @BeforeEach
    void setUp() {
        enforcer = new PolicyEnforcer();
    }

    // --- enforce (AND semantics) ---

    @Test
    void enforce_succeedsWhenAllRulesPass() {
        PolicyRule<Void> rule1 = (ctx, t) -> Mono.empty();
        PolicyRule<Void> rule2 = (ctx, t) -> Mono.empty();

        PolicyContext ctx = new PolicyContext("ORG1", List.of(), null, null, null, false, null, null);

        StepVerifier.create(enforcer.enforce(ctx, null, rule1, rule2))
                .verifyComplete();
    }

    @Test
    void enforce_failsOnFirstViolation() {
        PolicyRule<Void> passingRule = (ctx, t) -> Mono.empty();
        PolicyRule<Void> failingRule = (ctx, t) -> Mono.error(new UnauthorizedRoleException("denied"));
        PolicyRule<Void> neverReached = (ctx, t) -> {
            throw new AssertionError("This rule should not be reached");
        };

        PolicyContext ctx = new PolicyContext("ORG1", List.of(), null, null, null, false, null, null);

        StepVerifier.create(enforcer.enforce(ctx, null, passingRule, failingRule, neverReached))
                .expectError(UnauthorizedRoleException.class)
                .verify();
    }

    @Test
    void enforce_failsWhenSingleRuleFails() {
        PolicyRule<Void> failingRule = (ctx, t) -> Mono.error(new InsufficientPermissionException("no permission"));

        PolicyContext ctx = new PolicyContext("ORG1", List.of(), null, null, null, false, null, null);

        StepVerifier.create(enforcer.enforce(ctx, null, failingRule))
                .expectError(InsufficientPermissionException.class)
                .verify();
    }

    // --- enforceAny (OR semantics) ---

    @Test
    void enforceAny_succeedsWhenAtLeastOneRulePasses() {
        PolicyRule<Void> failingRule = (ctx, t) -> Mono.error(new InsufficientPermissionException("denied"));
        PolicyRule<Void> passingRule = (ctx, t) -> Mono.empty();

        PolicyContext ctx = new PolicyContext("ORG1", List.of(), null, null, null, false, null, null);

        StepVerifier.create(enforcer.enforceAny(ctx, null, "All failed", failingRule, passingRule))
                .verifyComplete();
    }

    @Test
    void enforceAny_failsWhenAllRulesFail() {
        PolicyRule<Void> failingRule1 = (ctx, t) -> Mono.error(new InsufficientPermissionException("denied1"));
        PolicyRule<Void> failingRule2 = (ctx, t) -> Mono.error(new InsufficientPermissionException("denied2"));

        PolicyContext ctx = new PolicyContext("ORG1", List.of(), null, null, null, false, null, null);

        StepVerifier.create(enforcer.enforceAny(ctx, null, "All policies failed", failingRule1, failingRule2))
                .expectErrorMatches(e ->
                        e instanceof InsufficientPermissionException &&
                                e.getMessage().equals("All policies failed"))
                .verify();
    }

    @Test
    void enforceAny_succeedsWhenOnlyRulePasses() {
        PolicyRule<Void> passingRule = (ctx, t) -> Mono.empty();

        PolicyContext ctx = new PolicyContext("ORG1", List.of(), null, null, null, false, null, null);

        StepVerifier.create(enforcer.enforceAny(ctx, null, "Should not fail", passingRule))
                .verifyComplete();
    }

    // --- enforceOrganization ---

    @Test
    void enforceOrganization_succeedsWhenOrgMatches() {
        PolicyContext ctx = new PolicyContext("ORG1", List.of(), null, null, null, false, null, null);

        StepVerifier.create(enforcer.enforceOrganization(ctx, "ORG1"))
                .verifyComplete();
    }

    @Test
    void enforceOrganization_succeedsWhenSysAdmin() {
        PolicyContext ctx = new PolicyContext("ADMIN_ORG", List.of(), null, null, null, true, null, null);

        StepVerifier.create(enforcer.enforceOrganization(ctx, "DIFFERENT_ORG"))
                .verifyComplete();
    }

    @Test
    void enforceOrganization_failsWhenOrgDoesNotMatchAndNotSysAdmin() {
        PolicyContext ctx = new PolicyContext("ORG1", List.of(), null, null, null, false, null, null);

        StepVerifier.create(enforcer.enforceOrganization(ctx, "ORG2"))
                .expectError(UnauthorizedRoleException.class)
                .verify();
    }
}
