package es.in2.issuer.backend.shared.domain.policy.rules;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import java.util.List;

import static org.mockito.Mockito.mock;

class RequireSignerIssuanceRuleTest {

    private final RequireSignerIssuanceRule rule = new RequireSignerIssuanceRule();

    @Test
    void evaluate_succeedsWhenSysAdminWithOnboardingExecute() {
        Power power = Power.builder()
                .function("Onboarding").action("Execute").build();
        PolicyContext ctx = new PolicyContext("ORG-1", List.of(power), null, null, null, true, null, null);

        StepVerifier.create(rule.evaluate(ctx, mock(JsonNode.class)))
                .verifyComplete();
    }

    @Test
    void evaluate_failsWhenSysAdminButMissingPower() {
        PolicyContext ctx = new PolicyContext("ORG-1", List.of(), null, null, null, true, null, null);

        StepVerifier.create(rule.evaluate(ctx, mock(JsonNode.class)))
                .expectErrorMatches(e ->
                        e instanceof InsufficientPermissionException &&
                                e.getMessage().contains("Signer issuance policy not met"))
                .verify();
    }

    @Test
    void evaluate_failsWhenNotSysAdminEvenWithPower() {
        Power power = Power.builder()
                .function("Onboarding").action("Execute").build();
        PolicyContext ctx = new PolicyContext("ORG-1", List.of(power), null, null, null, false, null, null);

        StepVerifier.create(rule.evaluate(ctx, mock(JsonNode.class)))
                .expectErrorMatches(e ->
                        e instanceof InsufficientPermissionException &&
                                e.getMessage().contains("Signer issuance policy not met"))
                .verify();
    }

    @Test
    void evaluate_failsWhenNotSysAdminAndNoPower() {
        PolicyContext ctx = new PolicyContext("ORG-1", List.of(), null, null, null, false, null, null);

        StepVerifier.create(rule.evaluate(ctx, mock(JsonNode.class)))
                .expectErrorMatches(e ->
                        e instanceof InsufficientPermissionException &&
                                e.getMessage().contains("Signer issuance policy not met"))
                .verify();
    }
}
