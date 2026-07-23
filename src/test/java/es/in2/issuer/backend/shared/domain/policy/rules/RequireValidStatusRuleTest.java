package es.in2.issuer.backend.shared.domain.policy.rules;

import es.in2.issuer.backend.issuance.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import reactor.test.StepVerifier;

class RequireValidStatusRuleTest {

    private final RequireValidStatusRule rule = new RequireValidStatusRule();

    @Test
    void evaluate_succeedsWhenStatusIsValid() {
        StepVerifier.create(rule.evaluate(null, CredentialStatusEnum.VALID))
                .verifyComplete();
    }

    @ParameterizedTest
    @EnumSource(value = CredentialStatusEnum.class, names = "VALID", mode = EnumSource.Mode.EXCLUDE)
    void evaluate_failsWhenStatusIsNotValid(CredentialStatusEnum status) {
        StepVerifier.create(rule.evaluate(null, status))
                .expectErrorMatches(e ->
                        e instanceof InvalidStatusException &&
                                e.getMessage().contains("Invalid status: " + status))
                .verify();
    }
}
