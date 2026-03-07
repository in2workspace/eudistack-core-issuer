package es.in2.issuer.backend.shared.domain.policy.rules;

import es.in2.issuer.backend.issuance.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyRule;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.VALID;

public class RequireValidStatusRule implements PolicyRule<CredentialStatusEnum> {

    @Override
    public Mono<Void> evaluate(PolicyContext context, CredentialStatusEnum credentialStatus) {
        if (credentialStatus == VALID) {
            return Mono.empty();
        }
        return Mono.error(
                new InvalidStatusException("Invalid status: " + credentialStatus)
        );
    }
}