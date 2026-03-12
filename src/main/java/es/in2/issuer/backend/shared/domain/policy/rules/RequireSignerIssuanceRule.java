package es.in2.issuer.backend.shared.domain.policy.rules;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyRule;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Signer issuance policy: requires the user to be a sysAdmin (admin org)
 * AND have the Onboarding/Execute power.
 * <p>
 * No generic sysAdmin bypass — being sysAdmin IS the rule itself.
 * Used as one OR-path in Employee and Machine credential issuance.
 */
@Slf4j
public class RequireSignerIssuanceRule implements PolicyRule<JsonNode> {

    @Override
    public Mono<Void> evaluate(PolicyContext context, JsonNode target) {
        if (context.sysAdmin() && context.hasPower("Onboarding", "Execute")) {
            log.info("Signer issuance policy met: admin org with Onboarding/Execute power.");
            return Mono.empty();
        }
        return Mono.error(new InsufficientPermissionException(
                "Signer issuance policy not met: requires admin org with Onboarding/Execute power"));
    }
}
