package es.in2.issuer.backend.shared.domain.policy.rules;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Mandator;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.machine.LEARCredentialMachine;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyRule;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Utils.extractMandatorLearCredentialEmployee;
import static es.in2.issuer.backend.shared.domain.util.Utils.extractPowers;

/**
 * Mandator delegation policy for LEARCredentialMachine issuance.
 * Checks:
 * 1. Signer credential has Onboarding/Execute power
 * 2. Payload mandator organizationIdentifier matches signer mandator
 * 3. All payload powers have function == "Onboarding"
 */
@Slf4j
@RequiredArgsConstructor
public class RequireMandatorMachineIssuanceRule implements PolicyRule<JsonNode> {

    private final ObjectMapper objectMapper;

    @Override
    public Mono<Void> evaluate(PolicyContext context, JsonNode target) {
        return Mono.fromCallable(() -> validate(context, target))
                .flatMap(valid -> valid
                        ? Mono.empty()
                        : Mono.error(new InsufficientPermissionException(
                                "Mandator machine issuance policy not met")));
    }

    private boolean validate(PolicyContext context, JsonNode payload) {
        List<Power> signerPowers = extractPowers(context.credential());
        if (!hasOnboardingExecutePower(signerPowers)) {
            return false;
        }

        LEARCredentialMachine.CredentialSubject.Mandate mandate =
                objectMapper.convertValue(payload, LEARCredentialMachine.CredentialSubject.Mandate.class);
        if (mandate == null) {
            return false;
        }

        Mandator signerMandator = extractMandatorLearCredentialEmployee(context.credential());
        if (!mandate.mandator().organizationIdentifier().equals(signerMandator.organizationIdentifier())) {
            return false;
        }

        return mandate.power().stream()
                .allMatch(power -> "Onboarding".equals(power.function()));
    }

    private boolean hasOnboardingExecutePower(List<Power> powers) {
        return powers.stream().anyMatch(p -> "Onboarding".equals(p.function()))
                && powers.stream().anyMatch(p -> PolicyContext.hasAction(p, "Execute"));
    }
}
