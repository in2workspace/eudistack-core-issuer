package es.in2.issuer.backend.shared.domain.policy.rules;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Mandator;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyRule;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Utils.extractMandatorLearCredentialEmployee;
import static es.in2.issuer.backend.shared.domain.util.Utils.extractPowers;

/**
 * Mandator delegation policy for LEARCredentialEmployee issuance.
 * Checks:
 * 1. Signer credential has Onboarding/Execute power
 * 2. Payload mandator organizationIdentifier matches signer mandator
 * 3. All payload powers have function == "ProductOffering"
 * 4. Each delegated power's actions must be a subset of the signer's actions for the same function
 */
@Slf4j
@RequiredArgsConstructor
public class RequireMandatorEmployeeIssuanceRule implements PolicyRule<JsonNode> {

    private final ObjectMapper objectMapper;

    @Override
    public Mono<Void> evaluate(PolicyContext context, JsonNode target) {
        return Mono.fromCallable(() -> validate(context, target))
                .flatMap(valid -> valid
                        ? Mono.empty()
                        : Mono.error(new InsufficientPermissionException(
                                "Mandator employee issuance policy not met")));
    }

    private boolean validate(PolicyContext context, JsonNode payload) {
        List<Power> signerPowers = extractPowers(context.credential());
        if (!hasOnboardingExecutePower(signerPowers)) {
            return false;
        }

        LEARCredentialEmployee.CredentialSubject.Mandate mandate =
                objectMapper.convertValue(payload, LEARCredentialEmployee.CredentialSubject.Mandate.class);
        if (mandate == null) {
            return false;
        }

        Mandator signerMandator = extractMandatorLearCredentialEmployee(context.credential());
        if (!mandate.mandator().organizationIdentifier().equals(signerMandator.organizationIdentifier())) {
            return false;
        }

        if (!mandate.power().stream().allMatch(power -> "ProductOffering".equals(power.function()))) {
            return false;
        }

        // Delegation limitation: each delegated power must be covered by a signer power
        return mandate.power().stream().allMatch(delegated -> isDelegationCovered(delegated, signerPowers));
    }

    private boolean isDelegationCovered(Power delegated, List<Power> signerPowers) {
        List<String> delegatedActions = normalizeActions(delegated.action());
        return signerPowers.stream()
                .filter(sp -> delegated.function().equals(sp.function()))
                .anyMatch(sp -> normalizeActions(sp.action()).containsAll(delegatedActions));
    }

    private List<String> normalizeActions(Object action) {
        if (action instanceof List<?> actions) {
            return actions.stream().map(Object::toString).toList();
        }
        return List.of(action.toString());
    }

    private boolean hasOnboardingExecutePower(List<Power> powers) {
        return powers.stream().anyMatch(p -> "Onboarding".equals(p.function()))
                && powers.stream().anyMatch(p -> PolicyContext.hasAction(p, "Execute"));
    }
}
