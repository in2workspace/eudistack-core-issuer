package es.in2.issuer.backend.shared.domain.policy.rules;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyRule;
import es.in2.issuer.backend.shared.domain.util.DynamicCredentialParser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Unified mandator delegation policy for credential issuance.
 * Replaces RequireMandatorEmployeeIssuanceRule and RequireMandatorMachineIssuanceRule.
 * Parameterized by the expected power function (e.g., "ProductOffering" or "Onboarding").
 *
 * Checks:
 * 1. Signer credential has Onboarding/Execute power
 * 2. Payload mandator organizationIdentifier matches signer mandator
 * 3. All payload powers have the expected function
 * 4. Each delegated power's actions must be a subset of the signer's actions
 */
@Slf4j
@RequiredArgsConstructor
public class RequireMandatorDelegationRule implements PolicyRule<JsonNode> {

    private final String expectedFunction;
    private final ObjectMapper objectMapper;
    private final DynamicCredentialParser credentialParser;

    @Override
    public Mono<Void> evaluate(PolicyContext context, JsonNode target) {
        return Mono.fromCallable(() -> validate(context, target))
                .flatMap(valid -> valid
                        ? Mono.empty()
                        : Mono.error(new InsufficientPermissionException(
                                "Mandator delegation issuance policy not met (expected function: " + expectedFunction + ")")));
    }

    private boolean validate(PolicyContext context, JsonNode payload) {
        List<Power> signerPowers = context.powers();
        if (!hasOnboardingExecutePower(signerPowers)) {
            return false;
        }

        // Extract mandator org ID from payload
        JsonNode mandatorNode = payload.path("mandator");
        String payloadOrgId = mandatorNode.path("organizationIdentifier").asText(null);
        if (payloadOrgId == null) {
            return false;
        }

        // Extract signer mandator org ID from context credential via profile
        String signerOrgId = credentialParser.extractOrganizationId(context.credential(), context.profile());
        if (!payloadOrgId.equals(signerOrgId)) {
            return false;
        }

        // Extract powers from payload
        JsonNode powerArrayNode = payload.path("power");
        if (powerArrayNode.isMissingNode() || !powerArrayNode.isArray()) {
            return false;
        }
        List<Power> payloadPowers = objectMapper.convertValue(powerArrayNode, new TypeReference<>() {});

        if (!payloadPowers.stream().allMatch(power -> expectedFunction.equals(power.function()))) {
            return false;
        }

        // Delegation limitation: each delegated power must be covered by a signer power
        return payloadPowers.stream().allMatch(delegated -> isDelegationCovered(delegated, signerPowers));
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
