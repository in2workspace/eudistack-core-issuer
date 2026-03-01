package es.in2.issuer.backend.shared.domain.policy.rules;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Mandator;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.machine.LEARCredentialMachine;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import java.util.Collections;
import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Utils.extractPowers;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RequireMandatorMachineIssuanceRuleTest {

    private final ObjectMapper objectMapper = mock(ObjectMapper.class);
    private final RequireMandatorMachineIssuanceRule rule = new RequireMandatorMachineIssuanceRule(objectMapper);

    private LEARCredentialEmployee buildSignerCredential(String orgId) {
        Mandator mandator = Mandator.builder()
                .organizationIdentifier(orgId)
                .build();
        Power power = Power.builder()
                .function("Onboarding").action("Execute").build();
        LEARCredentialEmployee.CredentialSubject.Mandate mandate =
                LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                        .mandator(mandator)
                        .power(Collections.singletonList(power))
                        .build();
        return LEARCredentialEmployee.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .credentialSubject(LEARCredentialEmployee.CredentialSubject.builder()
                        .mandate(mandate).build())
                .build();
    }

    @Test
    void evaluate_succeedsWhenOrgIdMatchesAndOnboardingPowers() {
        LEARCredentialEmployee signer = buildSignerCredential("ORG-1");
        PolicyContext ctx = new PolicyContext("ORG-1", extractPowers(signer), signer, "LEARCredentialEmployee", false, null);

        JsonNode payload = mock(JsonNode.class);
        LEARCredentialMachine.CredentialSubject.Mandate payloadMandate =
                LEARCredentialMachine.CredentialSubject.Mandate.builder()
                        .mandator(LEARCredentialMachine.CredentialSubject.Mandate.Mandator.builder()
                                .organizationIdentifier("ORG-1").build())
                        .power(Collections.singletonList(
                                Power.builder().function("Onboarding").action("Execute").build()))
                        .build();
        when(objectMapper.convertValue(payload, LEARCredentialMachine.CredentialSubject.Mandate.class))
                .thenReturn(payloadMandate);

        StepVerifier.create(rule.evaluate(ctx, payload))
                .verifyComplete();
    }

    @Test
    void evaluate_failsWhenOrgIdDoesNotMatch() {
        LEARCredentialEmployee signer = buildSignerCredential("ORG-1");
        PolicyContext ctx = new PolicyContext("ORG-1", extractPowers(signer), signer, "LEARCredentialEmployee", false, null);

        JsonNode payload = mock(JsonNode.class);
        LEARCredentialMachine.CredentialSubject.Mandate payloadMandate =
                LEARCredentialMachine.CredentialSubject.Mandate.builder()
                        .mandator(LEARCredentialMachine.CredentialSubject.Mandate.Mandator.builder()
                                .organizationIdentifier("OTHER-ORG").build())
                        .power(Collections.singletonList(
                                Power.builder().function("Onboarding").action("Execute").build()))
                        .build();
        when(objectMapper.convertValue(payload, LEARCredentialMachine.CredentialSubject.Mandate.class))
                .thenReturn(payloadMandate);

        StepVerifier.create(rule.evaluate(ctx, payload))
                .expectErrorMatches(e ->
                        e instanceof InsufficientPermissionException &&
                                e.getMessage().contains("Mandator machine issuance policy not met"))
                .verify();
    }

    @Test
    void evaluate_failsWhenPayloadPowersAreNotOnboarding() {
        LEARCredentialEmployee signer = buildSignerCredential("ORG-1");
        PolicyContext ctx = new PolicyContext("ORG-1", extractPowers(signer), signer, "LEARCredentialEmployee", false, null);

        JsonNode payload = mock(JsonNode.class);
        LEARCredentialMachine.CredentialSubject.Mandate payloadMandate =
                LEARCredentialMachine.CredentialSubject.Mandate.builder()
                        .mandator(LEARCredentialMachine.CredentialSubject.Mandate.Mandator.builder()
                                .organizationIdentifier("ORG-1").build())
                        .power(Collections.singletonList(
                                Power.builder().function("ProductOffering").action("Create").build()))
                        .build();
        when(objectMapper.convertValue(payload, LEARCredentialMachine.CredentialSubject.Mandate.class))
                .thenReturn(payloadMandate);

        StepVerifier.create(rule.evaluate(ctx, payload))
                .expectErrorMatches(e ->
                        e instanceof InsufficientPermissionException &&
                                e.getMessage().contains("Mandator machine issuance policy not met"))
                .verify();
    }

    @Test
    void evaluate_failsWhenSignerMissingOnboardingPower() {
        Mandator mandator = Mandator.builder()
                .organizationIdentifier("ORG-1").build();
        Power power = Power.builder().function("Certification").action("Attest").build();
        LEARCredentialEmployee signer = LEARCredentialEmployee.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .credentialSubject(LEARCredentialEmployee.CredentialSubject.builder()
                        .mandate(LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                                .mandator(mandator)
                                .power(Collections.singletonList(power))
                                .build())
                        .build())
                .build();
        PolicyContext ctx = new PolicyContext("ORG-1", extractPowers(signer), signer, "LEARCredentialEmployee", false, null);

        JsonNode payload = mock(JsonNode.class);

        StepVerifier.create(rule.evaluate(ctx, payload))
                .expectErrorMatches(e ->
                        e instanceof InsufficientPermissionException &&
                                e.getMessage().contains("Mandator machine issuance policy not met"))
                .verify();
    }
}
