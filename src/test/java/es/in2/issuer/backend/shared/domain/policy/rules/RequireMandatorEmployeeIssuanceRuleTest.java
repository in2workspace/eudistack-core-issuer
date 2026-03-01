package es.in2.issuer.backend.shared.domain.policy.rules;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Mandator;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import java.util.Collections;
import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Utils.extractPowers;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RequireMandatorEmployeeIssuanceRuleTest {

    private final ObjectMapper objectMapper = mock(ObjectMapper.class);
    private final RequireMandatorEmployeeIssuanceRule rule = new RequireMandatorEmployeeIssuanceRule(objectMapper);

    private LEARCredentialEmployee buildSignerCredential(String orgId) {
        Mandator mandator = Mandator.builder()
                .organizationIdentifier(orgId)
                .commonName("TestOrg")
                .country("ES")
                .serialNumber("SN-001")
                .build();
        Power power = Power.builder()
                .function("Onboarding").action("Execute").build();
        LEARCredentialEmployee.CredentialSubject.Mandate mandate =
                LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                        .mandator(mandator)
                        .power(Collections.singletonList(power))
                        .build();
        LEARCredentialEmployee.CredentialSubject credentialSubject =
                LEARCredentialEmployee.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();
        return LEARCredentialEmployee.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .credentialSubject(credentialSubject)
                .build();
    }

    @Test
    void evaluate_succeedsWhenOrgMatchesAndProductOfferingPowers() {
        String orgId = "ORG-123";
        LEARCredentialEmployee signer = buildSignerCredential(orgId);
        PolicyContext ctx = new PolicyContext(orgId, extractPowers(signer), signer, "LEARCredentialEmployee", false, null);

        JsonNode payload = mock(JsonNode.class);
        LEARCredentialEmployee.CredentialSubject.Mandate payloadMandate =
                LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                        .mandator(Mandator.builder().organizationIdentifier(orgId).build())
                        .power(Collections.singletonList(
                                Power.builder().function("ProductOffering").action("Create").build()))
                        .build();
        when(objectMapper.convertValue(payload, LEARCredentialEmployee.CredentialSubject.Mandate.class))
                .thenReturn(payloadMandate);

        StepVerifier.create(rule.evaluate(ctx, payload))
                .verifyComplete();
    }

    @Test
    void evaluate_failsWhenOrgDoesNotMatch() {
        LEARCredentialEmployee signer = buildSignerCredential("ORG-123");
        PolicyContext ctx = new PolicyContext("ORG-123", extractPowers(signer), signer, "LEARCredentialEmployee", false, null);

        JsonNode payload = mock(JsonNode.class);
        LEARCredentialEmployee.CredentialSubject.Mandate payloadMandate =
                LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                        .mandator(Mandator.builder().organizationIdentifier("ORG-OTHER").build())
                        .power(Collections.singletonList(
                                Power.builder().function("ProductOffering").action("Create").build()))
                        .build();
        when(objectMapper.convertValue(payload, LEARCredentialEmployee.CredentialSubject.Mandate.class))
                .thenReturn(payloadMandate);

        StepVerifier.create(rule.evaluate(ctx, payload))
                .expectErrorMatches(e ->
                        e instanceof InsufficientPermissionException &&
                                e.getMessage().contains("Mandator employee issuance policy not met"))
                .verify();
    }

    @Test
    void evaluate_failsWhenPowerIsNotProductOffering() {
        String orgId = "ORG-123";
        LEARCredentialEmployee signer = buildSignerCredential(orgId);
        PolicyContext ctx = new PolicyContext(orgId, extractPowers(signer), signer, "LEARCredentialEmployee", false, null);

        JsonNode payload = mock(JsonNode.class);
        LEARCredentialEmployee.CredentialSubject.Mandate payloadMandate =
                LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                        .mandator(Mandator.builder().organizationIdentifier(orgId).build())
                        .power(Collections.singletonList(
                                Power.builder().function("Onboarding").action("Execute").build()))
                        .build();
        when(objectMapper.convertValue(payload, LEARCredentialEmployee.CredentialSubject.Mandate.class))
                .thenReturn(payloadMandate);

        StepVerifier.create(rule.evaluate(ctx, payload))
                .expectErrorMatches(e ->
                        e instanceof InsufficientPermissionException &&
                                e.getMessage().contains("Mandator employee issuance policy not met"))
                .verify();
    }

    @Test
    void evaluate_failsWhenSignerMissingOnboardingPower() {
        String orgId = "ORG-123";
        // Signer without Onboarding/Execute power
        Mandator mandator = Mandator.builder().organizationIdentifier(orgId).build();
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
        PolicyContext ctx = new PolicyContext(orgId, extractPowers(signer), signer, "LEARCredentialEmployee", false, null);

        JsonNode payload = mock(JsonNode.class);

        StepVerifier.create(rule.evaluate(ctx, payload))
                .expectErrorMatches(e ->
                        e instanceof InsufficientPermissionException &&
                                e.getMessage().contains("Mandator employee issuance policy not met"))
                .verify();
    }
}
