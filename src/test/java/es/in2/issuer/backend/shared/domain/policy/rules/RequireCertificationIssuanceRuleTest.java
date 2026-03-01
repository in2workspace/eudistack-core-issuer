package es.in2.issuer.backend.shared.domain.policy.rules;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Mandator;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.machine.LEARCredentialMachine;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.domain.util.factory.CredentialFactory;
import es.in2.issuer.backend.shared.domain.util.factory.GenericCredentialBuilder;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialMachineFactory;
import es.in2.issuer.backend.shared.domain.util.factory.LabelCredentialFactory;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Utils.extractPowers;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RequireCertificationIssuanceRuleTest {

    @Mock
    private VerifierService verifierService;
    @Mock
    private JWTService jwtService;
    @Mock
    private ObjectMapper objectMapper;
    @Mock
    private LEARCredentialEmployeeFactory learCredentialEmployeeFactory;
    @Mock
    private LEARCredentialMachineFactory learCredentialMachineFactory;
    @Mock
    private LabelCredentialFactory labelCredentialFactory;
    @Mock
    private GenericCredentialBuilder genericCredentialBuilder;
    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;
    @Mock
    private CredentialProcedureService credentialProcedureService;
    @Mock
    private DeferredCredentialMetadataService deferredCredentialMetadataService;

    private RequireCertificationIssuanceRule rule;

    @BeforeEach
    void setUp() {
        CredentialFactory credentialFactory = new CredentialFactory(
                learCredentialEmployeeFactory,
                learCredentialMachineFactory,
                labelCredentialFactory,
                genericCredentialBuilder,
                credentialProfileRegistry,
                credentialProcedureService,
                deferredCredentialMetadataService
        );
        rule = new RequireCertificationIssuanceRule(verifierService, jwtService, objectMapper, credentialFactory);
    }

    private LEARCredentialMachine buildMachineCredentialWithPower(String function, String action) {
        Power power = Power.builder().function(function).action(action).build();
        return LEARCredentialMachine.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialMachine"))
                .credentialSubject(LEARCredentialMachine.CredentialSubject.builder()
                        .mandate(LEARCredentialMachine.CredentialSubject.Mandate.builder()
                                .mandator(LEARCredentialMachine.CredentialSubject.Mandate.Mandator.builder()
                                        .organization("Org").build())
                                .mandatee(LEARCredentialMachine.CredentialSubject.Mandate.Mandatee.builder()
                                        .id("did:key:1234").build())
                                .power(Collections.singletonList(power))
                                .build())
                        .build())
                .build();
    }

    private LEARCredentialEmployee buildEmployeeCredentialWithPower(String function, String action) {
        Mandator mandator = Mandator.builder().organizationIdentifier("Org").build();
        Power power = Power.builder().function(function).action(action).build();
        return LEARCredentialEmployee.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .credentialSubject(LEARCredentialEmployee.CredentialSubject.builder()
                        .mandate(LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                                .mandator(mandator)
                                .mandatee(LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.builder()
                                        .id("did:key:5678").firstName("Jane").lastName("Doe")
                                        .email("jane@example.com").build())
                                .power(Collections.singletonList(power))
                                .build())
                        .build())
                .build();
    }

    @Test
    void evaluate_succeedsWhenBothSignerAndIdTokenHaveCertificationAttest() throws Exception {
        // Signer with Certification/Attest
        var signer = buildMachineCredentialWithPower("Certification", "Attest");
        PolicyContext ctx = new PolicyContext("Org", extractPowers(signer), signer, "LEARCredentialMachine", false, null);

        String idToken = "dummy-id-token";

        SignedJWT idTokenJWT = mock(SignedJWT.class);
        Payload idTokenPayload = new Payload(new HashMap<>());
        when(idTokenJWT.getPayload()).thenReturn(idTokenPayload);
        when(verifierService.verifyTokenWithoutExpiration(idToken)).thenReturn(Mono.empty());
        when(jwtService.parseJWT(idToken)).thenReturn(idTokenJWT);
        when(jwtService.getClaimFromPayload(idTokenPayload, "vc_json")).thenReturn("\"vcJson\"");
        when(objectMapper.readValue("\"vcJson\"", String.class)).thenReturn("vcJson");

        var idTokenCredential = buildEmployeeCredentialWithPower("Certification", "Attest");
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee("vcJson"))
                .thenReturn(idTokenCredential);

        StepVerifier.create(rule.evaluate(ctx, idToken))
                .verifyComplete();
    }

    @Test
    void evaluate_failsWhenSignerLacksCertificationPower() {
        var signer = buildMachineCredentialWithPower("Onboarding", "Execute");
        PolicyContext ctx = new PolicyContext("Org", extractPowers(signer), signer, "LEARCredentialMachine", false, null);

        StepVerifier.create(rule.evaluate(ctx, "dummy-id-token"))
                .expectErrorMatches(e ->
                        e instanceof InsufficientPermissionException &&
                                e.getMessage().contains("Signer credential does not have Certification/Attest power"))
                .verify();
    }

    @Test
    void evaluate_failsWhenIdTokenLacksCertificationPower() throws Exception {
        var signer = buildMachineCredentialWithPower("Certification", "Attest");
        PolicyContext ctx = new PolicyContext("Org", extractPowers(signer), signer, "LEARCredentialMachine", false, null);

        String idToken = "dummy-id-token";

        SignedJWT idTokenJWT = mock(SignedJWT.class);
        Payload idTokenPayload = new Payload(new HashMap<>());
        when(idTokenJWT.getPayload()).thenReturn(idTokenPayload);
        when(verifierService.verifyTokenWithoutExpiration(idToken)).thenReturn(Mono.empty());
        when(jwtService.parseJWT(idToken)).thenReturn(idTokenJWT);
        when(jwtService.getClaimFromPayload(idTokenPayload, "vc_json")).thenReturn("\"vcJson\"");
        when(objectMapper.readValue("\"vcJson\"", String.class)).thenReturn("vcJson");

        // idToken credential with wrong power
        var idTokenCredential = buildEmployeeCredentialWithPower("Onboarding", "Execute");
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee("vcJson"))
                .thenReturn(idTokenCredential);

        StepVerifier.create(rule.evaluate(ctx, idToken))
                .expectErrorMatches(e ->
                        e instanceof InsufficientPermissionException &&
                                e.getMessage().contains("ID token credential does not have Certification/Attest power"))
                .verify();
    }
}
