package es.in2.issuer.backend.shared.infrastructure.config.security.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.exception.ParseErrorException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.LEARCredential;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Mandator;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.employee.LEARCredentialEmployee;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.machine.LEARCredentialMachine;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyContextFactory;
import es.in2.issuer.backend.shared.domain.policy.PolicyEnforcer;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireCertificationIssuanceRule;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.domain.util.factory.LEARCredentialEmployeeFactory;
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

import static es.in2.issuer.backend.shared.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.util.Utils.extractPowers;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IssuancePdpServiceImplTest {

    private static final String ADMIN_ORG_ID = "IN2_ADMIN_ORG_ID_FOR_TEST";

    @Mock
    private PolicyContextFactory policyContextFactory;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private JWTService jwtService;

    @Mock
    private VerifierService verifierService;

    @Mock
    private LEARCredentialEmployeeFactory learCredentialEmployeeFactory;

    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;

    private IssuancePdpServiceImpl issuancePdpService;

    @BeforeEach
    void setUp() {
        PolicyEnforcer policyEnforcer = new PolicyEnforcer();

        RequireCertificationIssuanceRule certificationRule = new RequireCertificationIssuanceRule(
                verifierService, jwtService, objectMapper, learCredentialEmployeeFactory);

        issuancePdpService = new IssuancePdpServiceImpl(
                policyContextFactory,
                policyEnforcer,
                objectMapper,
                certificationRule,
                credentialProfileRegistry
        );
    }

    private PolicyContext buildContext(LEARCredential credential, String credentialType,
                                      String orgId, boolean sysAdmin) {
        return new PolicyContext(
                orgId,
                extractPowers(credential),
                credential,
                credentialType,
                sysAdmin,
                null
        );
    }

    @Test
    void authorize_success_withLearCredentialEmployee() {
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        LEARCredentialEmployee learCredential = getLEARCredentialEmployee();
        PolicyContext ctx = buildContext(learCredential, LEAR_CREDENTIAL_EMPLOYEE, ADMIN_ORG_ID, true);
        when(policyContextFactory.fromTokenForIssuance(eq(token), eq(LEAR_CREDENTIAL_EMPLOYEE), any()))
                .thenReturn(Mono.just(ctx));

        Mono<Void> result = issuancePdpService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        StepVerifier.create(result).verifyComplete();
    }

    @Test
    void authorize_failure_dueToInvalidCredentialType() {
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        when(policyContextFactory.fromTokenForIssuance(eq(token), eq(LEAR_CREDENTIAL_EMPLOYEE), any()))
                .thenReturn(Mono.error(new InsufficientPermissionException(
                        "Unauthorized: Credential type 'LEARCredentialEmployee' or 'LEARCredentialMachine' is required.")));

        Mono<Void> result = issuancePdpService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException &&
                                throwable.getMessage().contains("Unauthorized: Credential type 'LEARCredentialEmployee' or 'LEARCredentialMachine' is required."))
                .verify();
    }

    @Test
    void authorize_failure_dueToUnsupportedSchema() {
        String token = "valid-token";
        String schema = "UnsupportedSchema";
        JsonNode payload = mock(JsonNode.class);

        LEARCredentialEmployee learCredential = getLEARCredentialEmployee();
        PolicyContext ctx = buildContext(learCredential, LEAR_CREDENTIAL_EMPLOYEE, ADMIN_ORG_ID, true);
        when(policyContextFactory.fromTokenForIssuance(eq(token), eq(schema), any()))
                .thenReturn(Mono.just(ctx));

        Mono<Void> result = issuancePdpService.authorize(token, schema, payload, "dummy-id-token");

        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException &&
                                throwable.getMessage().contains("Unauthorized: Unsupported schema"))
                .verify();
    }

    @Test
    void authorize_failure_dueToInvalidToken() {
        String token = "invalid-token";
        JsonNode payload = mock(JsonNode.class);

        when(policyContextFactory.fromTokenForIssuance(eq(token), eq(LEAR_CREDENTIAL_EMPLOYEE), any()))
                .thenReturn(Mono.error(new ParseErrorException("Invalid token")));

        Mono<Void> result = issuancePdpService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof ParseErrorException &&
                                throwable.getMessage().contains("Invalid token"))
                .verify();
    }

    @Test
    void authorize_failure_dueToIssuancePoliciesNotMet() {
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        LEARCredentialEmployee learCredential = getLEARCredentialEmployeeWithDifferentOrg();
        PolicyContext ctx = buildContext(learCredential, LEAR_CREDENTIAL_EMPLOYEE, "OTHER_ORGANIZATION", false);
        when(policyContextFactory.fromTokenForIssuance(eq(token), eq(LEAR_CREDENTIAL_EMPLOYEE), any()))
                .thenReturn(Mono.just(ctx));

        Mono<Void> result = issuancePdpService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException &&
                                throwable.getMessage().contains("Unauthorized: LEARCredentialEmployee does not meet any issuance policies."))
                .verify();
    }

    @Test
    void authorize_failure_dueToVerifiableCertificationPolicyNotMet() {
        String token = "valid-token";
        String idToken = "dummy-id-token";
        JsonNode payload = mock(JsonNode.class);

        // Signer has empty powers — short-circuits before idToken validation
        LEARCredentialMachine learCredential = getLEARCredentialMachineWithInvalidPolicy();
        PolicyContext ctx = buildContext(learCredential, LEAR_CREDENTIAL_MACHINE, ADMIN_ORG_ID, true);
        when(policyContextFactory.fromTokenForIssuance(eq(token), eq(LABEL_CREDENTIAL), any()))
                .thenReturn(Mono.just(ctx));

        Mono<Void> result = issuancePdpService.authorize(token, LABEL_CREDENTIAL, payload, idToken);

        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException)
                .verify();
    }

    @Test
    void authorize_success_withVerifiableCertification() throws Exception {
        String token = "valid-token";
        String idToken = "dummy-id-token";
        JsonNode payload = mock(JsonNode.class);

        LEARCredentialMachine learCredential = getLEARCredentialMachineForCertification();
        PolicyContext ctx = buildContext(learCredential, LEAR_CREDENTIAL_MACHINE, "SomeOrganization", false);
        when(policyContextFactory.fromTokenForIssuance(eq(token), eq(LABEL_CREDENTIAL), any()))
                .thenReturn(Mono.just(ctx));

        // id_token mocks
        SignedJWT idTokenSignedJWT = mock(SignedJWT.class);
        Payload idTokenPayload = new Payload(new HashMap<>());
        when(idTokenSignedJWT.getPayload()).thenReturn(idTokenPayload);
        when(verifierService.verifyTokenWithoutExpiration(idToken)).thenReturn(Mono.empty());
        when(jwtService.parseJWT(idToken)).thenReturn(idTokenSignedJWT);
        when(jwtService.getClaimFromPayload(idTokenPayload, "vc_json")).thenReturn("\"vcJson\"");
        when(objectMapper.readValue("\"vcJson\"", String.class)).thenReturn("vcJson");
        LEARCredentialEmployee idTokenCredential = getLEARCredentialEmployeeForCertification();
        when(learCredentialEmployeeFactory.mapStringToLEARCredentialEmployee("vcJson")).thenReturn(idTokenCredential);

        Mono<Void> result = issuancePdpService.authorize(token, LABEL_CREDENTIAL, payload, idToken);

        StepVerifier.create(result).verifyComplete();
    }

    @Test
    void authorize_failure_withLearCredentialEmployerRoleLear() {
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        LEARCredentialEmployee learCredential = getLEARCredentialEmployeeForCertification();
        PolicyContext ctx = buildContext(learCredential, LEAR_CREDENTIAL_EMPLOYEE, "SomeOrganization", false);
        when(policyContextFactory.fromTokenForIssuance(eq(token), eq(LEAR_CREDENTIAL_EMPLOYEE), any()))
                .thenReturn(Mono.just(ctx));

        Mono<Void> result = issuancePdpService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException &&
                                throwable.getMessage().contains("Unauthorized: LEARCredentialEmployee does not meet any issuance policies."))
                .verify();
    }

    @Test
    void authorize_success_withMandatorIssuancePolicyValid() {
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        LEARCredentialEmployee learCredential = getLEARCredentialEmployeeWithDifferentOrg();

        LEARCredentialEmployee.CredentialSubject.Mandate mandateFromPayload = LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                .mandator(Mandator.builder()
                        .organizationIdentifier(learCredential.credentialSubject().mandate().mandator().organizationIdentifier())
                        .serialNumber(learCredential.credentialSubject().mandate().mandator().serialNumber())
                        .country(learCredential.credentialSubject().mandate().mandator().country())
                        .commonName(learCredential.credentialSubject().mandate().mandator().commonName())
                        .email(learCredential.credentialSubject().mandate().mandator().email())
                        .build())
                .power(Collections.singletonList(
                        Power.builder()
                                .function("ProductOffering")
                                .action(List.of("Create", "Update", "Delete"))
                                .build()))
                .build();
        when(objectMapper.convertValue(payload, LEARCredentialEmployee.CredentialSubject.Mandate.class)).thenReturn(mandateFromPayload);

        PolicyContext ctx = buildContext(learCredential, LEAR_CREDENTIAL_EMPLOYEE, "OTHER_ORGANIZATION", false);
        when(policyContextFactory.fromTokenForIssuance(eq(token), eq(LEAR_CREDENTIAL_EMPLOYEE), any()))
                .thenReturn(Mono.just(ctx));

        Mono<Void> result = issuancePdpService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        StepVerifier.create(result).verifyComplete();
    }

    @Test
    void authorize_failure_dueToInvalidPayloadPowers() {
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        LEARCredentialEmployee learCredential = getLEARCredentialEmployeeWithDifferentOrg();

        LEARCredentialEmployee.CredentialSubject.Mandate mandateFromPayload = LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                .mandator(Mandator.builder()
                        .organizationIdentifier(learCredential.credentialSubject().mandate().mandator().organizationIdentifier())
                        .serialNumber(learCredential.credentialSubject().mandate().mandator().serialNumber())
                        .country(learCredential.credentialSubject().mandate().mandator().country())
                        .commonName(learCredential.credentialSubject().mandate().mandator().commonName())
                        .email(learCredential.credentialSubject().mandate().mandator().email())
                        .build())
                .power(Collections.singletonList(
                        Power.builder()
                                .function("OtherFunction")
                                .action("SomeAction")
                                .build()))
                .build();
        when(objectMapper.convertValue(payload, LEARCredentialEmployee.CredentialSubject.Mandate.class)).thenReturn(mandateFromPayload);

        PolicyContext ctx = buildContext(learCredential, LEAR_CREDENTIAL_EMPLOYEE, "OTHER_ORGANIZATION", false);
        when(policyContextFactory.fromTokenForIssuance(eq(token), eq(LEAR_CREDENTIAL_EMPLOYEE), any()))
                .thenReturn(Mono.just(ctx));

        Mono<Void> result = issuancePdpService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        StepVerifier.create(result)
                .expectErrorMatches(throwable ->
                        throwable instanceof InsufficientPermissionException &&
                                throwable.getMessage().contains("Unauthorized: LEARCredentialEmployee does not meet any issuance policies."))
                .verify();
    }

    @Test
    void authorize_success_withLearCredentialMachine() {
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        LEARCredentialEmployee signerEmployee = getLEARCredentialEmployee();
        PolicyContext ctx = buildContext(signerEmployee, LEAR_CREDENTIAL_EMPLOYEE, ADMIN_ORG_ID, true);
        when(policyContextFactory.fromTokenForIssuance(eq(token), eq(LEAR_CREDENTIAL_MACHINE), any()))
                .thenReturn(Mono.just(ctx));

        Mono<Void> result = issuancePdpService.authorize(token, LEAR_CREDENTIAL_MACHINE, payload, "dummy-id-token");

        StepVerifier.create(result).verifyComplete();
    }

    @Test
    void authorize_failure_withLearCredentialMachine_dueToPolicy() {
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        when(policyContextFactory.fromTokenForIssuance(eq(token), eq("LEAR_CREDENTIAL_MACHINE"), any()))
                .thenReturn(Mono.error(new InsufficientPermissionException(
                        "Unauthorized: Credential type 'LEARCredentialEmployee' is required for LEARCredentialMachine.")));

        Mono<Void> result = issuancePdpService.authorize(token, "LEAR_CREDENTIAL_MACHINE", payload, "dummy-id-token");

        StepVerifier.create(result)
                .expectErrorMatches(InsufficientPermissionException.class::isInstance)
                .verify();
    }

    @Test
    void authorize_machine_success_whenMandatorAllowed_and_OnboardingExecute() {
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        LEARCredentialEmployee signerEmployee = getLEARCredentialEmployee();
        PolicyContext ctx = buildContext(signerEmployee, LEAR_CREDENTIAL_EMPLOYEE, ADMIN_ORG_ID, true);
        when(policyContextFactory.fromTokenForIssuance(eq(token), eq(LEAR_CREDENTIAL_MACHINE), any()))
                .thenReturn(Mono.just(ctx));

        Mono<Void> result = issuancePdpService.authorize(token, LEAR_CREDENTIAL_MACHINE, payload, "dummy-id-token");

        StepVerifier.create(result).verifyComplete();
    }

    // --- Credential helper methods ---

    private LEARCredentialEmployee getLEARCredentialEmployee() {
        Mandator mandator = Mandator.builder()
                .organizationIdentifier(ADMIN_ORG_ID)
                .build();
        LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.builder()
                        .id("did:key:1234")
                        .firstName("John")
                        .lastName("Doe")
                        .email("john.doe@example.com")
                        .build();
        Power power = Power.builder()
                .function("Onboarding")
                .action("Execute")
                .build();
        LEARCredentialEmployee.CredentialSubject.Mandate mandate =
                LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                        .mandator(mandator)
                        .mandatee(mandatee)
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

    private LEARCredentialEmployee getLEARCredentialEmployeeWithDifferentOrg() {
        Mandator mandator = Mandator.builder()
                .organizationIdentifier("OTHER_ORGANIZATION")
                .commonName("SomeOtherOrganization")
                .country("ES")
                .email("someaddres@example.com")
                .serialNumber("123456")
                .build();
        LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.builder()
                        .id("did:key:1234")
                        .firstName("John")
                        .lastName("Doe")
                        .email("john.doe@example.com")
                        .build();
        Power power = Power.builder()
                .function("Onboarding")
                .action("Execute")
                .build();
        LEARCredentialEmployee.CredentialSubject.Mandate mandate =
                LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                        .mandator(mandator)
                        .mandatee(mandatee)
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

    private LEARCredentialMachine getLEARCredentialMachineForCertification() {
        LEARCredentialMachine.CredentialSubject.Mandate.Mandator mandator =
                LEARCredentialMachine.CredentialSubject.Mandate.Mandator.builder()
                        .organization("SomeOrganization")
                        .build();
        LEARCredentialMachine.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialMachine.CredentialSubject.Mandate.Mandatee.builder()
                        .id("did:key:1234")
                        .build();
        Power power = Power.builder()
                .function("Certification")
                .action("Attest")
                .build();
        LEARCredentialMachine.CredentialSubject.Mandate mandate =
                LEARCredentialMachine.CredentialSubject.Mandate.builder()
                        .mandator(mandator)
                        .mandatee(mandatee)
                        .power(Collections.singletonList(power))
                        .build();
        LEARCredentialMachine.CredentialSubject credentialSubject =
                LEARCredentialMachine.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();
        return LEARCredentialMachine.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialMachine"))
                .credentialSubject(credentialSubject)
                .build();
    }

    private LEARCredentialEmployee getLEARCredentialEmployeeForCertification() {
        Mandator mandator = Mandator.builder()
                .organizationIdentifier("SomeOrganization")
                .build();
        LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialEmployee.CredentialSubject.Mandate.Mandatee.builder()
                        .id("did:key:1234")
                        .firstName("Jane")
                        .lastName("Doe")
                        .email("jane.doe@example.com")
                        .build();
        Power power = Power.builder()
                .function("Certification")
                .action("Attest")
                .build();
        LEARCredentialEmployee.CredentialSubject.Mandate mandate =
                LEARCredentialEmployee.CredentialSubject.Mandate.builder()
                        .mandator(mandator)
                        .mandatee(mandatee)
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

    private LEARCredentialMachine getLEARCredentialMachineWithInvalidPolicy() {
        LEARCredentialMachine.CredentialSubject.Mandate.Mandator mandator =
                LEARCredentialMachine.CredentialSubject.Mandate.Mandator.builder()
                        .organization(ADMIN_ORG_ID)
                        .build();
        LEARCredentialMachine.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialMachine.CredentialSubject.Mandate.Mandatee.builder()
                        .id("did:key:1234")
                        .build();
        List<Power> emptyPowers = Collections.emptyList();
        LEARCredentialMachine.CredentialSubject.Mandate mandate =
                LEARCredentialMachine.CredentialSubject.Mandate.builder()
                        .mandator(mandator)
                        .mandatee(mandatee)
                        .power(emptyPowers)
                        .build();
        LEARCredentialMachine.CredentialSubject credentialSubject =
                LEARCredentialMachine.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();
        return LEARCredentialMachine.builder()
                .type(List.of("VerifiableCredential", "LEARCredentialMachine"))
                .credentialSubject(credentialSubject)
                .build();
    }
}
