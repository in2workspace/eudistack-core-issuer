package es.in2.issuer.backend.shared.infrastructure.config.security.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.exception.ParseErrorException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyContextFactory;
import es.in2.issuer.backend.shared.domain.policy.PolicyEnforcer;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireCertificationIssuanceRule;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.domain.util.DynamicCredentialParser;
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
    private DynamicCredentialParser credentialParser;

    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;

    private IssuancePdpServiceImpl issuancePdpService;

    @BeforeEach
    void setUp() {
        PolicyEnforcer policyEnforcer = new PolicyEnforcer();

        RequireCertificationIssuanceRule certificationRule = new RequireCertificationIssuanceRule(
                verifierService, jwtService, objectMapper, credentialParser);

        issuancePdpService = new IssuancePdpServiceImpl(
                policyContextFactory,
                policyEnforcer,
                objectMapper,
                certificationRule,
                credentialProfileRegistry,
                credentialParser
        );
    }

    private PolicyContext buildContextFromPowers(List<Power> powers, String credentialType,
                                                 String orgId, boolean sysAdmin) {
        return new PolicyContext(
                orgId,
                powers,
                null,
                null,
                credentialType,
                sysAdmin,
                null
        );
    }

    private PolicyContext buildContextWithCredential(List<Power> powers, String credentialType,
                                                     String orgId, boolean sysAdmin,
                                                     JsonNode credential, CredentialProfile profile) {
        return new PolicyContext(
                orgId,
                powers,
                credential,
                profile,
                credentialType,
                sysAdmin,
                null
        );
    }

    @Test
    void authorize_success_withLearCredentialEmployee() {
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        List<Power> signerPowers = List.of(
                Power.builder().function("Onboarding").action("Execute").build()
        );
        PolicyContext ctx = buildContextFromPowers(signerPowers, LEAR_CREDENTIAL_EMPLOYEE, ADMIN_ORG_ID, true);
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

        List<Power> signerPowers = List.of(
                Power.builder().function("Onboarding").action("Execute").build()
        );
        PolicyContext ctx = buildContextFromPowers(signerPowers, LEAR_CREDENTIAL_EMPLOYEE, ADMIN_ORG_ID, true);
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

        List<Power> signerPowers = List.of(
                Power.builder().function("Onboarding").action("Execute").build()
        );
        PolicyContext ctx = buildContextFromPowers(signerPowers, LEAR_CREDENTIAL_EMPLOYEE, "OTHER_ORGANIZATION", false);
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
        List<Power> emptyPowers = Collections.emptyList();
        PolicyContext ctx = buildContextFromPowers(emptyPowers, LEAR_CREDENTIAL_MACHINE, ADMIN_ORG_ID, true);
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

        List<Power> certificationPowers = List.of(
                Power.builder().function("Certification").action("Attest").build()
        );
        PolicyContext ctx = buildContextFromPowers(certificationPowers, LEAR_CREDENTIAL_MACHINE, "SomeOrganization", false);
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
        // Mock DynamicCredentialParser for id_token VC
        com.fasterxml.jackson.databind.node.ObjectNode idTokenVcNode = new ObjectMapper().createObjectNode();
        CredentialProfile idTokenProfile = mock(CredentialProfile.class);
        Power certPower = Power.builder().function("Certification").action("Attest").build();
        var parsed = new DynamicCredentialParser.ParsedCredential(idTokenVcNode, idTokenProfile, "LEARCredentialEmployee");
        when(credentialParser.parse("vcJson")).thenReturn(parsed);
        when(credentialParser.extractPowers(idTokenVcNode, idTokenProfile)).thenReturn(List.of(certPower));

        Mono<Void> result = issuancePdpService.authorize(token, LABEL_CREDENTIAL, payload, idToken);

        StepVerifier.create(result).verifyComplete();
    }

    @Test
    void authorize_failure_withLearCredentialEmployerRoleLear() {
        String token = "valid-token";
        JsonNode payload = mock(JsonNode.class);

        List<Power> certificationPowers = List.of(
                Power.builder().function("Certification").action("Attest").build()
        );
        PolicyContext ctx = buildContextFromPowers(certificationPowers, LEAR_CREDENTIAL_EMPLOYEE, "SomeOrganization", false);
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

        // Build a real JsonNode payload with mandator and power array
        ObjectMapper realMapper = new ObjectMapper();
        com.fasterxml.jackson.databind.node.ObjectNode payload = realMapper.createObjectNode();
        com.fasterxml.jackson.databind.node.ObjectNode mandatorNode = payload.putObject("mandator");
        mandatorNode.put("organizationIdentifier", "OTHER_ORGANIZATION");
        com.fasterxml.jackson.databind.node.ArrayNode powerArray = payload.putArray("power");
        com.fasterxml.jackson.databind.node.ObjectNode powerNode = powerArray.addObject();
        powerNode.put("function", "ProductOffering");
        com.fasterxml.jackson.databind.node.ArrayNode actionArray = powerNode.putArray("action");
        actionArray.add("Create").add("Update").add("Delete");

        // Signer has Onboarding/Execute + ProductOffering powers
        List<Power> signerPowers = List.of(
                Power.builder().function("Onboarding").action("Execute").build(),
                Power.builder().function("ProductOffering").action(List.of("Create", "Update", "Delete")).build()
        );

        // Context needs credential and profile for credentialParser.extractOrganizationId()
        JsonNode signerCredential = realMapper.createObjectNode();
        CredentialProfile signerProfile = mock(CredentialProfile.class);
        when(credentialParser.extractOrganizationId(signerCredential, signerProfile)).thenReturn("OTHER_ORGANIZATION");

        // objectMapper.convertValue is still used on the power array node inside the rule
        when(objectMapper.convertValue(any(JsonNode.class), any(com.fasterxml.jackson.core.type.TypeReference.class)))
                .thenAnswer(invocation -> {
                    JsonNode node = invocation.getArgument(0);
                    return realMapper.convertValue(node, new com.fasterxml.jackson.core.type.TypeReference<List<Power>>() {});
                });

        PolicyContext ctx = buildContextWithCredential(signerPowers, LEAR_CREDENTIAL_EMPLOYEE, "OTHER_ORGANIZATION", false, signerCredential, signerProfile);
        when(policyContextFactory.fromTokenForIssuance(eq(token), eq(LEAR_CREDENTIAL_EMPLOYEE), any()))
                .thenReturn(Mono.just(ctx));

        Mono<Void> result = issuancePdpService.authorize(token, LEAR_CREDENTIAL_EMPLOYEE, payload, "dummy-id-token");

        StepVerifier.create(result).verifyComplete();
    }

    @Test
    void authorize_failure_dueToInvalidPayloadPowers() {
        String token = "valid-token";

        // Build a real JsonNode payload with mandator and power array with wrong function
        ObjectMapper realMapper = new ObjectMapper();
        com.fasterxml.jackson.databind.node.ObjectNode payload = realMapper.createObjectNode();
        com.fasterxml.jackson.databind.node.ObjectNode mandatorNode = payload.putObject("mandator");
        mandatorNode.put("organizationIdentifier", "OTHER_ORGANIZATION");
        com.fasterxml.jackson.databind.node.ArrayNode powerArray = payload.putArray("power");
        com.fasterxml.jackson.databind.node.ObjectNode powerNode = powerArray.addObject();
        powerNode.put("function", "OtherFunction");
        powerNode.put("action", "SomeAction");

        // Signer has Onboarding/Execute power (needed to pass first check) but no ProductOffering
        List<Power> signerPowers = List.of(
                Power.builder().function("Onboarding").action("Execute").build()
        );

        // Context needs credential and profile for credentialParser.extractOrganizationId()
        JsonNode signerCredential = realMapper.createObjectNode();
        CredentialProfile signerProfile = mock(CredentialProfile.class);
        when(credentialParser.extractOrganizationId(signerCredential, signerProfile)).thenReturn("OTHER_ORGANIZATION");

        // objectMapper.convertValue is still used on the power array node inside the rule
        when(objectMapper.convertValue(any(JsonNode.class), any(com.fasterxml.jackson.core.type.TypeReference.class)))
                .thenAnswer(invocation -> {
                    JsonNode node = invocation.getArgument(0);
                    return realMapper.convertValue(node, new com.fasterxml.jackson.core.type.TypeReference<List<Power>>() {});
                });

        PolicyContext ctx = buildContextWithCredential(signerPowers, LEAR_CREDENTIAL_EMPLOYEE, "OTHER_ORGANIZATION", false, signerCredential, signerProfile);
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

        List<Power> signerPowers = List.of(
                Power.builder().function("Onboarding").action("Execute").build()
        );
        PolicyContext ctx = buildContextFromPowers(signerPowers, LEAR_CREDENTIAL_EMPLOYEE, ADMIN_ORG_ID, true);
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

        List<Power> signerPowers = List.of(
                Power.builder().function("Onboarding").action("Execute").build()
        );
        PolicyContext ctx = buildContextFromPowers(signerPowers, LEAR_CREDENTIAL_EMPLOYEE, ADMIN_ORG_ID, true);
        when(policyContextFactory.fromTokenForIssuance(eq(token), eq(LEAR_CREDENTIAL_MACHINE), any()))
                .thenReturn(Mono.just(ctx));

        Mono<Void> result = issuancePdpService.authorize(token, LEAR_CREDENTIAL_MACHINE, payload, "dummy-id-token");

        StepVerifier.create(result).verifyComplete();
    }

}
