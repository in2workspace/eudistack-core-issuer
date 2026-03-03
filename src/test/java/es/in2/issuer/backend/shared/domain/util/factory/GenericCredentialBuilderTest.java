package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.SimpleIssuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;

import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_EMPLOYEE;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GenericCredentialBuilderTest {

    @Spy
    private ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private IssuerFactory issuerFactory;

    @Mock
    private AccessTokenService accessTokenService;

    @InjectMocks
    private GenericCredentialBuilder genericCredentialBuilder;

    // --- buildCredential ---

    @Test
    void buildCredential_shouldBuildW3cVcdmWithCorrectStructure() {
        CredentialProfile profile = employeeProfile();
        JsonNode payload = mandatePayload();
        CredentialStatus status = credentialStatus();

        StepVerifier.create(genericCredentialBuilder.buildCredential(
                        profile, "proc-1", payload, status, "S", "test@example.com"))
                .assertNext(request -> {
                    assertThat(request.procedureId()).isEqualTo("proc-1");
                    assertThat(request.credentialType()).isEqualTo(LEAR_CREDENTIAL_EMPLOYEE);
                    assertThat(request.operationMode()).isEqualTo("S");
                    assertThat(request.email()).isEqualTo("test@example.com");
                    assertThat(request.subject()).isEqualTo("John Doe");
                    assertThat(request.organizationIdentifier()).isEqualTo("VATES-B12345678");
                    assertThat(request.validUntil()).isNotNull();

                    // Verify credential JSON structure
                    assertThat(request.credentialDecoded()).contains("\"@context\"");
                    assertThat(request.credentialDecoded()).contains("\"VerifiableCredential\"");
                    assertThat(request.credentialDecoded()).contains("\"LEARCredentialEmployee\"");
                    assertThat(request.credentialDecoded()).contains("\"credentialSubject\"");
                    assertThat(request.credentialDecoded()).contains("\"mandate\"");
                    assertThat(request.credentialDecoded()).contains("\"validFrom\"");
                    assertThat(request.credentialDecoded()).contains("\"validUntil\"");
                    assertThat(request.credentialDecoded()).contains("\"credentialStatus\"");
                })
                .verifyComplete();
    }

    @Test
    void buildCredential_shouldUsePayloadDatesWhenValidityDaysIsZero() {
        CredentialProfile profile = labelProfile();
        String fixedFrom = "2025-01-01T00:00:00Z";
        String fixedUntil = "2026-01-01T00:00:00Z";

        JsonNode payload = objectMapper.createObjectNode()
                .put("validFrom", fixedFrom)
                .put("validUntil", fixedUntil);

        when(accessTokenService.getOrganizationIdFromCurrentSession()).thenReturn(Mono.just("ORG-123"));

        StepVerifier.create(genericCredentialBuilder.buildCredential(
                        profile, "proc-2", payload, credentialStatus(), "S", "test@example.com"))
                .assertNext(request -> {
                    assertThat(request.credentialDecoded()).contains(fixedFrom);
                    assertThat(request.credentialDecoded()).contains(fixedUntil);
                })
                .verifyComplete();
    }

    @Test
    void buildCredential_shouldUseSessionOrganizationExtraction() {
        CredentialProfile profile = labelProfile();
        JsonNode payload = objectMapper.createObjectNode();

        when(accessTokenService.getOrganizationIdFromCurrentSession()).thenReturn(Mono.just("SESSION-ORG-ID"));

        StepVerifier.create(genericCredentialBuilder.buildCredential(
                        profile, "proc-3", payload, credentialStatus(), "S", "test@example.com"))
                .assertNext(request ->
                        assertThat(request.organizationIdentifier()).isEqualTo("SESSION-ORG-ID"))
                .verifyComplete();
    }

    @Test
    void buildCredential_shouldExtractSubjectWithConcatStrategy() {
        CredentialProfile profile = employeeProfile();
        JsonNode payload = mandatePayload();

        StepVerifier.create(genericCredentialBuilder.buildCredential(
                        profile, "proc-4", payload, credentialStatus(), "S", "test@example.com"))
                .assertNext(request ->
                        assertThat(request.subject()).isEqualTo("John Doe"))
                .verifyComplete();
    }

    @Test
    void buildCredential_shouldExtractSubjectWithFieldStrategy() {
        CredentialProfile profile = machineProfile();

        com.fasterxml.jackson.databind.node.ObjectNode mandateNode = objectMapper.createObjectNode();
        mandateNode.set("mandatee", objectMapper.createObjectNode()
                .put("domain", "api.example.com"));
        mandateNode.set("mandator", objectMapper.createObjectNode()
                .put("organizationIdentifier", "VATES-X99999999"));
        com.fasterxml.jackson.databind.node.ObjectNode payloadRoot = objectMapper.createObjectNode();
        payloadRoot.set("mandate", mandateNode);
        JsonNode payload = payloadRoot;

        StepVerifier.create(genericCredentialBuilder.buildCredential(
                        profile, "proc-5", payload, credentialStatus(), "S", "test@example.com"))
                .assertNext(request ->
                        assertThat(request.subject()).isEqualTo("api.example.com"))
                .verifyComplete();
    }

    @Test
    void buildCredential_shouldIncludeDescriptionWhenPresent() {
        CredentialProfile profile = employeeProfile();
        JsonNode payload = mandatePayload();

        StepVerifier.create(genericCredentialBuilder.buildCredential(
                        profile, "proc-6", payload, credentialStatus(), "S", "test@example.com"))
                .assertNext(request ->
                        assertThat(request.credentialDecoded()).contains("\"description\""))
                .verifyComplete();
    }

    // --- bindSubjectId ---

    @Test
    void bindSubjectId_shouldSetCredentialSubjectId() {
        String credential = """
                {
                  "credentialSubject": {
                    "mandate": {}
                  }
                }
                """;

        StepVerifier.create(genericCredentialBuilder.bindSubjectId(credential, "did:key:z123"))
                .assertNext(result -> {
                    assertThat(result).contains("\"id\":\"did:key:z123\"");
                    assertThat(result).contains("\"mandate\"");
                })
                .verifyComplete();
    }

    @Test
    void bindSubjectId_shouldFailWhenCredentialSubjectMissing() {
        String credential = """
                {
                  "type": "VerifiableCredential"
                }
                """;

        StepVerifier.create(genericCredentialBuilder.bindSubjectId(credential, "did:key:z123"))
                .expectErrorMatches(e -> e instanceof IllegalStateException
                        && e.getMessage().contains("Missing credentialSubject"))
                .verify();
    }

    // --- bindIssuer ---

    @Test
    void bindIssuer_shouldUseDetailedIssuerForDetailedType() {
        CredentialProfile profile = employeeProfile();
        String credential = """
                {
                  "credentialSubject": {"mandate": {}}
                }
                """;

        DetailedIssuer detailedIssuer = DetailedIssuer.builder()
                .id("did:key:issuer123")
                .build();

        when(issuerFactory.createDetailedIssuerAndNotifyOnError(anyString(), anyString()))
                .thenReturn(Mono.just(detailedIssuer));

        StepVerifier.create(genericCredentialBuilder.bindIssuer(profile, credential, "proc-1", "admin@example.com"))
                .assertNext(result -> assertThat(result).contains("issuer"))
                .verifyComplete();
    }

    @Test
    void bindIssuer_shouldUseSimpleIssuerForSimpleType() {
        CredentialProfile profile = labelProfile();
        String credential = """
                {
                  "credentialSubject": {"mandate": {}}
                }
                """;

        SimpleIssuer simpleIssuer = new SimpleIssuer("did:key:simple-issuer");

        when(issuerFactory.createSimpleIssuerAndNotifyOnError(anyString(), anyString()))
                .thenReturn(Mono.just(simpleIssuer));

        StepVerifier.create(genericCredentialBuilder.bindIssuer(profile, credential, "proc-2", "admin@example.com"))
                .assertNext(result -> assertThat(result).contains("did:key:simple-issuer"))
                .verifyComplete();
    }

    // --- buildJwtPayload ---

    @Test
    void buildJwtPayload_shouldBuildJwtWithCnfWhenRequired() {
        CredentialProfile profile = employeeProfile();
        String now = Instant.now().toString();
        String future = Instant.now().plus(365, ChronoUnit.DAYS).toString();

        String credential = String.format("""
                {
                  "issuer": {"id": "did:key:issuer1"},
                  "credentialSubject": {"id": "did:key:subject1", "mandate": {}},
                  "validFrom": "%s",
                  "validUntil": "%s"
                }
                """, now, future);

        Map<String, Object> cnf = Map.of("kid", "did:key:subject1#key1");

        StepVerifier.create(genericCredentialBuilder.buildJwtPayload(profile, credential, cnf))
                .assertNext(payload -> {
                    assertThat(payload).contains("\"jti\"");
                    assertThat(payload).contains("\"iss\":\"did:key:issuer1\"");
                    assertThat(payload).contains("\"sub\":\"did:key:subject1\"");
                    assertThat(payload).contains("\"vc\"");
                    assertThat(payload).contains("\"cnf\"");
                    assertThat(payload).contains("\"kid\"");
                    assertThat(payload).contains("\"iat\"");
                    assertThat(payload).contains("\"exp\"");
                    assertThat(payload).contains("\"nbf\"");
                })
                .verifyComplete();
    }

    @Test
    void buildJwtPayload_shouldOmitCnfWhenNotRequired() {
        CredentialProfile profile = labelProfile();
        String now = Instant.now().toString();
        String future = Instant.now().plus(365, ChronoUnit.DAYS).toString();

        String credential = String.format("""
                {
                  "issuer": "did:key:simple-issuer",
                  "credentialSubject": {"id": "did:key:subject1"},
                  "validFrom": "%s",
                  "validUntil": "%s"
                }
                """, now, future);

        StepVerifier.create(genericCredentialBuilder.buildJwtPayload(profile, credential, null))
                .assertNext(payload -> {
                    assertThat(payload).contains("\"iss\":\"did:key:simple-issuer\"");
                    assertThat(payload).doesNotContain("\"cnf\"");
                })
                .verifyComplete();
    }

    @Test
    void buildJwtPayload_shouldFailWhenCnfRequiredButMissing() {
        CredentialProfile profile = employeeProfile();
        String now = Instant.now().toString();
        String future = Instant.now().plus(365, ChronoUnit.DAYS).toString();

        String credential = String.format("""
                {
                  "issuer": {"id": "did:key:issuer1"},
                  "credentialSubject": {"id": "did:key:subject1"},
                  "validFrom": "%s",
                  "validUntil": "%s"
                }
                """, now, future);

        StepVerifier.create(genericCredentialBuilder.buildJwtPayload(profile, credential, null))
                .expectErrorMatches(e -> e instanceof IllegalStateException
                        && e.getMessage().contains("Missing cnf"))
                .verify();
    }

    @Test
    void buildJwtPayload_shouldFailWhenCnfHasMultipleKeys() {
        CredentialProfile profile = employeeProfile();
        String now = Instant.now().toString();
        String future = Instant.now().plus(365, ChronoUnit.DAYS).toString();

        String credential = String.format("""
                {
                  "issuer": {"id": "did:key:issuer1"},
                  "credentialSubject": {"id": "did:key:subject1"},
                  "validFrom": "%s",
                  "validUntil": "%s"
                }
                """, now, future);

        Map<String, Object> cnf = Map.of("kid", "value1", "jwk", Map.of("kty", "EC"));

        StepVerifier.create(genericCredentialBuilder.buildJwtPayload(profile, credential, cnf))
                .expectErrorMatches(e -> e instanceof IllegalStateException
                        && e.getMessage().contains("Invalid cnf"))
                .verify();
    }

    @Test
    void buildJwtPayload_shouldExtractIssuerIdFromStringIssuer() {
        CredentialProfile profile = labelProfile();
        String now = Instant.now().toString();
        String future = Instant.now().plus(365, ChronoUnit.DAYS).toString();

        String credential = String.format("""
                {
                  "issuer": "did:key:string-issuer",
                  "credentialSubject": {"id": "did:key:sub"},
                  "validFrom": "%s",
                  "validUntil": "%s"
                }
                """, now, future);

        StepVerifier.create(genericCredentialBuilder.buildJwtPayload(profile, credential, null))
                .assertNext(payload ->
                        assertThat(payload).contains("\"iss\":\"did:key:string-issuer\""))
                .verifyComplete();
    }

    // --- Helper methods ---

    private CredentialProfile employeeProfile() {
        return CredentialProfile.builder()
                .credentialConfigurationId("LEARCredentialEmployee")
                .format("jwt_vc_json")
                .scope("lear_credential_employee")
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .context(List.of("https://www.w3.org/ns/credentials/v2"))
                        .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                        .build())
                .cryptographicBindingMethodsSupported(Set.of("did:key"))
                .credentialSigningAlgValuesSupported(Set.of("ES256"))
                .validityDays(365)
                .issuerType(CredentialProfile.IssuerType.DETAILED)
                .cnfRequired(true)
                .description("Verifiable Credential for employees of an organization")
                .subjectExtraction(CredentialProfile.SubjectExtraction.builder()
                        .strategy("concat")
                        .fields(List.of("mandate.mandatee.firstName", "mandate.mandatee.lastName"))
                        .separator(" ")
                        .build())
                .organizationExtraction(CredentialProfile.OrganizationExtraction.builder()
                        .strategy("field")
                        .field("mandate.mandator.organizationIdentifier")
                        .build())
                .build();
    }

    private CredentialProfile machineProfile() {
        return CredentialProfile.builder()
                .credentialConfigurationId("LEARCredentialMachine")
                .format("jwt_vc_json")
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .context(List.of("https://www.w3.org/ns/credentials/v2"))
                        .type(List.of("VerifiableCredential", "LEARCredentialMachine"))
                        .build())
                .validityDays(365)
                .issuerType(CredentialProfile.IssuerType.DETAILED)
                .cnfRequired(true)
                .subjectExtraction(CredentialProfile.SubjectExtraction.builder()
                        .strategy("field")
                        .fields(List.of("mandate.mandatee.domain"))
                        .build())
                .organizationExtraction(CredentialProfile.OrganizationExtraction.builder()
                        .strategy("field")
                        .field("mandate.mandator.organizationIdentifier")
                        .build())
                .build();
    }

    private CredentialProfile labelProfile() {
        return CredentialProfile.builder()
                .credentialConfigurationId("gx:LabelCredential")
                .format("jwt_vc_json")
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .context(List.of("https://www.w3.org/ns/credentials/v2"))
                        .type(List.of("gx:LabelCredential", "VerifiableCredential"))
                        .build())
                .validityDays(0)
                .issuerType(CredentialProfile.IssuerType.SIMPLE)
                .cnfRequired(false)
                .organizationExtraction(CredentialProfile.OrganizationExtraction.builder()
                        .strategy("session")
                        .build())
                .build();
    }

    private JsonNode mandatePayload() {
        com.fasterxml.jackson.databind.node.ObjectNode mandateNode = objectMapper.createObjectNode();
        mandateNode.set("mandatee", objectMapper.createObjectNode()
                .put("firstName", "John")
                .put("lastName", "Doe")
                .put("email", "john@example.com"));
        mandateNode.set("mandator", objectMapper.createObjectNode()
                .put("organizationIdentifier", "VATES-B12345678"));
        com.fasterxml.jackson.databind.node.ObjectNode root = objectMapper.createObjectNode();
        root.set("mandate", mandateNode);
        return root;
    }

    private CredentialStatus credentialStatus() {
        return CredentialStatus.builder()
                .id("https://example.com/status/1")
                .type("StatusList2021Entry")
                .statusPurpose("revocation")
                .statusListIndex("12345")
                .statusListCredential("https://example.com/credentials/status/1")
                .build();
    }
}
