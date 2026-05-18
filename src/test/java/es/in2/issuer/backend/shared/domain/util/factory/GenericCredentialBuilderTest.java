package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.statuslist.domain.util.factory.IssuerFactory;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialBuildResult;
import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.SimpleIssuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;

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

        StepVerifier.create(genericCredentialBuilder.buildCredential(profile, payload))
                .assertNext(result -> {
                    assertThat(result.subject()).isEqualTo("John Doe");
                    assertThat(result.organizationIdentifier()).isEqualTo("VATES-B12345678");
                    assertThat(result.validFrom()).isNotNull();
                    assertThat(result.validUntil()).isNotNull();

                    // Verify credential JSON structure
                    assertThat(result.credentialDataSet()).contains("\"@context\"");
                    assertThat(result.credentialDataSet()).contains("\"VerifiableCredential\"");
                    assertThat(result.credentialDataSet()).contains("\"learcredential.employee.w3c.4\"");
                    assertThat(result.credentialDataSet()).contains("\"credentialSubject\"");
                    assertThat(result.credentialDataSet()).contains("\"mandate\"");
                    assertThat(result.credentialDataSet()).contains("\"validFrom\"");
                    assertThat(result.credentialDataSet()).contains("\"validUntil\"");
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

        StepVerifier.create(genericCredentialBuilder.buildCredential(profile, payload))
                .assertNext(result -> {
                    assertThat(result.credentialDataSet()).contains(fixedFrom);
                    assertThat(result.credentialDataSet()).contains(fixedUntil);
                })
                .verifyComplete();
    }

    @Test
    void buildCredential_shouldUseSessionOrganizationExtraction() {
        CredentialProfile profile = labelProfile();
        JsonNode payload = objectMapper.createObjectNode();

        when(accessTokenService.getOrganizationIdFromCurrentSession()).thenReturn(Mono.just("SESSION-ORG-ID"));

        StepVerifier.create(genericCredentialBuilder.buildCredential(profile, payload))
                .assertNext(result ->
                        assertThat(result.organizationIdentifier()).isEqualTo("SESSION-ORG-ID"))
                .verifyComplete();
    }

    @Test
    void buildCredential_shouldExtractSubjectWithConcatStrategy() {
        CredentialProfile profile = employeeProfile();
        JsonNode payload = mandatePayload();

        StepVerifier.create(genericCredentialBuilder.buildCredential(profile, payload))
                .assertNext(result ->
                        assertThat(result.subject()).isEqualTo("John Doe"))
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

        StepVerifier.create(genericCredentialBuilder.buildCredential(profile, payload))
                .assertNext(result ->
                        assertThat(result.subject()).isEqualTo("api.example.com"))
                .verifyComplete();
    }

    @Test
    void buildCredential_shouldIncludeDescriptionWhenPresent() {
        CredentialProfile profile = employeeProfile();
        JsonNode payload = mandatePayload();

        StepVerifier.create(genericCredentialBuilder.buildCredential(profile, payload))
                .assertNext(result ->
                        assertThat(result.credentialDataSet()).contains("\"description\""))
                .verifyComplete();
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

        when(issuerFactory.createDetailedIssuer())
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

        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(simpleIssuer));

        StepVerifier.create(genericCredentialBuilder.bindIssuer(profile, credential, "proc-2", "admin@example.com"))
                .assertNext(result -> assertThat(result).contains("did:key:simple-issuer"))
                .verifyComplete();
    }

    // --- buildJwtPayload ---

    @Test
    void buildJwtPayload_shouldBuildVcdmV2PayloadWithCnfWhenRequired() {
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
                    // VCDM v2.0: VC properties at root level, no "vc" wrapper
                    assertThat(payload).doesNotContain("\"vc\"");
                    assertThat(payload).doesNotContain("\"jti\"");
                    assertThat(payload).doesNotContain("\"sub\"");
                    assertThat(payload).doesNotContain("\"nbf\"");

                    // VC properties directly at root
                    assertThat(payload).contains("\"issuer\"");
                    assertThat(payload).contains("\"credentialSubject\"");
                    assertThat(payload).contains("\"validFrom\"");
                    assertThat(payload).contains("\"validUntil\"");

                    // cnf at root level per RFC 7800
                    assertThat(payload).contains("\"cnf\"");
                    assertThat(payload).contains("\"kid\"");
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
                    // VCDM v2.0: issuer at root, no wrapper
                    assertThat(payload).contains("\"issuer\":\"did:key:simple-issuer\"");
                    assertThat(payload).doesNotContain("\"cnf\"");
                    assertThat(payload).doesNotContain("\"vc\"");
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
    void buildJwtPayload_shouldPreserveIssuerAsRootProperty() {
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
                .assertNext(payload -> {
                    // VCDM v2.0: issuer stays as VC property at root
                    assertThat(payload).contains("\"issuer\":\"did:key:string-issuer\"");
                    assertThat(payload).doesNotContain("\"vc\"");
                })
                .verifyComplete();
    }

    @Test
    void buildCredential_withW3cProfileAndMandateStrategy_shouldWrapPayloadInsideCredentialSubjectMandate() throws Exception {
        CredentialProfile profile = employeeProfile();
        JsonNode payload = mandatePayload();

        StepVerifier.create(genericCredentialBuilder.buildCredential(profile, payload))
                .assertNext(result -> {
                    try {
                        JsonNode credential = objectMapper.readTree(result.credentialDataSet());

                        assertThat(credential.get("@context")).isNotNull();
                        assertThat(credential.get("@context").get(0).asText())
                                .isEqualTo("https://www.w3.org/ns/credentials/v2");

                        assertThat(credential.get("id").asText()).startsWith("urn:uuid:");
                        assertThat(credential.get("type").isArray()).isTrue();
                        assertThat(credential.get("type").get(0).asText()).isEqualTo("VerifiableCredential");
                        assertThat(credential.get("type").get(1).asText()).isEqualTo("learcredential.employee.w3c.4");

                        assertThat(credential.get("description").asText())
                                .isEqualTo("Verifiable Credential for employees of an organization");

                        JsonNode credentialSubject = credential.get("credentialSubject");
                        assertThat(credentialSubject).isNotNull();
                        assertThat(credentialSubject.get("id").asText()).startsWith("urn:uuid:");
                        assertThat(credentialSubject.get("mandate")).isEqualTo(payload);

                        assertThat(credential.get("validFrom")).isNotNull();
                        assertThat(credential.get("validUntil")).isNotNull();
                        assertThat(credential.has("issuer")).isFalse();
                        assertThat(credential.has("credentialStatus")).isFalse();
                    } catch (Exception e) {
                        throw new AssertionError(e);
                    }
                })
                .verifyComplete();
    }

    @Test
    void buildCredential_withW3cProfileAndDirectStrategy_shouldUseCredentialSubjectFromPayload() throws Exception {
        CredentialProfile profile = directW3cProfile();

        com.fasterxml.jackson.databind.node.ObjectNode credentialSubject = objectMapper.createObjectNode()
                .put("id", "did:key:subject-123")
                .put("firstName", "Jane")
                .put("lastName", "Doe")
                .put("email", "jane@example.com");

        com.fasterxml.jackson.databind.node.ObjectNode payload = objectMapper.createObjectNode();
        payload.set("credentialSubject", credentialSubject);
        payload.set("mandator", objectMapper.createObjectNode()
                .put("organizationIdentifier", "VATES-DIRECT123"));

        StepVerifier.create(genericCredentialBuilder.buildCredential(profile, payload))
                .assertNext(result -> {
                    try {
                        JsonNode credential = objectMapper.readTree(result.credentialDataSet());
                        JsonNode resultCredentialSubject = credential.get("credentialSubject");

                        assertThat(resultCredentialSubject).isNotNull();
                        assertThat(resultCredentialSubject.get("id").asText()).isEqualTo("did:key:subject-123");
                        assertThat(resultCredentialSubject.get("firstName").asText()).isEqualTo("Jane");
                        assertThat(resultCredentialSubject.get("lastName").asText()).isEqualTo("Doe");
                        assertThat(resultCredentialSubject.get("email").asText()).isEqualTo("jane@example.com");

                        assertThat(resultCredentialSubject.has("mandate")).isFalse();
                        assertThat(result.organizationIdentifier()).isEqualTo("VATES-DIRECT123");
                        assertThat(result.subject()).isEqualTo("Jane Doe");
                    } catch (Exception e) {
                        throw new AssertionError(e);
                    }
                })
                .verifyComplete();
    }

    @Test
    void buildCredential_withW3cProfileAndDirectStrategyWithoutCredentialSubject_shouldUsePayloadAsCredentialSubject() {
        CredentialProfile profile = directW3cProfileWithoutCredentialSubjectWrapper();

        com.fasterxml.jackson.databind.node.ObjectNode payload = objectMapper.createObjectNode()
                .put("firstName", "Alice")
                .put("lastName", "Smith")
                .put("email", "alice@example.com");

        payload.set("mandator", objectMapper.createObjectNode()
                .put("organizationIdentifier", "VATES-ALICE123"));

        StepVerifier.create(genericCredentialBuilder.buildCredential(profile, payload))
                .assertNext(result -> {
                    try {
                        JsonNode credential = objectMapper.readTree(result.credentialDataSet());
                        JsonNode credentialSubject = credential.get("credentialSubject");

                        assertThat(credentialSubject).isNotNull();
                        assertThat(credentialSubject.get("id").asText()).startsWith("urn:uuid:");
                        assertThat(credentialSubject.get("firstName").asText()).isEqualTo("Alice");
                        assertThat(credentialSubject.get("lastName").asText()).isEqualTo("Smith");
                        assertThat(credentialSubject.get("email").asText()).isEqualTo("alice@example.com");
                        assertThat(credentialSubject.get("mandator").get("organizationIdentifier").asText())
                                .isEqualTo("VATES-ALICE123");

                        assertThat(result.organizationIdentifier()).isEqualTo("VATES-ALICE123");
                        assertThat(result.subject()).isEqualTo("Alice Smith");
                    } catch (Exception e) {
                        throw new AssertionError(e);
                    }
                })
                .verifyComplete();
    }

    @Test
    void buildCredential_withW3cProfileAndDirectStrategyWithoutSubjectId_shouldGenerateCredentialSubjectId() {
        CredentialProfile profile = directW3cProfile();

        com.fasterxml.jackson.databind.node.ObjectNode credentialSubject = objectMapper.createObjectNode()
                .put("firstName", "Jane")
                .put("lastName", "Doe")
                .put("email", "jane@example.com");

        com.fasterxml.jackson.databind.node.ObjectNode payload = objectMapper.createObjectNode();
        payload.set("credentialSubject", credentialSubject);
        payload.set("mandator", objectMapper.createObjectNode()
                .put("organizationIdentifier", "VATES-DIRECT123"));

        StepVerifier.create(genericCredentialBuilder.buildCredential(profile, payload))
                .assertNext(result -> {
                    try {
                        JsonNode credential = objectMapper.readTree(result.credentialDataSet());
                        JsonNode resultCredentialSubject = credential.get("credentialSubject");

                        assertThat(resultCredentialSubject.get("id").asText()).startsWith("urn:uuid:");
                        assertThat(resultCredentialSubject.get("firstName").asText()).isEqualTo("Jane");
                        assertThat(resultCredentialSubject.get("lastName").asText()).isEqualTo("Doe");
                    } catch (Exception e) {
                        throw new AssertionError(e);
                    }
                })
                .verifyComplete();
    }

    @Test
    void buildCredential_withW3cProfileWithoutDescription_shouldNotIncludeDescription() {
        CredentialProfile profile = w3cProfileWithoutDescription();
        JsonNode payload = mandatePayload();

        StepVerifier.create(genericCredentialBuilder.buildCredential(profile, payload))
                .assertNext(result -> {
                    try {
                        JsonNode credential = objectMapper.readTree(result.credentialDataSet());

                        assertThat(credential.has("description")).isFalse();
                        assertThat(credential.get("@context").get(0).asText())
                                .isEqualTo("https://www.w3.org/ns/credentials/v2");
                        assertThat(credential.get("type").get(0).asText()).isEqualTo("VerifiableCredential");
                        assertThat(credential.get("credentialSubject").get("mandate")).isEqualTo(payload);
                    } catch (Exception e) {
                        throw new AssertionError(e);
                    }
                })
                .verifyComplete();
    }

    @Test
    void buildCredential_withW3cProfileAndValidityDaysGreaterThanZero_shouldIgnorePayloadDates() {
        CredentialProfile profile = employeeProfile();

        com.fasterxml.jackson.databind.node.ObjectNode payload = (com.fasterxml.jackson.databind.node.ObjectNode) mandatePayload();
        payload.put("validFrom", "2020-01-01T00:00:00Z");
        payload.put("validUntil", "2021-01-01T00:00:00Z");

        StepVerifier.create(genericCredentialBuilder.buildCredential(profile, payload))
                .assertNext(result -> {
                    try {
                        JsonNode credential = objectMapper.readTree(result.credentialDataSet());

                        assertThat(credential.get("validFrom").asText()).isNotEqualTo("2020-01-01T00:00:00Z");
                        assertThat(credential.get("validUntil").asText()).isNotEqualTo("2021-01-01T00:00:00Z");

                        assertThat(result.validFrom().toInstant()).isAfter(Instant.parse("2020-01-01T00:00:00Z"));
                        assertThat(result.validUntil().toInstant()).isAfter(result.validFrom().toInstant());
                    } catch (Exception e) {
                        throw new AssertionError(e);
                    }
                })
                .verifyComplete();
    }

    // --- Helper methods ---

    private CredentialProfile directW3cProfileWithoutCredentialSubjectWrapper() {
        return CredentialProfile.builder()
                .credentialConfigurationId("learcredential.employee.w3c.4")
                .format("jwt_vc_json")
                .scope("lear_credential_employee")
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .context(List.of("https://www.w3.org/ns/credentials/v2"))
                        .type(List.of("VerifiableCredential", "learcredential.employee.w3c.4"))
                        .build())
                .cryptographicBindingMethodsSupported(Set.of("did:key"))
                .credentialSigningAlgValuesSupported(Set.of("ES256"))
                .validityDays(365)
                .issuerType(CredentialProfile.IssuerType.DETAILED)
                .cnfRequired(true)
                .credentialSubjectStrategy("direct")
                .description("Direct W3C employee credential")
                .subjectExtraction(CredentialProfile.SubjectExtraction.builder()
                        .strategy("concat")
                        .fields(List.of("firstName", "lastName"))
                        .separator(" ")
                        .build())
                .organizationExtraction(CredentialProfile.OrganizationExtraction.builder()
                        .strategy("field")
                        .field("mandator.organizationIdentifier")
                        .build())
                .build();
    }

    private CredentialProfile directW3cProfile() {
        return CredentialProfile.builder()
                .credentialConfigurationId("learcredential.employee.w3c.4")
                .format("jwt_vc_json")
                .scope("lear_credential_employee")
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .context(List.of("https://www.w3.org/ns/credentials/v2"))
                        .type(List.of("VerifiableCredential", "learcredential.employee.w3c.4"))
                        .build())
                .cryptographicBindingMethodsSupported(Set.of("did:key"))
                .credentialSigningAlgValuesSupported(Set.of("ES256"))
                .validityDays(365)
                .issuerType(CredentialProfile.IssuerType.DETAILED)
                .cnfRequired(true)
                .credentialSubjectStrategy("direct")
                .description("Direct W3C employee credential")
                .subjectExtraction(CredentialProfile.SubjectExtraction.builder()
                        .strategy("concat")
                        .fields(List.of("credentialSubject.firstName", "credentialSubject.lastName"))
                        .separator(" ")
                        .build())
                .organizationExtraction(CredentialProfile.OrganizationExtraction.builder()
                        .strategy("field")
                        .field("mandator.organizationIdentifier")
                        .build())
                .build();
    }

    private CredentialProfile w3cProfileWithoutDescription() {
        return CredentialProfile.builder()
                .credentialConfigurationId("learcredential.employee.w3c.4")
                .format("jwt_vc_json")
                .scope("lear_credential_employee")
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .context(List.of("https://www.w3.org/ns/credentials/v2"))
                        .type(List.of("VerifiableCredential", "learcredential.employee.w3c.4"))
                        .build())
                .cryptographicBindingMethodsSupported(Set.of("did:key"))
                .credentialSigningAlgValuesSupported(Set.of("ES256"))
                .validityDays(365)
                .issuerType(CredentialProfile.IssuerType.DETAILED)
                .cnfRequired(true)
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



    private CredentialProfile employeeProfile() {
        return CredentialProfile.builder()
                .credentialConfigurationId("learcredential.employee.w3c.4")
                .format("jwt_vc_json")
                .scope("lear_credential_employee")
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .context(List.of("https://www.w3.org/ns/credentials/v2"))
                        .type(List.of("VerifiableCredential", "learcredential.employee.w3c.4"))
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
                .credentialConfigurationId("learcredential.machine.w3c.3")
                .format("jwt_vc_json")
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .context(List.of("https://www.w3.org/ns/credentials/v2"))
                        .type(List.of("VerifiableCredential", "learcredential.machine.w3c.3"))
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
                .credentialConfigurationId("gx.labelcredential.w3c.1")
                .format("jwt_vc_json")
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .context(List.of("https://www.w3.org/ns/credentials/v2"))
                        .type(List.of("gx.labelcredential.w3c.1", "VerifiableCredential"))
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
}
