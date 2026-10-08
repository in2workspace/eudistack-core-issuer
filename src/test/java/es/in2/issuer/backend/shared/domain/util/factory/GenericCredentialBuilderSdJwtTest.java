package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.SimpleIssuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.statuslist.domain.util.factory.IssuerFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Covers the dc+sd-jwt flat format, holder DID binding and subject/organization extraction edge cases
 * of {@link GenericCredentialBuilder}.
 */
@ExtendWith(MockitoExtension.class)
class GenericCredentialBuilderSdJwtTest {

    private static final String DC_SD_JWT = "dc+sd-jwt";
    private static final String HOLDER_DID = "did:key:zHolder";

    @Spy
    private ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private IssuerFactory issuerFactory;

    @Mock
    private AccessTokenService accessTokenService;

    @InjectMocks
    private GenericCredentialBuilder builder;

    // --- buildCredential (SD-JWT flat) ---

    @Test
    void buildCredential_sdJwtWithMandateStrategy_wrapsPayloadInMandate() {
        CredentialProfile profile = sdJwtProfile(null).build();
        JsonNode payload = mandatePayload();

        StepVerifier.create(builder.buildCredential(profile, payload))
                .assertNext(result -> {
                    JsonNode credential = read(result.credentialDataSet());
                    assertThat(credential.path("vct").asText()).isEqualTo("urn:eudi:lear:1");
                    assertThat(credential.path("iss").asText()).isEmpty();
                    assertThat(credential.path("exp").asLong()).isGreaterThan(credential.path("iat").asLong());
                    assertThat(credential.path("nbf").asLong()).isEqualTo(credential.path("iat").asLong());
                    assertThat(credential.path("mandate").path("mandatee").path("firstName").asText()).isEqualTo("Ada");
                    assertThat(credential.has("credentialSubject")).isFalse();
                })
                .verifyComplete();
    }

    @Test
    void buildCredential_sdJwtWithDirectStrategy_copiesPayloadAtTopLevel() {
        CredentialProfile profile = sdJwtProfile("direct").build();
        ObjectNode payload = objectMapper.createObjectNode().put("givenName", "Ada").put("familyName", "Lovelace");

        StepVerifier.create(builder.buildCredential(profile, payload))
                .assertNext(result -> {
                    JsonNode credential = read(result.credentialDataSet());
                    assertThat(credential.path("givenName").asText()).isEqualTo("Ada");
                    assertThat(credential.has("mandate")).isFalse();
                })
                .verifyComplete();
    }

    @Test
    void buildCredential_sdJwtFormatWithoutSdJwtConfig_fallsBackToW3c() {
        CredentialProfile profile = CredentialProfile.builder()
                .format(DC_SD_JWT)
                .validityDays(30)
                .credentialDefinition(new CredentialProfile.CredentialDefinition(
                        List.of("https://www.w3.org/ns/credentials/v2"), List.of("VerifiableCredential")))
                .build();

        StepVerifier.create(builder.buildCredential(profile, mandatePayload()))
                .assertNext(result -> assertThat(read(result.credentialDataSet()).has("credentialSubject")).isTrue())
                .verifyComplete();
    }

    // --- subject / organization extraction ---

    @Test
    void buildCredential_withoutExtractionConfig_returnsEmptySubjectAndOrg() {
        CredentialProfile profile = sdJwtProfile(null).build();

        StepVerifier.create(builder.buildCredential(profile, mandatePayload()))
                .assertNext(result -> {
                    assertThat(result.subject()).isEmpty();
                    assertThat(result.organizationIdentifier()).isEmpty();
                })
                .verifyComplete();
    }

    static Stream<Arguments> subjectExtractions() {
        return Stream.of(
                Arguments.of(new CredentialProfile.SubjectExtraction("concat", List.of(), null, null), ""),
                Arguments.of(new CredentialProfile.SubjectExtraction("concat", null, null, null), ""),
                Arguments.of(new CredentialProfile.SubjectExtraction("concat",
                        List.of("mandatee.firstName", "mandatee.unknown", "mandatee", "mandatee.lastName"), null, null),
                        "Ada Lovelace"),
                Arguments.of(new CredentialProfile.SubjectExtraction("first", List.of("mandatee.unknown"), null, "/"), ""));
    }

    @ParameterizedTest
    @MethodSource("subjectExtractions")
    void buildCredential_withSubjectExtraction_resolvesSubject(CredentialProfile.SubjectExtraction extraction,
                                                                String expectedSubject) {
        CredentialProfile profile = sdJwtProfile(null).subjectExtraction(extraction).build();

        StepVerifier.create(builder.buildCredential(profile, mandatePayload()))
                .assertNext(result -> assertThat(result.subject()).isEqualTo(expectedSubject))
                .verifyComplete();
    }

    static Stream<Arguments> organizationFields() {
        return Stream.of(
                Arguments.of("mandator.missing", ""),
                Arguments.of(null, ""),
                Arguments.of("mandator.organizationIdentifier", "VATES-B12345678"));
    }

    @ParameterizedTest
    @MethodSource("organizationFields")
    void buildCredential_withFieldOrgExtraction_resolvesOrganization(String field, String expectedOrg) {
        CredentialProfile profile = sdJwtProfile(null)
                .organizationExtraction(new CredentialProfile.OrganizationExtraction("field", field))
                .build();

        StepVerifier.create(builder.buildCredential(profile, mandatePayload()))
                .assertNext(result -> assertThat(result.organizationIdentifier()).isEqualTo(expectedOrg))
                .verifyComplete();
    }

    // --- bindIssuer (SD-JWT) ---

    @Test
    void bindIssuer_sdJwtWithDetailedIssuer_setsIssToOrganizationIdentifier() {
        CredentialProfile profile = sdJwtProfile(null).issuerType(CredentialProfile.IssuerType.DETAILED).build();
        when(issuerFactory.createDetailedIssuer()).thenReturn(Mono.just(DetailedIssuer.builder()
                .id("did:elsi:VATES-Q0000000J").organizationIdentifier("VATES-Q0000000J").build()));

        StepVerifier.create(builder.bindIssuer(profile, "{}", "id", "e@x"))
                .assertNext(result -> assertThat(read(result).path("iss").asText()).isEqualTo("VATES-Q0000000J"))
                .verifyComplete();
    }

    @Test
    void bindIssuer_sdJwtWithSimpleIssuer_setsIssToText() {
        CredentialProfile profile = sdJwtProfile(null).issuerType(CredentialProfile.IssuerType.SIMPLE).build();
        when(issuerFactory.createSimpleIssuer()).thenReturn(Mono.just(new SimpleIssuer("did:elsi:simple")));

        StepVerifier.create(builder.bindIssuer(profile, "{}", "id", "e@x"))
                .assertNext(result -> assertThat(read(result).path("iss").asText()).isEqualTo("did:elsi:simple"))
                .verifyComplete();
    }

    @Test
    void bindIssuer_withInvalidCredentialJson_emitsError() {
        CredentialProfile profile = sdJwtProfile(null).issuerType(CredentialProfile.IssuerType.SIMPLE).build();
        when(issuerFactory.createSimpleIssuer()).thenReturn(Mono.just(new SimpleIssuer("did:elsi:simple")));

        StepVerifier.create(builder.bindIssuer(profile, "{not json", "id", "e@x"))
                .expectError(IllegalStateException.class)
                .verify();
    }

    // --- bindHolderDid ---

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "{\"credentialSubject\":{\"mandate\":{\"mandatee\":{\"firstName\":\"Ada\"}}}} | /credentialSubject/mandate/mandatee/id",
            "{\"mandate\":{\"mandatee\":{\"firstName\":\"Ada\"}}} | /mandate/mandatee/id"
    })
    void bindHolderDid_withMandatee_setsId(String json, String idPointer) {
        JsonNode result = read(builder.bindHolderDid(json, HOLDER_DID));

        assertThat(result.at(idPointer).asText()).isEqualTo(HOLDER_DID);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "{\"credentialSubject\":{\"id\":\"x\"}}",
            "{\"credentialSubject\":{\"mandate\":{\"mandator\":{}}}}",
            "{\"credentialSubject\":{\"mandate\":{\"mandatee\":\"text\"}}}",
            "{\"credentialSubject\":\"text\"}",
            "{\"mandate\":\"text\"}",
            "{\"mandate\":{\"mandator\":{}}}",
            "{\"mandate\":{\"mandatee\":[]}}",
            "{\"vct\":\"x\"}",
            "{not json"
    })
    void bindHolderDid_withoutBindableMandatee_returnsInputUnchanged(String json) {
        assertThat(builder.bindHolderDid(json, HOLDER_DID)).isEqualTo(json);
    }

    // --- helpers ---

    private CredentialProfile.CredentialProfileBuilder sdJwtProfile(String subjectStrategy) {
        return CredentialProfile.builder()
                .format(DC_SD_JWT)
                .validityDays(365)
                .credentialSubjectStrategy(subjectStrategy)
                .sdJwt(CredentialProfile.SdJwtConfig.builder()
                        .vct("urn:eudi:lear:1")
                        .sdAlg("sha-256")
                        .sdClaims(List.of("mandate.mandatee"))
                        .build());
    }

    private JsonNode mandatePayload() {
        ObjectNode payload = objectMapper.createObjectNode();
        payload.putObject("mandatee").put("firstName", "Ada").put("lastName", "Lovelace");
        payload.putObject("mandator").put("organizationIdentifier", "VATES-B12345678");
        return payload;
    }

    private JsonNode read(String json) {
        try {
            return objectMapper.readTree(json);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
