package es.in2.issuer.backend.shared.domain.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialFormatException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

/**
 * Covers the negative and alternative branches of {@link DynamicCredentialParser}.
 */
@ExtendWith(MockitoExtension.class)
class DynamicCredentialParserBranchesTest {

    private static final String VC = """
            {
              "type": ["VerifiableCredential", "learcredential.employee.w3c.4"],
              "credentialSubject": {
                "mandate": {
                  "mandator": {"organizationIdentifier": "VATES-B12345678", "nullOrg": null},
                  "nullMandator": null,
                  "power": null
                }
              }
            }
            """;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;

    private DynamicCredentialParser parser;
    private JsonNode vcNode;

    @BeforeEach
    void setUp() throws JsonProcessingException {
        parser = new DynamicCredentialParser(objectMapper, credentialProfileRegistry);
        vcNode = objectMapper.readTree(VC);
    }

    // --- parse ---

    @Test
    void parse_withOnlyVerifiableCredentialType_usesFirstType() {
        // Arrange
        CredentialProfile profile = CredentialProfile.builder().build();
        when(credentialProfileRegistry.resolveProfile("VerifiableCredential")).thenReturn(profile);

        // Act
        var parsed = parser.parse("{\"type\":[\"VerifiableCredential\"]}");

        // Assert
        assertThat(parsed.credentialType()).isEqualTo("VerifiableCredential");
    }

    @ParameterizedTest
    @ValueSource(strings = {"{}", "{\"type\":\"VerifiableCredential\"}"})
    void parse_withoutTypeArray_throws(String json) {
        assertThatThrownBy(() -> parser.parse(json))
                .isInstanceOf(InvalidCredentialFormatException.class)
                .hasMessageContaining("no 'type' array");
    }

    @Test
    void parse_withEmptyTypeArray_throws() {
        assertThatThrownBy(() -> parser.parse("{\"type\":[]}"))
                .isInstanceOf(InvalidCredentialFormatException.class)
                .hasMessageContaining("'type' array is empty");
    }

    @Test
    void parse_withUnknownProfile_throws() {
        assertThatThrownBy(() -> parser.parse("{\"type\":[\"unknown.type\"]}"))
                .isInstanceOf(InvalidCredentialFormatException.class)
                .hasMessage("No profile found for credential type: unknown.type");
    }

    @Test
    void parse_withMalformedJson_wrapsError() {
        assertThatThrownBy(() -> parser.parse("{not json"))
                .isInstanceOf(InvalidCredentialFormatException.class)
                .hasMessageStartingWith("Failed to parse credential:");
    }

    // --- extractPowers ---

    static Stream<Arguments> profilesWithoutPowers() {
        return Stream.of(
                Arguments.of(Named.of("no policy extraction", CredentialProfile.builder().build())),
                Arguments.of(Named.of("no powers path", profile(null, null, null))),
                Arguments.of(Named.of("missing powers path", profile("credentialSubject.mandate.nope", null, null))),
                Arguments.of(Named.of("null powers node", profile("credentialSubject.mandate.power", null, null))));
    }

    @ParameterizedTest
    @MethodSource("profilesWithoutPowers")
    void extractPowers_whenPowersNotResolvable_returnsEmptyList(CredentialProfile profile) {
        assertThat(parser.extractPowers(vcNode, profile)).isEmpty();
    }

    // --- extractOrganizationId ---

    static Stream<Arguments> organizationIdCases() {
        return Stream.of(
                Arguments.of(Named.of("no policy extraction", CredentialProfile.builder().build()), null),
                Arguments.of(Named.of("no mandator path", profile(null, null, "organizationIdentifier")), null),
                Arguments.of(Named.of("missing mandator",
                        profile(null, "credentialSubject.nope.mandator", "organizationIdentifier")), null),
                Arguments.of(Named.of("null mandator",
                        profile(null, "credentialSubject.mandate.nullMandator", "organizationIdentifier")), null),
                Arguments.of(Named.of("missing org field",
                        profile(null, "credentialSubject.mandate.mandator", "unknown")), null),
                Arguments.of(Named.of("null org field",
                        profile(null, "credentialSubject.mandate.mandator", "nullOrg")), null),
                Arguments.of(Named.of("org id present",
                        profile(null, "credentialSubject.mandate.mandator", "organizationIdentifier")),
                        "VATES-B12345678"));
    }

    @ParameterizedTest
    @MethodSource("organizationIdCases")
    void extractOrganizationId_resolvesOrReturnsNull(CredentialProfile profile, String expected) {
        assertThat(parser.extractOrganizationId(vcNode, profile)).isEqualTo(expected);
    }

    // --- extractMandator ---

    @Test
    void extractMandator_withMandatorPath_returnsNode() {
        CredentialProfile profile = profile(null, "credentialSubject.mandate.mandator", "organizationIdentifier");

        JsonNode mandator = parser.extractMandator(vcNode, profile);

        assertThat(mandator.path("organizationIdentifier").asText()).isEqualTo("VATES-B12345678");
    }

    static Stream<Arguments> profilesWithoutMandator() {
        return Stream.of(
                Arguments.of(Named.of("no policy extraction", CredentialProfile.builder().build())),
                Arguments.of(Named.of("no mandator path", profile(null, null, null))));
    }

    @ParameterizedTest
    @MethodSource("profilesWithoutMandator")
    void extractMandator_withoutMandatorPath_returnsMissingNode(CredentialProfile profile) {
        assertThat(parser.extractMandator(vcNode, profile).isMissingNode()).isTrue();
    }

    @Test
    void extractMandator_withNullRoot_returnsMissingNode() {
        CredentialProfile profile = profile(null, "credentialSubject.mandate.mandator", null);

        assertThat(parser.extractMandator(null, profile).isMissingNode()).isTrue();
    }

    private static CredentialProfile profile(String powersPath, String mandatorPath, String orgIdField) {
        return CredentialProfile.builder()
                .policyExtraction(new CredentialProfile.PolicyExtraction(powersPath, mandatorPath, orgIdField))
                .build();
    }
}
