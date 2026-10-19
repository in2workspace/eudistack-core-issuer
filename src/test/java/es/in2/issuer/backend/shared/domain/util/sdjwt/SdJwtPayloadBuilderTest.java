package es.in2.issuer.backend.shared.domain.util.sdjwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SdJwtPayloadBuilderTest {

    private static final String CREDENTIAL = """
            {
              "iss": "did:elsi:VATES-B12345678",
              "sub": "did:key:holder",
              "iat": 1700000000,
              "nbf": 1700000000,
              "exp": 1800000000,
              "vct": "urn:eudi:lear:1",
              "status": {"status_list": {"idx": 7, "uri": "https://issuer/status/1"}},
              "mandate": {
                "mandatee": {"firstName": "Ada"},
                "mandator": {"organization": "ACME"},
                "power": [{"function": "Onboarding"}]
              },
              "givenName": "Ada",
              "familyName": "Lovelace",
              "a": {"x": 1},
              "b": {"y": 2}
            }
            """;

    private static final Map<String, Object> CNF = Map.of("jwk", Map.of("kty", "EC"));

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final SdJwtPayloadBuilder builder = new SdJwtPayloadBuilder(objectMapper);

    @Test
    void build_withCommonParentClaims_placesDigestsInsideParent() throws JsonProcessingException {
        CredentialProfile profile = profile(List.of("mandate.mandatee", "mandate.mandator", "mandate.power"), false);

        SdJwtPayloadBuilder.SdJwtComponents result = builder.build(CREDENTIAL, profile, null);

        JsonNode payload = objectMapper.readTree(result.payloadJson());
        assertThat(payload.path("mandate").path("_sd")).hasSize(3);
        assertThat(payload.path("mandate").path("_sd_alg").asText()).isEqualTo("sha-256");
        assertThat(payload.has("_sd")).isFalse();
        assertThat(result.disclosures()).extracting(Disclosure::claimName)
                .containsExactly("mandatee", "mandator", "power");
    }

    static Stream<Arguments> claimsWithoutCommonParent() {
        return Stream.of(
                Arguments.of(Named.of("top-level claims", List.of("givenName", "familyName"))),
                Arguments.of(Named.of("different parents", List.of("a.x", "b.y"))),
                Arguments.of(Named.of("mixed nested and top-level", List.of("mandate.mandatee", "givenName"))));
    }

    @ParameterizedTest
    @MethodSource("claimsWithoutCommonParent")
    void build_withoutCommonParent_placesDigestsAtRoot(List<String> sdClaims) throws JsonProcessingException {
        CredentialProfile profile = profile(sdClaims, false);

        JsonNode payload = objectMapper.readTree(builder.build(CREDENTIAL, profile, null).payloadJson());

        assertThat(payload.path("_sd")).hasSize(2);
        assertThat(payload.path("_sd_alg").asText()).isEqualTo("sha-256");
    }

    @Test
    void build_copiesRegisteredClaimsAndStatus() throws JsonProcessingException {
        CredentialProfile profile = profile(List.of("givenName"), false);

        JsonNode payload = objectMapper.readTree(builder.build(CREDENTIAL, profile, null).payloadJson());

        assertThat(payload.path("iss").asText()).isEqualTo("did:elsi:VATES-B12345678");
        assertThat(payload.path("sub").asText()).isEqualTo("did:key:holder");
        assertThat(payload.path("exp").asLong()).isEqualTo(1800000000L);
        assertThat(payload.path("vct").asText()).isEqualTo("urn:eudi:lear:1");
        assertThat(payload.path("status").path("status_list").path("idx").asInt()).isEqualTo(7);
    }

    @Test
    void build_withoutSubStatusOrMatchingClaims_omitsOptionalFields() throws JsonProcessingException {
        String json = """
                {"iss":"i","sub":" ","vct":"v"}
                """;
        CredentialProfile profile = profile(List.of("missing.claim", "missing.other"), false);

        JsonNode payload = objectMapper.readTree(builder.build(json, profile, null).payloadJson());

        assertThat(payload.has("sub")).isFalse();
        assertThat(payload.has("status")).isFalse();
        assertThat(payload.has("_sd")).isFalse();
        assertThat(payload.has("missing")).isFalse();
    }

    static Stream<Arguments> claimsProducingNoDisclosures() {
        return Stream.of(
                Arguments.of(Named.of("empty sd_claims", List.of())),
                Arguments.of(Named.of("path through scalar", List.of("givenName.deep.leaf"))),
                Arguments.of(Named.of("missing claims", List.of("missing.claim", "missing.other"))));
    }

    @ParameterizedTest
    @MethodSource("claimsProducingNoDisclosures")
    void build_whenNoClaimMatches_producesNoDisclosures(List<String> sdClaims) {
        CredentialProfile profile = profile(sdClaims, false);

        SdJwtPayloadBuilder.SdJwtComponents result = builder.build(CREDENTIAL, profile, null);

        assertThat(result.disclosures()).isEmpty();
    }

    @Test
    void build_whenCnfRequiredAndProvided_addsCnf() throws JsonProcessingException {
        CredentialProfile profile = profile(List.of("givenName"), true);

        JsonNode payload = objectMapper.readTree(builder.build(CREDENTIAL, profile, CNF).payloadJson());

        assertThat(payload.path("cnf").path("jwk").path("kty").asText()).isEqualTo("EC");
    }

    static Stream<Arguments> cnfNotEmitted() {
        return Stream.of(
                Arguments.of(Named.of("required but null", true), null),
                Arguments.of(Named.of("required but empty", true), Map.of()),
                Arguments.of(Named.of("not required", false), CNF));
    }

    @ParameterizedTest
    @MethodSource("cnfNotEmitted")
    void build_whenCnfNotApplicable_omitsCnf(boolean cnfRequired, Map<String, Object> cnf)
            throws JsonProcessingException {
        CredentialProfile profile = profile(List.of("givenName"), cnfRequired);

        JsonNode payload = objectMapper.readTree(builder.build(CREDENTIAL, profile, cnf).payloadJson());

        assertThat(payload.has("cnf")).isFalse();
    }

    @Test
    void build_whenProfileHasNoSdJwtConfig_throws() {
        CredentialProfile profile = CredentialProfile.builder().build();

        RuntimeException ex = assertThrows(RuntimeException.class, () -> builder.build(CREDENTIAL, profile, null));

        assertThat(ex.getCause()).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void build_whenCredentialJsonInvalid_throws() {
        CredentialProfile profile = profile(List.of("givenName"), false);

        RuntimeException ex = assertThrows(RuntimeException.class, () -> builder.build("{not json", profile, null));

        assertThat(ex.getMessage()).isEqualTo("Failed to build SD-JWT payload");
    }

    @Test
    void build_disclosuresRoundTripThroughParse() {
        CredentialProfile profile = profile(List.of("givenName"), false);

        Disclosure disclosure = builder.build(CREDENTIAL, profile, null).disclosures().getFirst();
        Disclosure parsed = Disclosure.parse(disclosure.encoded());

        assertThat(parsed.claimName()).isEqualTo("givenName");
        assertThat(parsed.claimValue()).isEqualTo("Ada");
        assertThat(parsed.digest()).isEqualTo(disclosure.digest());
    }

    @Test
    void disclosureParse_whenNotThreeElements_throws() {
        String encoded = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString("[\"salt\",\"name\"]".getBytes());

        assertThrows(RuntimeException.class, () -> Disclosure.parse(encoded));
    }

    private static CredentialProfile profile(List<String> sdClaims, boolean cnfRequired) {
        return CredentialProfile.builder()
                .cnfRequired(cnfRequired)
                .sdJwt(CredentialProfile.SdJwtConfig.builder()
                        .vct("urn:eudi:lear:1")
                        .sdAlg("sha-256")
                        .sdClaims(sdClaims)
                        .build())
                .build();
    }
}
