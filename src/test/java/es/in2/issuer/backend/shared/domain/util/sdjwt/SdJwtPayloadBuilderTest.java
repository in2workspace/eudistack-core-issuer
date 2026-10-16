package es.in2.issuer.backend.shared.domain.util.sdjwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SdJwtPayloadBuilderTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final SdJwtPayloadBuilder builder = new SdJwtPayloadBuilder(objectMapper);

    private CredentialProfile profile(List<String> sdClaims) {
        return CredentialProfile.builder()
                .sdJwt(new CredentialProfile.SdJwtConfig("urn:test:vct", "sha-256", sdClaims))
                .build();
    }

    private static String credential(String extraClaims) {
        return """
                {
                  "vct": "urn:test:vct", "iss": "did:elsi:VATES-A00000000",
                  "iat": 1, "nbf": 1, "exp": 2,
                  "validFrom": "2026-01-01T00:00:00Z", "validUntil": "2027-01-01T00:00:00Z",
                  "givenName": "Jane", "familyName": "Doe"%s
                }
                """.formatted(extraClaims);
    }

    @Nested
    @DisplayName("build: top-level claims")
    class FlatClaims {

        @Test
        @DisplayName("build_claimNotListedInSdClaims_isDisclosedSelectively")
        void build_claimNotListedInSdClaims_isDisclosedSelectively() throws Exception {
            // Arrange
            String json = credential(", \"externalReference\": \"REF-1\"");

            // Act
            var result = builder.build(json, profile(List.of("givenName", "familyName")), null);

            // Assert
            assertEquals(3, result.disclosures().size());
            assertTrue(result.disclosures().stream().anyMatch(d -> d.claimName().equals("externalReference")));
            JsonNode payload = objectMapper.readTree(result.payloadJson());
            assertEquals(3, payload.get("_sd").size());
            assertFalse(payload.has("externalReference"));
        }

        @Test
        @DisplayName("build_onlyDeclaredClaims_disclosesExactlyTheDeclaredOnes")
        void build_onlyDeclaredClaims_disclosesExactlyTheDeclaredOnes() {
            // Arrange
            String json = credential("");

            // Act
            var result = builder.build(json, profile(List.of("givenName", "familyName")), null);

            // Assert
            assertEquals(2, result.disclosures().size());
        }

        @Test
        @DisplayName("build_fixedClaimsAndMetadata_areNeverDisclosed")
        void build_fixedClaimsAndMetadata_areNeverDisclosed() throws Exception {
            // Arrange
            String json = credential(", \"status\": {\"status_list\": {\"idx\": 1}}");

            // Act
            var result = builder.build(json, profile(List.of("givenName", "familyName")), null);

            // Assert
            assertEquals(2, result.disclosures().size());
            JsonNode payload = objectMapper.readTree(result.payloadJson());
            assertEquals("urn:test:vct", payload.get("vct").asText());
            assertTrue(payload.has("status"));
            assertFalse(payload.has("validFrom"));
        }
    }

    @Nested
    @DisplayName("build: claims grouped under a common parent")
    class NestedClaims {

        @Test
        @DisplayName("build_commonParentProfile_doesNotDiscloseExtraTopLevelClaims")
        void build_commonParentProfile_doesNotDiscloseExtraTopLevelClaims() {
            // Arrange
            String json = """
                    {
                      "vct": "urn:test:vct", "iss": "i", "iat": 1, "nbf": 1, "exp": 2,
                      "mandate": { "mandatee": { "email": "a@b.c" }, "mandator": { "x": 1 } },
                      "other": "value"
                    }
                    """;

            // Act
            var result = builder.build(json, profile(List.of("mandate.mandatee", "mandate.mandator")), null);

            // Assert
            assertEquals(2, result.disclosures().size());
        }
    }
}
