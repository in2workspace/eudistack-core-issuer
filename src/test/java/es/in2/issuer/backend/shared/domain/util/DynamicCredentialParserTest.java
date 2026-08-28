package es.in2.issuer.backend.shared.domain.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialFormatException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DynamicCredentialParserTest {

    private static final String LEGACY_TYPE = "LEARCredentialEmployee";
    private static final String MODERN_CONFIG_ID = "learcredential.employee.w3c.4";

    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;

    private DynamicCredentialParser parser;

    @BeforeEach
    void setUp() {
        parser = new DynamicCredentialParser(new ObjectMapper(), credentialProfileRegistry);
    }

    /**
     * Regression: legacy DOME credentials carry a human-readable type as the first entry of
     * the {@code type} array, which is not a credential_configuration_id.
     */
    @Test
    void parse_resolvesProfileForLegacyCredentialTypeName() {
        CredentialProfile profile = profileWithPolicyExtraction();
        when(credentialProfileRegistry.resolveProfile(LEGACY_TYPE)).thenReturn(profile);

        var parsed = parser.parse(legacyEmployeeVcJson());

        assertThat(parsed.credentialType()).isEqualTo(LEGACY_TYPE);
    }

    @Test
    void parse_resolvesProfileForModernConfigurationId() {
        CredentialProfile profile = profileWithPolicyExtraction();
        when(credentialProfileRegistry.resolveProfile(MODERN_CONFIG_ID)).thenReturn(profile);

        var parsed = parser.parse("""
                {
                  "type": ["VerifiableCredential", "learcredential.employee.w3c.4"],
                  "credentialSubject": {}
                }
                """);

        assertThat(parsed.credentialType()).isEqualTo(MODERN_CONFIG_ID);
    }

    @Test
    void parse_throwsWhenNoProfileMatchesTheCredentialType() {
        when(credentialProfileRegistry.resolveProfile(LEGACY_TYPE)).thenReturn(null);

        assertThatThrownBy(() -> parser.parse(legacyEmployeeVcJson()))
                .isInstanceOf(InvalidCredentialFormatException.class)
                .hasMessage("No profile found for credential type: " + LEGACY_TYPE);
    }

    @Test
    void parse_throwsWhenTypeArrayIsMissing() {
        assertThatThrownBy(() -> parser.parse("{\"credentialSubject\": {}}"))
                .isInstanceOf(InvalidCredentialFormatException.class)
                .hasMessageContaining("Credential has no 'type' array");
    }

    @Test
    void parse_throwsWhenTypeArrayIsEmpty() {
        assertThatThrownBy(() -> parser.parse("{\"type\": []}"))
                .isInstanceOf(InvalidCredentialFormatException.class)
                .hasMessageContaining("Credential 'type' array is empty");
    }

    @Test
    void extractPowers_readsPowersFromTheProfilePolicyExtractionPath() {
        CredentialProfile profile = profileWithPolicyExtraction();
        when(credentialProfileRegistry.resolveProfile(LEGACY_TYPE)).thenReturn(profile);
        var parsed = parser.parse(legacyEmployeeVcJson());

        List<Power> powers = parser.extractPowers(parsed.node(), parsed.profile());

        assertThat(powers).extracting(Power::function)
                .containsExactly("Onboarding", "Certification");
    }

    @Test
    void extractPowers_returnsEmptyListWhenProfileHasNoPolicyExtraction() {
        CredentialProfile profile = CredentialProfile.builder()
                .credentialConfigurationId("learcredential.employee.w3c.3")
                .build();
        when(credentialProfileRegistry.resolveProfile(LEGACY_TYPE)).thenReturn(profile);
        var parsed = parser.parse(legacyEmployeeVcJson());

        assertThat(parser.extractPowers(parsed.node(), parsed.profile())).isEmpty();
    }

    // --- Helper methods ---

    private CredentialProfile profileWithPolicyExtraction() {
        return CredentialProfile.builder()
                .credentialConfigurationId("learcredential.employee.w3c.3")
                .policyExtraction(CredentialProfile.PolicyExtraction.builder()
                        .powersPath("credentialSubject.mandate.power")
                        .mandatorPath("credentialSubject.mandate.mandator")
                        .orgIdField("organizationIdentifier")
                        .build())
                .build();
    }

    /**
     * Shape of a legacy DOME credential: the human-readable type comes first in the array,
     * ahead of {@code VerifiableCredential}.
     */
    private String legacyEmployeeVcJson() {
        return """
                {
                  "@context": [
                    "https://www.w3.org/ns/credentials/v2",
                    "https://credentials.eudistack.eu/.well-known/credentials/lear_credential_employee/w3c/v3"
                  ],
                  "type": ["LEARCredentialEmployee", "VerifiableCredential"],
                  "credentialSubject": {
                    "mandate": {
                      "mandator": { "organizationIdentifier": "VATES-X0000000X" },
                      "power": [
                        { "action": ["Execute"], "domain": "DOME", "function": "Onboarding", "type": "domain" },
                        { "action": ["Upload", "Attest"], "domain": "DOME", "function": "Certification", "type": "domain" }
                      ]
                    }
                  }
                }
                """;
    }
}
