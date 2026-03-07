package es.in2.issuer.backend.shared.infrastructure.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.ResourcePatternResolver;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CredentialProfileRegistryTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Test
    void shouldLoadProfileAndLookupByConfigurationId() throws IOException {
        ResourcePatternResolver resolver = mockResolver(validEmployeeProfile());

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        CredentialProfile profile = registry.getByConfigurationId("learcredential.employee.w3c.4");
        assertThat(profile).isNotNull();
        assertThat(profile.format()).isEqualTo("jwt_vc_json");
        assertThat(profile.scope()).isEqualTo("lear_credential_employee");
        assertThat(profile.validityDays()).isEqualTo(365);
        assertThat(profile.issuerType()).isEqualTo(CredentialProfile.IssuerType.DETAILED);
        assertThat(profile.cnfRequired()).isTrue();
    }

    @Test
    void shouldLookupByCredentialType() throws IOException {
        ResourcePatternResolver resolver = mockResolver(validEmployeeProfile());

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        CredentialProfile profile = registry.getByCredentialType("learcredential.employee.w3c.4");
        assertThat(profile).isNotNull();
        assertThat(profile.credentialConfigurationId()).isEqualTo("learcredential.employee.w3c.4");
    }

    @Test
    void shouldReturnNullForUnknownKeys() throws IOException {
        ResourcePatternResolver resolver = mockResolver(validEmployeeProfile());

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        assertThat(registry.getByConfigurationId("NonExistent")).isNull();
        assertThat(registry.getByCredentialType("NonExistent")).isNull();
    }

    @Test
    void shouldLoadMultipleProfiles() throws IOException {
        ResourcePatternResolver resolver = mockResolver(validEmployeeProfile(), validMachineProfile());

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        assertThat(registry.getAllProfiles()).hasSize(2);
        assertThat(registry.getByConfigurationId("learcredential.employee.w3c.4")).isNotNull();
        assertThat(registry.getByConfigurationId("learcredential.machine.w3c.3")).isNotNull();
    }

    @Test
    void shouldDeriveCredentialTypeFromDefinition() throws IOException {
        ResourcePatternResolver resolver = mockResolver(validEmployeeProfile());

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        CredentialProfile profile = registry.getByConfigurationId("learcredential.employee.w3c.4");
        assertThat(profile.credentialType()).isEqualTo("learcredential.employee.w3c.4");
        assertThat(profile.credentialDefinition().type())
                .containsExactly("VerifiableCredential", "learcredential.employee.w3c.4");
    }

    @Test
    void shouldParseCredentialMetadata() throws IOException {
        ResourcePatternResolver resolver = mockResolver(validEmployeeProfile());

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        CredentialProfile profile = registry.getByConfigurationId("learcredential.employee.w3c.4");
        assertThat(profile.credentialMetadata()).isNotNull();
        assertThat(profile.credentialMetadata().display()).hasSize(1);
        assertThat(profile.credentialMetadata().display().getFirst().name()).isEqualTo("LEAR Credential Employee");
        assertThat(profile.credentialMetadata().claims()).hasSize(5);
    }

    @Test
    void shouldParseSubjectExtraction() throws IOException {
        ResourcePatternResolver resolver = mockResolver(validEmployeeProfile());

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        CredentialProfile profile = registry.getByConfigurationId("learcredential.employee.w3c.4");
        assertThat(profile.subjectExtraction()).isNotNull();
        assertThat(profile.subjectExtraction().strategy()).isEqualTo("concat");
        assertThat(profile.subjectExtraction().fields())
                .containsExactly("mandate.mandatee.firstName", "mandate.mandatee.lastName");
        assertThat(profile.subjectExtraction().separator()).isEqualTo(" ");
    }

    @Test
    void shouldParseOrganizationExtraction() throws IOException {
        ResourcePatternResolver resolver = mockResolver(validEmployeeProfile());

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        CredentialProfile profile = registry.getByConfigurationId("learcredential.employee.w3c.4");
        assertThat(profile.organizationExtraction()).isNotNull();
        assertThat(profile.organizationExtraction().strategy()).isEqualTo("field");
        assertThat(profile.organizationExtraction().field()).isEqualTo("mandate.mandator.organizationIdentifier");
    }

    @Test
    void shouldFailOnMissingConfigurationId() throws IOException {
        String json = """
                {
                  "credential_format": "jwt_vc_json",
                  "credential_definition": {
                    "type": ["VerifiableCredential", "Test"]
                  }
                }
                """;
        ResourcePatternResolver resolver = mockResolver(namedResource("bad.json", json));

        assertThatThrownBy(() -> new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("no credential_configuration_id");
    }

    @Test
    void shouldFailOnDuplicateConfigurationId() throws IOException {
        ResourcePatternResolver resolver = mockResolver(
                validEmployeeProfile(),
                namedResource("duplicate.json", validEmployeeProfileJson()));

        assertThatThrownBy(() -> new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Duplicate credential_configuration_id");
    }

    @Test
    void shouldKeepFirstProfileForDuplicateCredentialType() throws IOException {
        String duplicateTypeJson = """
                {
                  "credential_configuration_id": "DifferentId",
                  "credential_format": "jwt_vc_json",
                  "credential_definition": {
                    "type": ["VerifiableCredential", "learcredential.employee.w3c.4"]
                  },
                  "validity_days": 365,
                  "issuer_type": "DETAILED",
                  "cnf_required": true
                }
                """;
        ResourcePatternResolver resolver = mockResolver(
                validEmployeeProfile(),
                namedResource("dup-type.json", duplicateTypeJson));

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        assertThat(registry.getAllProfiles()).hasSize(2);
        CredentialProfile typeResult = registry.getByCredentialType("learcredential.employee.w3c.4");
        assertThat(typeResult).isNotNull();
        assertThat(typeResult.credentialConfigurationId()).isEqualTo("learcredential.employee.w3c.4");
    }

    @Test
    void shouldHandleEmptyResourceList() throws IOException {
        ResourcePatternResolver resolver = mock(ResourcePatternResolver.class);
        when(resolver.getResources(anyString())).thenReturn(new Resource[0]);

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        assertThat(registry.getAllProfiles()).isEmpty();
    }

    @Test
    void shouldReturnUnmodifiableMap() throws IOException {
        ResourcePatternResolver resolver = mockResolver(validEmployeeProfile());

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        assertThatThrownBy(() -> registry.getAllProfiles().put("key", null))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    // --- Helper methods ---

    private ResourcePatternResolver mockResolver(Resource... resources) throws IOException {
        ResourcePatternResolver resolver = mock(ResourcePatternResolver.class);
        when(resolver.getResources(anyString())).thenReturn(resources);
        return resolver;
    }

    private Resource validEmployeeProfile() {
        return namedResource("lear-credential-employee.json", validEmployeeProfileJson());
    }

    private Resource validMachineProfile() {
        return namedResource("lear-credential-machine.json", """
                {
                  "credential_configuration_id": "learcredential.machine.w3c.3",
                  "credential_format": "jwt_vc_json",
                  "scope": "lear_credential_machine",
                  "credential_definition": {
                    "context": ["https://www.w3.org/ns/credentials/v2"],
                    "type": ["VerifiableCredential", "learcredential.machine.w3c.3"]
                  },
                  "credential_metadata": {
                    "display": [{"name": "LEAR Credential Machine", "locale": "en"}],
                    "claims": []
                  },
                  "validity_days": 365,
                  "issuer_type": "DETAILED",
                  "cnf_required": true,
                  "subject_extraction": {
                    "strategy": "field",
                    "fields": ["mandate.mandatee.domain"]
                  },
                  "organization_extraction": {
                    "strategy": "field",
                    "field": "mandate.mandator.organizationIdentifier"
                  }
                }
                """);
    }

    private String validEmployeeProfileJson() {
        return """
                {
                  "credential_configuration_id": "learcredential.employee.w3c.4",
                  "credential_format": "jwt_vc_json",
                  "scope": "lear_credential_employee",
                  "credential_definition": {
                    "context": [
                      "https://www.w3.org/ns/credentials/v2",
                      "https://credentials.eudistack.eu/.well-known/credentials/lear_credential_employee/w3c/v3"
                    ],
                    "type": ["VerifiableCredential", "learcredential.employee.w3c.4"]
                  },
                  "cryptographic_binding_methods_supported": ["did:key"],
                  "credential_signing_alg_values_supported": ["ES256"],
                  "proof_types_supported": {
                    "jwt": { "proof_signing_alg_values_supported": ["ES256"] }
                  },
                  "credential_metadata": {
                    "display": [{
                      "name": "LEAR Credential Employee",
                      "locale": "en",
                      "description": "Verifiable Credential for employees of an organization"
                    }],
                    "claims": [
                      { "path": ["credentialSubject", "mandate", "mandatee", "firstName"], "display": [{"name": "First Name", "locale": "en"}] },
                      { "path": ["credentialSubject", "mandate", "mandatee", "lastName"], "display": [{"name": "Last Name", "locale": "en"}] },
                      { "path": ["credentialSubject", "mandate", "mandatee", "email"], "display": [{"name": "Email", "locale": "en"}] },
                      { "path": ["credentialSubject", "mandate", "mandator", "organizationIdentifier"], "display": [{"name": "Organization", "locale": "en"}] },
                      { "path": ["credentialSubject", "mandate", "power"], "display": [{"name": "Powers", "locale": "en"}] }
                    ]
                  },
                  "validity_days": 365,
                  "issuer_type": "DETAILED",
                  "cnf_required": true,
                  "description": "Verifiable Credential for employees of an organization",
                  "subject_extraction": {
                    "strategy": "concat",
                    "fields": ["mandate.mandatee.firstName", "mandate.mandatee.lastName"],
                    "separator": " "
                  },
                  "organization_extraction": {
                    "strategy": "field",
                    "field": "mandate.mandator.organizationIdentifier"
                  }
                }
                """;
    }

    private Resource namedResource(String filename, String content) {
        return new ByteArrayResource(content.getBytes(StandardCharsets.UTF_8)) {
            @Override
            public String getFilename() {
                return filename;
            }
        };
    }
}
