package es.in2.issuer.backend.oidc4vci;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;
import es.in2.issuer.backend.oidc4vci.domain.model.port.Oid4vciProfilePort;
import es.in2.issuer.backend.oidc4vci.domain.service.impl.AuthorizationServerMetadataServiceImpl;
import es.in2.issuer.backend.oidc4vci.infrastructure.config.Oid4vciProfileProperties;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import es.in2.issuer.backend.shared.domain.service.impl.CredentialIssuerMetadataServiceImpl;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import reactor.core.publisher.Mono;

import java.io.InputStream;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Guards both discovery documents against the JSON Schemas the OIDF conformance suite
 * validates them with, so a new field in a credential profile or in the metadata records
 * cannot silently reintroduce the "unexpected parameters" warnings.
 *
 * <p>The schemas under {@code src/test/resources/oidf-conformance/} are verbatim copies of
 * the suite's own {@code src/main/resources/json-schemas/} (both declare
 * {@code additionalProperties: false}); refresh them from
 * <a href="https://gitlab.com/openid/conformance-suite">gitlab.com/openid/conformance-suite</a>
 * when the suite is updated.
 *
 * <p>Every real credential profile is projected through the metadata mapper, so this covers
 * the catalogue we actually publish, not a fixture.
 */
@ExtendWith(MockitoExtension.class)
class OidfConformanceMetadataSchemaTest {

    private static final String ISSUER_URL = "https://issuer.example.com";

    /**
     * Absolute, so the test reads the same profiles whatever the working directory is —
     * Gradle runs from the project dir, an IDE run may not.
     */
    private static final String PROFILES_PATH =
            Paths.get("dev-tools", "credentials", "profiles").toAbsolutePath().toUri().toString();

    /** A metadata build that hangs is a failure, not a reason to sit until the build times out. */
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    /** Same shape as the application mapper: unknown profile members dropped, nulls omitted. */
    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.builder()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .serializationInclusion(JsonInclude.Include.NON_NULL)
            .build();

    @Mock
    private TenantCredentialProfileService tenantCredentialProfileService;

    @Mock
    private Oid4vciProfilePort profileProperties;

    @Test
    void credentialIssuerMetadata_conformsToTheConformanceSuiteSchema() {
        CredentialProfileRegistry registry = new CredentialProfileRegistry(
                OBJECT_MAPPER, new PathMatchingResourcePatternResolver(), PROFILES_PATH);
        Set<String> allConfigurationIds = registry.getAllProfiles().keySet();
        assertThat(allConfigurationIds).isNotEmpty();

        when(tenantCredentialProfileService.getEnabledConfigurationIds()).thenReturn(Mono.just(allConfigurationIds));

        var service = new CredentialIssuerMetadataServiceImpl(registry, tenantCredentialProfileService);
        JsonNode metadata = OBJECT_MAPPER.valueToTree(service.getCredentialIssuerMetadata(ISSUER_URL).block(TIMEOUT));

        assertThat(validate("oidf-conformance/credential_issuer_metadata-1_0.json", metadata)).isEmpty();
    }

    @Test
    void authorizationServerMetadata_conformsToTheConformanceSuiteSchema() {
        // Full HAIP configuration: every optional field the builder can emit is exercised.
        var authCodeProps = new Oid4vciProfileProperties.AuthorizationCodeProperties(
                true, true, List.of("S256"),
                true, List.of("ES256"),
                "attest_jwt_client_auth", true);

        when(profileProperties.isAuthorizationCodeEnabled()).thenReturn(true);
        when(profileProperties.isPreAuthorizedCodeEnabled()).thenReturn(true);
        when(profileProperties.grantsSupported()).thenReturn(
                List.of("authorization_code", "urn:ietf:params:oauth:grant-type:pre-authorized_code"));
        when(profileProperties.authorizationCode()).thenReturn(authCodeProps);

        var service = new AuthorizationServerMetadataServiceImpl(profileProperties);
        JsonNode metadata = OBJECT_MAPPER.valueToTree(
                service.buildAuthorizationServerMetadata("test-process", ISSUER_URL).block(TIMEOUT));

        assertThat(validate("oidf-conformance/oauth_authorization_server_metadata.json", metadata)).isEmpty();
    }

    @Test
    void theSchemaGuardRejectsAClaimsMemberOutsideTheSpec() throws Exception {
        // Guards the guard: without this, a schema that silently failed to load would make
        // the two tests above pass no matter what we publish. `value_map` is the member the
        // conformance suite flagged before it was removed.
        JsonNode metadata = OBJECT_MAPPER.readTree("""
                {
                  "credential_issuer": "https://issuer.example.com",
                  "credential_endpoint": "https://issuer.example.com/credential",
                  "credential_configurations_supported": {
                    "gx.labelcredential.w3c.2": {
                      "format": "jwt_vc_json",
                      "credential_definition": { "type": ["VerifiableCredential"] },
                      "credential_metadata": {
                        "claims": [
                          { "path": ["credentialSubject", "gx:labelLevel"], "value_map": { "BL": "Baseline" } }
                        ]
                      }
                    }
                  }
                }
                """);

        assertThat(validate("oidf-conformance/credential_issuer_metadata-1_0.json", metadata))
                .extracting(ValidationMessage::getMessage)
                .anySatisfy(message -> assertThat(message).contains("value_map"));
    }

    private Set<ValidationMessage> validate(String schemaResource, JsonNode document) {
        JsonSchemaFactory factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012);
        try (InputStream schemaStream = getClass().getClassLoader().getResourceAsStream(schemaResource)) {
            assertThat(schemaStream).as("schema %s", schemaResource).isNotNull();
            JsonSchema schema = factory.getSchema(schemaStream);
            return schema.validate(document);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to validate against " + schemaResource, e);
        }
    }
}
