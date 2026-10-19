package es.in2.issuer.backend.shared.infrastructure.config;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import es.in2.issuer.backend.shared.domain.model.catalog.ClaimPath;
import es.in2.issuer.backend.shared.domain.model.enums.BindingType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.io.support.ResourcePatternResolver;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The catalog-entry lookups of {@link CredentialProfileRegistry} (EUD-266: attribute paths, schema
 * URIs, binding type) against the credential types under {@code src/test/resources/catalog-profiles}.
 * DoctorID v1 there is the platform-dev one plus a {@code schema_uri}; the other types come from
 * {@code dev-tools/credentials/profiles} and carry none.
 */
class CredentialProfileRegistryCatalogTest {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.builder()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .build();

    private static final String DOCTORID_URI = "https://registry.eudistack.net/schemas/doctorid/1.0.0/dc+sd-jwt";

    private final CredentialProfileRegistry registry = new CredentialProfileRegistry(
            OBJECT_MAPPER, new PathMatchingResourcePatternResolver(), "classpath:catalog-profiles");

    // ---- bindingTypeOf ---------------------------------------------------------

    @ParameterizedTest
    @CsvSource({
            "doctorid.sd.1,              KEY",
            "learcredential.employee.sd.1, KEY",
            "gx.labelcredential.w3c.2,   NONE",
            "synthetic.x509-binding.sd.1, UNSUPPORTED"
    })
    void bindingTypeOf_translatesTheDeclaredBindingMethods(String ccid, BindingType expected) {
        assertThat(registry.bindingTypeOf(ccid)).isEqualTo(expected);
    }

    @Test
    void bindingTypeOf_ofAnUnknownType_isRejected() {
        assertThatThrownBy(() -> registry.bindingTypeOf("unknown.type"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // ---- schema URIs -----------------------------------------------------------

    @Test
    void resolveSchemaUri_ofTheContractExample_resolvesToDoctorId() {
        assertThat(registry.resolveSchemaUri(DOCTORID_URI)).contains("doctorid.sd.1");
    }

    @Test
    void resolveSchemaUri_ofATypeWithoutSchemaUri_resolvesByTheSyntheticUri() {
        assertThat(registry.resolveSchemaUri("https://registry.eudistack.net/schemas/gx.labelcredential.w3c.2"))
                .contains("gx.labelcredential.w3c.2");
    }

    @Test
    void resolveSchemaUri_ofATypeWithARealSchemaUri_doesNotResolveBySyntheticUri() {
        assertThat(registry.resolveSchemaUri("https://registry.eudistack.net/schemas/doctorid.sd.1")).isEmpty();
    }

    @ParameterizedTest
    @CsvSource({
            "https://registry.eudistack.net/schemas/unknown/1.0.0/dc+sd-jwt",
            "https://registry.eudistack.net/schemas/doctorid/1.0.0/jwt_vc_json",
            "https://registry.eudistack.net/schemas/doctorid/2.0.0/dc+sd-jwt"
    })
    void resolveSchemaUri_ofAnUnknownOtherFormatOrOtherVersion_doesNotResolve(String uri) {
        assertThat(registry.resolveSchemaUri(uri)).isEmpty();
    }

    @Test
    void startup_failsWhenTwoTypesDeclareTheSameSchemaUri() throws IOException {
        ResourcePatternResolver resolver = mock(ResourcePatternResolver.class);
        when(resolver.getResources(anyString())).thenReturn(new Resource[] {
                typeFile("first.json", "first.sd.1"), typeFile("second.json", "second.sd.1")});

        assertThatThrownBy(() -> new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:catalog-profiles"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("first.sd.1")
                .hasMessageContaining("second.sd.1")
                .hasMessageContaining("same schema_uri");
    }

    @Test
    void schemaUriOf_returnsTheDeclaredUri_orTheSyntheticFallback() {
        assertThat(registry.schemaUriOf("doctorid.sd.1")).isEqualTo(DOCTORID_URI);
        assertThat(registry.schemaUriOf("learcredential.employee.sd.1"))
                .isEqualTo("https://registry.eudistack.net/schemas/learcredential.employee.sd.1");
    }

    @Test
    void getByConfigurationId_exposesTheDeclaredSchemaUri_andNullWhenAbsent() {
        assertThat(registry.getByConfigurationId("doctorid.sd.1").schemaUri()).isEqualTo(DOCTORID_URI);
        assertThat(registry.getByConfigurationId("gx.labelcredential.w3c.2").schemaUri()).isNull();
    }

    // ---- attributePaths --------------------------------------------------------

    @Test
    void attributePaths_ofDoctorIdV1_areItsSixAttributes_withArraysAsLeaves() {
        assertThat(registry.attributePaths("doctorid.sd.1")).containsExactlyInAnyOrder(
                ClaimPath.of("givenName"),
                ClaimPath.of("familyName"),
                ClaimPath.of("personal_administrative_number"),
                ClaimPath.of("medical_board"),
                ClaimPath.of("medical_speciality"),
                ClaimPath.of("legally_entitled"));
    }

    @Test
    void attributePaths_ofLearSdJwt_includeTheMandateLeaves_andTreatPowerAsALeaf() {
        List<ClaimPath> paths = registry.attributePaths("learcredential.employee.sd.1");

        assertThat(paths).contains(
                ClaimPath.of("mandate", "mandatee", "firstName"),
                ClaimPath.of("mandate", "mandatee", "lastName"),
                ClaimPath.of("mandate", "mandator", "organizationIdentifier"),
                ClaimPath.of("mandate", "power"));
        assertThat(paths).doesNotContain(ClaimPath.of("mandate"), ClaimPath.of("mandate", "mandatee"));
        assertThat(paths).doesNotContain(ClaimPath.of("mandate", "power", "domain"));
    }

    @Test
    void attributePaths_ofLearW3c_areOnlyThoseUnderCredentialSubject() {
        List<ClaimPath> paths = registry.attributePaths("learcredential.employee.w3c.4");

        assertThat(paths).contains(
                ClaimPath.of("credentialSubject", "id"),
                ClaimPath.of("credentialSubject", "mandate", "mandatee", "firstName"),
                ClaimPath.of("credentialSubject", "mandate", "power"));
        assertThat(paths).allMatch(path -> path.segments().getFirst().equals("credentialSubject"));
        assertThat(paths).doesNotContain(ClaimPath.of("validFrom"), ClaimPath.of("issuer", "id"));
    }

    @Test
    void attributePaths_ofGaiaXLabel_includeTheSubjectIdAndSkipTheEnvelope() {
        List<ClaimPath> paths = registry.attributePaths("gx.labelcredential.w3c.2");

        assertThat(paths).contains(
                ClaimPath.of("credentialSubject", "id"),
                ClaimPath.of("credentialSubject", "gx:labelLevel"),
                ClaimPath.of("credentialSubject", "gx:compliantCredentials"));
        assertThat(paths).allMatch(path -> path.segments().getFirst().equals("credentialSubject"));
        assertThat(paths).doesNotContain(ClaimPath.of("credentialStatus", "id"), ClaimPath.of("issuer"));
    }

    @Test
    void attributePaths_ofAnUnknownType_isRejected() {
        assertThatThrownBy(() -> registry.attributePaths("unknown.type"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static Resource typeFile(String filename, String ccid) {
        String json = """
                {
                  "credential_configuration_id": "%s",
                  "schema_uri": "https://registry.eudistack.net/schemas/clash/1.0.0/dc+sd-jwt",
                  "credential_format": "dc+sd-jwt",
                  "credential_definition": {"type": ["VerifiableCredential", "%s"]},
                  "issuer_type": "DETAILED"
                }
                """.formatted(ccid, ccid);
        return new ByteArrayResource(json.getBytes(StandardCharsets.UTF_8)) {
            @Override
            public String getFilename() {
                return filename;
            }
        };
    }
}
