package es.in2.issuer.backend.shared.infrastructure.config;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import es.in2.issuer.backend.shared.domain.model.catalog.ClaimPath;
import es.in2.issuer.backend.shared.domain.model.enums.BindingType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
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
            "doctorid.sd.1,               KEY",
            "learcredential.employee.sd.1, KEY",
            "gx.labelcredential.w3c.2,    NONE",
            "synthetic.biometric-binding.sd.1, BIOMETRIC"
    })
    void bindingTypeOf_ofTheFixtures_followsTheTypeFile(String ccid, BindingType expected) {
        assertThat(registry.bindingTypeOf(ccid)).isEqualTo(expected);
    }

    @ParameterizedTest
    @ValueSource(strings = {"jwk", "did:key", "x509"})
    void bindingTypeOf_withoutBindingType_aDeclaredBindingMethodIsAKey(String method) {
        CredentialProfileRegistry registry = registryOf("""
                "cryptographic_binding_methods_supported": ["%s"],
                "proof_types_supported": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}}
                """.formatted(method));

        assertThat(registry.bindingTypeOf("sample.sd.1")).isEqualTo(BindingType.KEY);
    }

    @Test
    void bindingTypeOf_withoutBindingType_cnfRequiredWithoutMethodsIsAKey() {
        CredentialProfileRegistry registry = registryOf("\"cnf_required\": true", "learcredential.machine.sd.1");

        assertThat(registry.bindingTypeOf("learcredential.machine.sd.1")).isEqualTo(BindingType.KEY);
    }

    @Test
    void bindingTypeOf_withoutBindingTypeMethodsOrCnf_isNone() {
        assertThat(registryOf("\"issuer_type\": \"DETAILED\"").bindingTypeOf("sample.sd.1"))
                .isEqualTo(BindingType.NONE);
    }

    @ParameterizedTest
    @CsvSource({"claim, CLAIM", "biometric, BIOMETRIC", "none, NONE", "key, KEY"})
    void bindingTypeOf_anExplicitBindingType_isUsed(String declared, BindingType expected) {
        CredentialProfileRegistry registry = registryOf("\"binding_type\": \"" + declared + "\"");

        assertThat(registry.bindingTypeOf("sample.sd.1")).isEqualTo(expected);
    }

    @Test
    void bindingTypeOf_anExplicitBindingType_winsOverTheDerivation() {
        CredentialProfileRegistry registry = registryOf("""
                "binding_type": "claim",
                "cryptographic_binding_methods_supported": ["jwk"],
                "proof_types_supported": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}}
                """);

        assertThat(registry.bindingTypeOf("sample.sd.1")).isEqualTo(BindingType.CLAIM);
    }

    @Test
    void startup_failsWhenTheBindingTypeIsNotOneOfTheKnownValues() {
        assertThatThrownBy(() -> registryOf("\"binding_type\": \"x509\""))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("sample.sd.1")
                .hasMessageContaining("binding_type");
    }

    // ---- validity --------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {"\"validity_days\": 0,", "\"validity_days\": -1,", ""})
    void startup_failsWhenTheValidityDaysAreMissingOrBelowOne(String validityMember) {
        String json = """
                {
                  "credential_configuration_id": "sample.sd.1",
                  "credential_format": "dc+sd-jwt",
                  "credential_definition": {"type": ["VerifiableCredential", "sample.sd.1"]},
                  %s
                  "issuer_type": "DETAILED"
                }
                """.formatted(validityMember);

        assertThatThrownBy(() -> new CredentialProfileRegistry(OBJECT_MAPPER, resolverOf("sample.sd.1.json", json),
                "classpath:catalog-profiles"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("sample.sd.1")
                .hasMessageContaining("validity_days");
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

    private static CredentialProfileRegistry registryOf(String extraMembers) {
        return registryOf(extraMembers, "sample.sd.1");
    }

    /** A registry with one type, {@code ccid}, whose file carries {@code extraMembers} (JSON members, without a trailing comma). */
    private static CredentialProfileRegistry registryOf(String extraMembers, String ccid) {
        String json = """
                {
                  "credential_configuration_id": "%s",
                  "credential_format": "dc+sd-jwt",
                  "credential_definition": {"type": ["VerifiableCredential", "%s"]},
                  "issuer_type": "DETAILED",
                  "validity_days": 365,
                  %s
                }
                """.formatted(ccid, ccid, extraMembers);
        return new CredentialProfileRegistry(OBJECT_MAPPER, resolverOf(ccid + ".json", json), "classpath:catalog-profiles");
    }

    /** A resolver that finds one type file, {@code filename}, with {@code json} as its content. */
    private static ResourcePatternResolver resolverOf(String filename, String json) {
        Resource file = new ByteArrayResource(json.getBytes(StandardCharsets.UTF_8)) {
            @Override
            public String getFilename() {
                return filename;
            }
        };
        ResourcePatternResolver resolver = mock(ResourcePatternResolver.class);
        try {
            when(resolver.getResources(anyString())).thenReturn(new Resource[] {file});
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return resolver;
    }

    private static Resource typeFile(String filename, String ccid) {
        String json = """
                {
                  "credential_configuration_id": "%s",
                  "schema_uri": "https://registry.eudistack.net/schemas/clash/1.0.0/dc+sd-jwt",
                  "credential_format": "dc+sd-jwt",
                  "credential_definition": {"type": ["VerifiableCredential", "%s"]},
                  "issuer_type": "DETAILED",
                  "validity_days": 365
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
