package es.in2.issuer.backend.issuance.infrastructure.controller;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.SimpleIssuer;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.service.SignDocService;
import es.in2.issuer.backend.statuslist.domain.util.factory.IssuerFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;
import reactor.core.publisher.Mono;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * End-to-end coverage of synchronous ({@code delivery=direct}) issuance through the real
 * controller, security filter chain, PDP rule chain, status list allocation and Postgres
 * (Testcontainers).
 *
 * <p><b>Why this exists.</b> Direct issuance forwards the optional {@code X-Id-Token} header
 * as the "caller token" down to status list allocation and signing, and both used to reject a
 * null — so every direct issuance for a profile that does not require that header returned a
 * 500 ({@code NullPointerException: token cannot be null}). No unit test could catch it: the
 * workflow test mocks {@code StatusListWorkflow}, which is precisely the collaborator that
 * threw. Only a wiring test does.
 *
 * <p><b>Mocked collaborators, and why only these.</b> {@link VerifierService} (external crypto
 * verification against the Verifier's JWKS), {@link IssuerFactory} and {@link SignDocService}
 * (both reach the remote QTSP over HTTP). Everything between the HTTP request and those three
 * is real — including {@code CscSignDocSigningProvider} and {@code SigningRequestValidator},
 * which is the second place the null caller token used to be rejected. {@code sign-doc} is
 * seeded as the tenant's signing operation for exactly that reason: routing to
 * {@code CscSignHashSigningProvider} instead would bypass that validator.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class DirectIssuanceIT {

    private static final String TENANT = "tenanta";
    private static final String MACHINE_CONFIG_ID = "learcredential.machine.w3c.3";
    private static final String LABEL_CONFIG_ID = "gx.labelcredential.w3c.2";
    private static final String ISSUANCES_URI = "/issuer/api/v1/issuances";

    /** Operator's own org. Seeded as the tenant admin org so on-behalf delegation is allowed. */
    private static final String OPERATOR_ORG = "VATES-A00000001";
    /** Subject org in the payload. Must differ from {@link #OPERATOR_ORG}: the LEAR rule only
     *  allows delegating Onboarding/Execute on behalf of another organization. */
    private static final String SUBJECT_ORG = "VATES-B00000002";

    private static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>(DockerImageName.parse("postgres:17-alpine"))
                    .withDatabaseName("issuer")
                    .withUsername("issuer")
                    .withPassword("issuer");

    static {
        POSTGRES.start();
        seedTenantRegistry();
    }

    @DynamicPropertySource
    static void registerProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + POSTGRES.getHost() + ":" + POSTGRES.getFirstMappedPort()
                        + "/" + POSTGRES.getDatabaseName());
        registry.add("spring.r2dbc.username", POSTGRES::getUsername);
        registry.add("spring.r2dbc.password", POSTGRES::getPassword);
        registry.add("spring.flyway.url", POSTGRES::getJdbcUrl);
        // Real profile definitions copied from dev-tools/schemas/ — see
        // src/test/resources/test-credential-profiles/.
        registry.add("credential.profiles.path", () -> "classpath:test-credential-profiles");
    }

    private static void seedTenantRegistry() {
        try (Connection conn = jdbcConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute("""
                    CREATE TABLE IF NOT EXISTS public.tenant_registry (
                        schema_name  VARCHAR PRIMARY KEY,
                        display_name VARCHAR,
                        tenant_type  VARCHAR,
                        status       VARCHAR,
                        created_at   TIMESTAMPTZ DEFAULT now(),
                        updated_at   TIMESTAMPTZ DEFAULT now()
                    )
                    """);
            stmt.execute("""
                    INSERT INTO public.tenant_registry (schema_name, display_name, tenant_type, status)
                    VALUES ('%s', 'Tenant A', 'multi_org', 'active')
                    ON CONFLICT (schema_name) DO NOTHING
                    """.formatted(TENANT));
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to seed tenant_registry for IT", e);
        }
    }

    private static Connection jdbcConnection() throws SQLException {
        return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }

    @LocalServerPort
    private int port;

    @MockitoBean
    private VerifierService verifierService;

    @MockitoBean
    private IssuerFactory issuerFactory;

    @MockitoBean
    private SignDocService signDocService;

    private WebTestClient webTestClient;
    private String issuerOrigin;
    private ECKey signingKey;

    @BeforeEach
    void setUp() throws Exception {
        issuerOrigin = "http://localhost:" + port;
        webTestClient = WebTestClient.bindToServer().baseUrl(issuerOrigin).build();
        signingKey = new ECKeyGenerator(Curve.P_256).keyID("test-signer").generate();

        when(verifierService.verifyToken(anyString())).thenReturn(Mono.empty());

        DetailedIssuer detailed = DetailedIssuer.builder()
                .id("did:elsi:VATES-Z99999999")
                .organizationIdentifier("VATES-Z99999999")
                .organization("Test QTSP")
                .country("ES")
                .commonName("Test Issuer")
                .serialNumber("SN-1")
                .build();
        when(issuerFactory.createDetailedIssuer()).thenReturn(Mono.just(detailed));
        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(SimpleIssuer.builder().id(detailed.id()).build()));

        when(signDocService.signIssuedCredential(any(), anyString()))
                .thenReturn(Mono.just(new SigningResult(SigningType.JADES, "signed.credential.jwt")));
        when(signDocService.signSystemCredential(any()))
                .thenReturn(Mono.just(new SigningResult(SigningType.JADES, "signed.statuslist.jwt")));

        seedTenantConfig();
        seedEnabledProfiles();
        seedSigningConfig();
    }

    /**
     * admin_organization_id is deliberately NOT seeded by V1__Tenant_schema.sql. Pointing it at
     * the operator's own org makes PolicyContextFactory resolve tenantAdmin=true, which the LEAR
     * rule requires before it will allow delegating Onboarding/Execute on behalf of another org.
     */
    private void seedTenantConfig() throws SQLException {
        execute("""
                INSERT INTO %s%s.tenant_config (config_key, config_value)
                VALUES ('admin_organization_id', '%s')
                ON CONFLICT (config_key) DO UPDATE SET config_value = EXCLUDED.config_value
                """.formatted(TENANT, SCHEMA_SUFFIX, OPERATOR_ORG));
    }

    private void seedEnabledProfiles() throws SQLException {
        execute("""
                INSERT INTO %1$s%2$s.tenant_credential_profile (credential_configuration_id, enabled)
                VALUES ('%3$s', true), ('%4$s', true)
                ON CONFLICT (credential_configuration_id) DO UPDATE SET enabled = true
                """.formatted(TENANT, SCHEMA_SUFFIX, MACHINE_CONFIG_ID, LABEL_CONFIG_ID));
    }

    /**
     * signPath drives {@code SigningProviderResolver}: 'sign-doc' keeps
     * {@code CscSignDocSigningProvider} and {@code SigningRequestValidator} in the call path,
     * which is where the caller token used to be demanded for issued credentials.
     */
    private void seedSigningConfig() throws SQLException {
        execute("""
                INSERT INTO %s%s.tenant_signing_config (provider, csc_api_version, provider_specific_config)
                SELECT 'csc-sign-doc', 'v2',
                       '{"url": "https://qtsp.invalid", "signPath": "sign-doc", "clientId": "c",
                         "clientSecret": "s", "credentialId": "cred", "credentialPwd": "pwd"}'::jsonb
                WHERE NOT EXISTS (SELECT 1 FROM %s%s.tenant_signing_config)
                """.formatted(TENANT, SCHEMA_SUFFIX, TENANT, SCHEMA_SUFFIX));
    }

    private void execute(String sql) throws SQLException {
        try (Connection conn = jdbcConnection(); Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
        }
    }

    // ---------------------------------------------------------------- helpers

    private String operatorToken() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuerOrigin + "/verifier")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 3_600_000L))
                .claim("credential_type", "learcredential.employee.w3c.4")
                .claim("mandator", Map.of("organizationIdentifier", OPERATOR_ORG))
                .claim("power", List.of(Map.of(
                        "type", "domain", "domain", TENANT,
                        "function", "Onboarding", "action", "Execute")))
                .claim("tenant", TENANT)
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(signingKey.getKeyID()).build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(signingKey));
        return jwt.serialize();
    }

    private Map<String, Object> machinePayload() {
        return Map.of(
                "mandator", Map.of(
                        "id", "did:elsi:" + SUBJECT_ORG,
                        "email", "operator@example.com",
                        "country", "Spain",
                        "commonName", "Subject Org",
                        "organizationIdentifier", SUBJECT_ORG),
                "mandatee", Map.of("domain", "machine.example.com"),
                "power", List.of(Map.of(
                        "type", "Domain", "domain", TENANT,
                        "function", "Onboarding", "action", List.of("Execute"))));
    }

    private Map<String, Object> holderKey() {
        return Map.of("jwk", Map.of(
                "kty", "EC",
                "crv", "P-256",
                "x", "_w3A8D-bEDLVjiTFZLturS4rf_aS9vGkW3jKuyVmn5A",
                "y", "hKdwPYqCndCfDkk_BqtZ5xIuChfrAiK5u8dkkFriVvY"));
    }

    private WebTestClient.RequestHeadersSpec<?> post(String bearer, Object body) {
        return webTestClient.post()
                .uri(ISSUANCES_URI)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + bearer)
                .header(X_TENANT_HEADER, TENANT)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body);
    }

    // ---------------------------------------------------------------- tests

    @Test
    void directIssuance_withoutIdTokenHeader_returnsSignedCredential() throws Exception {
        // The exact shape that used to return a 500: delivery=direct, no X-Id-Token, on a profile
        // whose issuance policy does not demand one.
        Map<String, Object> body = Map.of(
                "schema", MACHINE_CONFIG_ID,
                "delivery", "direct",
                "email", "operator@example.com",
                "holder_key", holderKey(),
                "payload", machinePayload());

        post(operatorToken(), body)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.signed_credential").isEqualTo("signed.credential.jwt");
    }

    @Test
    void directIssuance_ofProfileRequiringIdToken_withoutHeader_returns400() throws Exception {
        // Guard rail for the fix: relaxing the caller-token checks must NOT weaken the
        // X-Id-Token requirement of profiles carrying RequireCertificationIssuance.
        // gx.labelcredential.w3c.2 is the sharpest case there is: direct-eligible (no
        // cryptographic_binding_methods_supported), needs no holder_key (cnf_required=false),
        // and still demands X-Id-Token. Same delivery mode as the test above.
        Map<String, Object> body = Map.of(
                "schema", LABEL_CONFIG_ID,
                "delivery", "direct",
                "email", "operator@example.com",
                "payload", Map.of("credentialSubject", Map.of("id", "did:web:service.example.com")));

        post(operatorToken(), body)
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.type").isEqualTo("missing_header");
    }
}
