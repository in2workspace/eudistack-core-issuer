package es.in2.issuer.backend.statuslist.infrastructure.controller;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.infrastructure.repository.IssuanceRepository;
import es.in2.issuer.backend.statuslist.domain.model.dto.RevokeCredentialRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
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
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * EUD-97 — Proteger la revocación frente a estados no revocables y ámbitos ajenos.
 *
 * <p>End-to-end coverage of AC-01..AC-06, EC-01, EC-03, ES-01 and ES-02 against a real
 * Postgres (Testcontainers), the real security filter chain and the real policy rule
 * chain ({@code StatusListPdpServiceImpl}). {@link VerifierService} is the only mocked
 * collaborator: it is an external system (crypto verification against the Verifier's
 * own JWKS), not part of the issuer's own safeguards under test. The JWT itself is a
 * real, locally-signed {@code SignedJWT} whose {@code iss} claim matches the verifier
 * origin the running server computes for this request, so it is routed through
 * {@code CustomAuthenticationManager}'s verifier-token branch exactly like a real
 * operator session token would be.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class BitstringStatusListControllerRevokeIT {

    private static final String TENANT_A = "tenanta";
    private static final String TENANT_B = "tenantb";
    private static final String CREDENTIAL_CONFIG_ID = "learcredential.employee.w3c.4";
    private static final String REVOKE_PATH = "/issuer/w3c/v1/credentials/status/revoke";

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
        // Real profile definitions copied from dev-tools/schemas/ (single source of truth,
        // normally mounted at file:/etc/eudistack/schemas in Docker) — see
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
                    VALUES ('%s', 'Tenant A', 'multi_org', 'active'),
                           ('%s', 'Tenant B', 'multi_org', 'active')
                    ON CONFLICT (schema_name) DO NOTHING
                    """.formatted(TENANT_A, TENANT_B));
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to seed tenant_registry for IT", e);
        }
    }

    private static Connection jdbcConnection() throws SQLException {
        return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }

    @LocalServerPort
    private int port;

    @Autowired
    private IssuanceRepository issuanceRepository;

    @MockitoBean
    private VerifierService verifierService;

    private WebTestClient webTestClient;
    private String issuerOrigin;
    private ECKey signingKey;
    private ListAppender<ILoggingEvent> auditAppender;

    @BeforeEach
    void setUp() throws Exception {
        issuerOrigin = "http://localhost:" + port;
        webTestClient = WebTestClient.bindToServer().baseUrl(issuerOrigin).build();
        signingKey = new ECKeyGenerator(Curve.P_256).keyID("test-signer").generate();
        when(verifierService.verifyToken(anyString())).thenReturn(Mono.empty());

        // admin_organization_id is deliberately NOT seeded by V1__Tenant_schema.sql (it's
        // provisioned per-tenant outside the issuer in real environments — see the comment
        // in that migration). Seed it here to a value that never matches a test operator's
        // org, so PolicyContextFactory#resolveTenantAdmin resolves to `false` instead of
        // throwing TenantConfigMissingException, and none of our operators are accidentally
        // treated as the tenant's admin-org bypass.
        seedAdminOrgPlaceholder(TENANT_A);
        seedAdminOrgPlaceholder(TENANT_B);
    }

    // EUD-98: capture the AUDIT logger's output so tests can assert the revocation
    // audit trail (attempted/revoked/failed) against the real Spring context, real
    // security filter chain and real policy rule chain — not mocks.
    @BeforeEach
    void attachAuditAppender() {
        Logger auditLogger = (Logger) LoggerFactory.getLogger("AUDIT");
        auditAppender = new ListAppender<>();
        auditAppender.start();
        auditLogger.addAppender(auditAppender);
    }

    @AfterEach
    void detachAuditAppender() {
        if (auditAppender == null) {
            return;
        }
        Logger auditLogger = (Logger) LoggerFactory.getLogger("AUDIT");
        auditLogger.detachAppender(auditAppender);
        auditAppender.stop();
    }

    private List<String> auditMessages() {
        return auditAppender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }

    private void seedAdminOrgPlaceholder(String tenant) throws SQLException {
        try (Connection conn = jdbcConnection(); Statement stmt = conn.createStatement()) {
            stmt.execute(("""
                    INSERT INTO %s%s.tenant_config (config_key, config_value)
                    VALUES ('admin_organization_id', 'ADMIN-ORG-NONE')
                    ON CONFLICT (config_key) DO NOTHING
                    """).formatted(tenant, SCHEMA_SUFFIX));
        }
    }

    // ---------------------------------------------------------------- helpers

    private Issuance seedIssuance(String tenant, String orgId, CredentialStatusEnum status) {
        Issuance issuance = Issuance.builder()
                .credentialFormat("jwt_vc_json")
                .credentialDataSet("{}")
                .credentialStatus(status)
                .organizationIdentifier(orgId)
                .credentialType(CREDENTIAL_CONFIG_ID)
                .email("operator@example.com")
                .delivery("email")
                .build();
        return issuanceRepository.save(issuance)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant))
                .block();
    }

    private CredentialStatusEnum currentStatus(String tenant, UUID issuanceId) {
        return issuanceRepository.findByIssuanceId(issuanceId)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant))
                .map(Issuance::getCredentialStatus)
                .block();
    }

    private String token(String orgId, String tokenTenant, List<Map<String, Object>> powers) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuerOrigin + "/verifier")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 3_600_000L))
                .claim("credential_type", CREDENTIAL_CONFIG_ID)
                .claim("mandator", Map.of("organizationIdentifier", orgId))
                .claim("power", powers)
                .claim("tenant", tokenTenant)
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(signingKey.getKeyID()).build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(signingKey));
        return jwt.serialize();
    }

    private static Map<String, Object> executePower(String domain) {
        return Map.of("function", "Onboarding", "action", "Execute", "domain", domain, "type", "organization");
    }

    private WebTestClient.ResponseSpec revoke(String tenantHeader, String bearerToken, String issuanceId) {
        return webTestClient.post()
                .uri(REVOKE_PATH)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + bearerToken)
                .header(X_TENANT_HEADER, tenantHeader)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new RevokeCredentialRequest(issuanceId, null))
                .exchange();
    }

    // ---------------------------------------------------------------- AC-01 / AC-02 / EC-01

    @Test
    void revoke_alreadyRevoked_returns409AndKeepsStatus() throws Exception {
        Issuance issuance = seedIssuance(TENANT_A, "ORG-A", CredentialStatusEnum.REVOKED);
        String bearer = token("ORG-A", TENANT_A, List.of(executePower(TENANT_A)));

        revoke(TENANT_A, bearer, issuance.getIssuanceId().toString())
                .expectStatus().isEqualTo(409);

        assertThat(currentStatus(TENANT_A, issuance.getIssuanceId())).isEqualTo(CredentialStatusEnum.REVOKED);
    }

    @Test
    void revoke_expiredCredential_returns409AndKeepsStatus() throws Exception {
        Issuance issuance = seedIssuance(TENANT_A, "ORG-A", CredentialStatusEnum.EXPIRED);
        String bearer = token("ORG-A", TENANT_A, List.of(executePower(TENANT_A)));

        revoke(TENANT_A, bearer, issuance.getIssuanceId().toString())
                .expectStatus().isEqualTo(409);

        assertThat(currentStatus(TENANT_A, issuance.getIssuanceId())).isEqualTo(CredentialStatusEnum.EXPIRED);
    }

    @ParameterizedTest
    @EnumSource(value = CredentialStatusEnum.class, names = {"VALID", "REVOKED", "EXPIRED"}, mode = EnumSource.Mode.EXCLUDE)
    void revoke_nonValidNonTerminalStatuses_returns409(CredentialStatusEnum status) throws Exception {
        Issuance issuance = seedIssuance(TENANT_A, "ORG-A", status);
        String bearer = token("ORG-A", TENANT_A, List.of(executePower(TENANT_A)));

        revoke(TENANT_A, bearer, issuance.getIssuanceId().toString())
                .expectStatus().isEqualTo(409);

        assertThat(currentStatus(TENANT_A, issuance.getIssuanceId())).isEqualTo(status);
    }

    // ---------------------------------------------------------------- AC-03 / AC-04 / AC-05

    @Test
    void revoke_crossOrganization_returns403AndKeepsStatus() throws Exception {
        Issuance issuance = seedIssuance(TENANT_A, "ORG-B", CredentialStatusEnum.VALID);
        // Operator belongs to ORG-A and has the required power, but the credential belongs to ORG-B.
        String bearer = token("ORG-A", TENANT_A, List.of(executePower(TENANT_A)));

        revoke(TENANT_A, bearer, issuance.getIssuanceId().toString())
                .expectStatus().isEqualTo(403);

        assertThat(currentStatus(TENANT_A, issuance.getIssuanceId())).isEqualTo(CredentialStatusEnum.VALID);
    }

    @Test
    void revoke_crossTenant_returns403AndKeepsStatus() throws Exception {
        Issuance issuance = seedIssuance(TENANT_B, "ORG-B", CredentialStatusEnum.VALID);
        // Token's 'tenant' claim is tenant-a, but the request is resolved against tenant-b
        // (X-Tenant header) — RequireTenantMatchRule must deny before anything else runs.
        String bearer = token("ORG-B", TENANT_A, List.of(executePower(TENANT_A)));

        revoke(TENANT_B, bearer, issuance.getIssuanceId().toString())
                .expectStatus().isEqualTo(403);

        assertThat(currentStatus(TENANT_B, issuance.getIssuanceId())).isEqualTo(CredentialStatusEnum.VALID);
    }

    @Test
    void revoke_readOnlyActorWithoutPower_returns403AndKeepsStatus() throws Exception {
        Issuance issuance = seedIssuance(TENANT_A, "ORG-A", CredentialStatusEnum.VALID);
        // Same org as the credential and correct tenant, but no Onboarding/Execute power at all
        // (multi-org admin with a read-only role).
        String bearer = token("ORG-A", TENANT_A, List.of());

        revoke(TENANT_A, bearer, issuance.getIssuanceId().toString())
                .expectStatus().isEqualTo(403);

        assertThat(currentStatus(TENANT_A, issuance.getIssuanceId())).isEqualTo(CredentialStatusEnum.VALID);
    }

    // ---------------------------------------------------------------- EC-03

    @Test
    void revoke_raceSecondAttemptAfterAlreadyRevoked_returns409() throws Exception {
        // Simulates another operator having already revoked the credential between the first
        // operator loading the detail view and confirming the action: functionally identical
        // to AC-01 (the policy chain has no notion of "who got there first", only current state).
        Issuance issuance = seedIssuance(TENANT_A, "ORG-A", CredentialStatusEnum.REVOKED);
        String bearer = token("ORG-A", TENANT_A, List.of(executePower(TENANT_A)));

        revoke(TENANT_A, bearer, issuance.getIssuanceId().toString())
                .expectStatus().isEqualTo(409);

        assertThat(currentStatus(TENANT_A, issuance.getIssuanceId())).isEqualTo(CredentialStatusEnum.REVOKED);
    }

    // ---------------------------------------------------------------- ES-01 / ES-02

    @Test
    void revoke_blankIssuanceId_returns400() throws Exception {
        String bearer = token("ORG-A", TENANT_A, List.of(executePower(TENANT_A)));

        revoke(TENANT_A, bearer, "")
                .expectStatus().isEqualTo(400);
    }

    @Test
    void revoke_nonExistentIssuanceId_returns404() throws Exception {
        String bearer = token("ORG-A", TENANT_A, List.of(executePower(TENANT_A)));

        revoke(TENANT_A, bearer, UUID.randomUUID().toString())
                .expectStatus().isEqualTo(404);
    }

    // ---------------------------------------------------------------- EUD-98: audit trail (AC-02/03, ES-02/03)
    //
    // AC-01 (enriched success audit) and EC-03 (race — second attempt) are NOT exercised here:
    // both need a first revoke to actually succeed, which requires a real StatusListIndex row
    // (issuanceId -> statusListId + bitstring position), normally created by the credential
    // issuance flow's allocateEntry(). seedIssuance() only inserts a bare Issuance row, so
    // BitstringStatusListProvider.revoke() throws StatusListIndexNotFoundException before ever
    // reaching the audit code — a pre-existing gap in this harness (status-list allocation is
    // EUD-96 territory, not EUD-98's). AC-01/EC-03 are covered at the unit level instead, in
    // RevocationWorkflowTest (see revoke_success_emitsAttemptedThenEnrichedSuccessAudit), which
    // mocks statusListProvider and isn't affected by this gap. Extending this harness with real
    // status-list-index seeding is tracked as follow-up tech debt, not part of this Story.

    @Test
    void revoke_alreadyRevoked_emitsAttemptedAndFailedAuditWithInvalidStatus() throws Exception {
        Issuance issuance = seedIssuance(TENANT_A, "ORG-A", CredentialStatusEnum.REVOKED);
        String issuanceId = issuance.getIssuanceId().toString();
        String bearer = token("ORG-A", TENANT_A, List.of(executePower(TENANT_A)));

        revoke(TENANT_A, bearer, issuanceId).expectStatus().isEqualTo(409);

        List<String> messages = auditMessages();
        assertThat(messages).anyMatch(m ->
                m.contains("event=credential.revoke.attempted") && m.contains("resourceId=" + issuanceId));
        assertThat(messages).anyMatch(m ->
                m.contains("event=credential.revoke.failed") && m.contains("errorType=invalid_status"));
    }

    @Test
    void revoke_nonExistentIssuanceId_emitsAttemptedAndFailedAuditWithIssuanceNotFound() throws Exception {
        String unknownId = UUID.randomUUID().toString();
        String bearer = token("ORG-A", TENANT_A, List.of(executePower(TENANT_A)));

        revoke(TENANT_A, bearer, unknownId).expectStatus().isEqualTo(404);

        List<String> messages = auditMessages();
        assertThat(messages).anyMatch(m ->
                m.contains("event=credential.revoke.attempted") && m.contains("resourceId=" + unknownId));
        assertThat(messages).anyMatch(m ->
                m.contains("event=credential.revoke.failed") && m.contains("errorType=issuance_not_found"));
    }

}
