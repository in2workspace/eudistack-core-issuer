package es.in2.issuer.backend.statuslist.infrastructure.controller;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.domain.spi.IssuancePort;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.infrastructure.adapter.DelegatingSigningProvider;
import es.in2.issuer.backend.statuslist.domain.model.StatusListFormat;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import es.in2.issuer.backend.statuslist.domain.util.BitstringEncoder;
import es.in2.issuer.backend.statuslist.domain.util.factory.IssuerFactory;
import es.in2.issuer.backend.statuslist.infrastructure.adapter.BitstringStatusListProvider;
import es.in2.issuer.backend.shared.domain.model.dto.credential.SimpleIssuer;
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
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * EUD-271 — {@code POST /api/v1/issuances/{id}/revocation} against a real Postgres, the real security
 * chain, the real policy rules and the real transaction manager. The QTSP, the Verifier and the mail
 * server are the only fakes: they are external systems, and faking them is how a failure is forced.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class RevocationControllerIT {

    private static final String TENANT = "revtenant";
    private static final String PLATFORM = "platform";
    private static final String CREDENTIAL_CONFIG_ID = "learcredential.employee.w3c.4";
    private static final String ORG = "ORG-A";
    private static final String BASE_URL = "https://issuer.example.com";
    private static final String REASON = "Baja del empleado";
    private static final String HOLDER_EMAIL = "holder@example.com";

    private static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>(DockerImageName.parse("postgres:17-alpine"))
                    .withDatabaseName("issuer")
                    .withUsername("issuer")
                    .withPassword("issuer");

    static {
        POSTGRES.start();
        try (Connection conn = jdbc(); Statement stmt = conn.createStatement()) {
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
                    VALUES ('%s', 'Revocation tenant', 'multi_org', 'active'),
                           ('%s', 'Platform', 'multi_org', 'active')
                    ON CONFLICT (schema_name) DO NOTHING
                    """.formatted(TENANT, PLATFORM));
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to seed tenant_registry", e);
        }
    }

    @DynamicPropertySource
    static void registerProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.r2dbc.url", () -> "r2dbc:postgresql://" + POSTGRES.getHost() + ":"
                + POSTGRES.getFirstMappedPort() + "/" + POSTGRES.getDatabaseName());
        registry.add("spring.r2dbc.username", POSTGRES::getUsername);
        registry.add("spring.r2dbc.password", POSTGRES::getPassword);
        registry.add("spring.flyway.url", POSTGRES::getJdbcUrl);
        registry.add("credential.profiles.path", () -> "classpath:test-credential-profiles");
    }

    private static Connection jdbc() throws SQLException {
        return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }

    @LocalServerPort
    private int port;

    @Autowired
    private BitstringStatusListProvider statusListProvider;

    @MockitoSpyBean
    private IssuancePort issuancePort;

    @MockitoSpyBean
    private AuditService auditService;

    @MockitoBean
    private VerifierService verifierService;

    @MockitoBean
    private DelegatingSigningProvider signingProvider;

    @MockitoBean
    private IssuerFactory issuerFactory;

    @MockitoBean
    private EmailService emailService;

    private WebTestClient client;
    private String issuerOrigin;
    private ECKey signingKey;
    private ListAppender<ILoggingEvent> audit;

    @BeforeEach
    void setUp() throws Exception {
        issuerOrigin = "http://localhost:" + port;
        client = WebTestClient.bindToServer().baseUrl(issuerOrigin).responseTimeout(Duration.ofSeconds(30)).build();
        signingKey = new ECKeyGenerator(Curve.P_256).keyID("test-signer").generate();
        when(verifierService.verifyToken(anyString())).thenReturn(Mono.empty());
        when(issuerFactory.createSimpleIssuer()).thenReturn(Mono.just(SimpleIssuer.builder().id("did:elsi:VATES-TEST").build()));
        when(signingProvider.sign(any(SigningRequest.class))).thenAnswer(inv -> qtspSigns(inv.getArgument(0)));
        when(emailService.sendCredentialStatusChangeNotification(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());
        try (Connection conn = jdbc(); Statement stmt = conn.createStatement()) {
            for (String tenant : List.of(TENANT, PLATFORM)) {
                stmt.execute("""
                        INSERT INTO %s%s.tenant_config (config_key, config_value)
                        VALUES ('admin_organization_id', 'ADMIN-ORG-NONE')
                        ON CONFLICT (config_key) DO NOTHING
                        """.formatted(tenant, SCHEMA_SUFFIX));
            }
        }
        audit = new ListAppender<>();
        audit.start();
        ((Logger) LoggerFactory.getLogger("AUDIT")).addAppender(audit);
    }

    @AfterEach
    void tearDown() {
        ((Logger) LoggerFactory.getLogger("AUDIT")).detachAppender(audit);
        audit.stop();
    }

    private static Mono<SigningResult> qtspSigns(SigningRequest request) {
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(request.data().getBytes(StandardCharsets.UTF_8));
        return Mono.just(new SigningResult(request.type(), "header." + payload + ".signature"));
    }

    // ---------------------------------------------------------------- fixtures

    private Issuance seed(CredentialStatusEnum status, String org) {
        return seed(status, org, TENANT);
    }

    private Issuance seed(CredentialStatusEnum status, String org, String tenant) {
        Issuance issuance = Issuance.builder()
                .credentialFormat("jwt_vc_json")
                .credentialDataSet("{\"credentialSubject\":{\"mandate\":{\"mandatee\":{\"employeeId\":\"E-77\"}}}}")
                .credentialStatus(status)
                .organizationIdentifier(org)
                .subject("Ana Holder")
                .credentialType(CREDENTIAL_CONFIG_ID)
                .email(HOLDER_EMAIL)
                .delivery("email")
                .build();
        return issuancePort.insert(issuance).contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant)).block();
    }

    /** A Valid attestation with its position reserved in a list, through the real allocation path. */
    private Issuance seedValidInList() {
        Issuance issuance = seed(CredentialStatusEnum.VALID, ORG);
        statusListProvider.allocateEntry(StatusPurpose.REVOCATION, StatusListFormat.BITSTRING_VC,
                        issuance.getIssuanceId().toString(), "seed-token", BASE_URL)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT))
                .block();
        return issuance;
    }

    private CredentialStatusEnum status(Issuance issuance) {
        return issuancePort.findByIssuanceId(issuance.getIssuanceId())
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT))
                .map(Issuance::getCredentialStatus)
                .block();
    }

    private boolean bit(Issuance issuance) throws SQLException {
        try (Connection conn = jdbc(); Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("""
                     SELECT l.encoded_list, i.idx
                     FROM %1$s%2$s.status_list_index i
                     JOIN %1$s%2$s.status_list l ON l.id = i.status_list_id
                     WHERE i.issuance_id = '%3$s'
                     """.formatted(TENANT, SCHEMA_SUFFIX, issuance.getIssuanceId()))) {
            assertThat(rs.next()).isTrue();
            return new BitstringEncoder().getBit(rs.getString(1), rs.getInt(2));
        }
    }

    private String token(String org, List<Map<String, Object>> powers) throws Exception {
        return token(org, powers, TENANT, Map.of());
    }

    /** A token the Verifier signs, with {@code extra} claims on top of (or replacing) the usual ones. */
    private String token(String org, List<Map<String, Object>> powers, String tokenTenant,
                         Map<String, Object> extra) throws Exception {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(issuerOrigin + "/verifier")
                .subject("did:key:requester")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 3_600_000L))
                .claim("credential_type", CREDENTIAL_CONFIG_ID)
                .claim("mandator", Map.of("organizationIdentifier", org))
                .claim("power", powers)
                .claim("tenant", tokenTenant);
        extra.forEach(builder::claim);
        JWTClaimsSet claims = builder.build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(signingKey.getKeyID()).build(), claims);
        jwt.sign(new ECDSASigner(signingKey));
        return jwt.serialize();
    }

    private String operator() throws Exception {
        return token(ORG, List.of(Map.of("function", "Onboarding", "action", "Execute", "domain", TENANT, "type", "organization")));
    }

    private static String path(Object id) {
        return "/api/v1/issuances/" + id + "/revocation";
    }

    private WebTestClient.ResponseSpec revoke(String bearer, Object id, String jsonBody) {
        return revoke(bearer, id, jsonBody, TENANT, null);
    }

    private WebTestClient.ResponseSpec revoke(String bearer, Object id, String jsonBody, String tenant, String idToken) {
        WebTestClient.RequestBodySpec spec = client.post()
                .uri("/issuer" + path(id))
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + bearer)
                .header(X_TENANT_HEADER, tenant)
                .accept(MediaType.APPLICATION_JSON);
        if (idToken != null) {
            spec = spec.header("X-ID-Token", idToken);
        }
        return jsonBody == null
                ? spec.exchange()
                : spec.contentType(MediaType.APPLICATION_JSON).bodyValue(jsonBody).exchange();
    }

    private WebTestClient.ResponseSpec revoke(String bearer, Issuance issuance) {
        return revoke(bearer, issuance.getIssuanceId(), "{\"reason\":\"" + REASON + "\"}");
    }

    private static void expectProblem(WebTestClient.ResponseSpec response, int status, String type, Object id) {
        response.expectStatus().isEqualTo(status)
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo(type)
                .jsonPath("$.status").isEqualTo(status)
                .jsonPath("$.title").isNotEmpty()
                .jsonPath("$.instance").isEqualTo(path(id));
    }

    private List<String> auditMessages() {
        return audit.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }

    private void verifyNotices(int count) {
        verify(emailService, times(count)).sendCredentialStatusChangeNotification(anyString(), anyString(), anyString(), anyString());
    }

    // ---------------------------------------------------------------- AC-01, AC-07, AC-10, AC-13

    @Test
    void revoke_valid_marksTheList_movesTheProcess_notifiesAndTraces() throws Exception {
        Issuance issuance = seedValidInList();
        String bearer = operator();

        revoke(bearer, issuance).expectStatus().isNoContent().expectBody().isEmpty();

        assertThat(status(issuance)).isEqualTo(CredentialStatusEnum.REVOKED);
        assertThat(bit(issuance)).isTrue();
        verify(emailService).sendCredentialStatusChangeNotification(eq(HOLDER_EMAIL), anyString(), eq(CREDENTIAL_CONFIG_ID), eq("REVOKED"));
        assertThat(auditMessages()).anySatisfy(message -> assertThat(message)
                .contains("event=credential.revoked", "userId=did:key:requester", "organizationId=" + ORG,
                        "requesterOrganizationId=" + ORG, REASON)
                // The holder goes to the encrypted audit store with EUD-244, not to these logs (AC-13).
                .doesNotContain(bearer, "mandatee", "holderName", "Ana Holder", HOLDER_EMAIL, "E-77"));
    }

    // ---------------------------------------------------------------- AC-03

    @Test
    void revoke_twice_answersAlreadyRevoked_withoutRepeatingAnyEffect() throws Exception {
        Issuance issuance = seedValidInList();
        String bearer = operator();
        revoke(bearer, issuance).expectStatus().isNoContent();

        expectProblem(revoke(bearer, issuance), 409, "already_revoked", issuance.getIssuanceId());

        verifyNotices(1);
        assertThat(auditMessages()).filteredOn(m -> m.contains("event=credential.revoked")).hasSize(1);
    }

    // ---------------------------------------------------------------- AC-04

    @ParameterizedTest
    @EnumSource(value = CredentialStatusEnum.class, names = {"VALID", "REVOKED"}, mode = EnumSource.Mode.EXCLUDE)
    void revoke_notValid_answersNotRevocable_andChangesNothing(CredentialStatusEnum current) throws Exception {
        Issuance issuance = seed(current, ORG);

        expectProblem(revoke(operator(), issuance), 409, "not_revocable", issuance.getIssuanceId());

        assertThat(status(issuance)).isEqualTo(current);
        verifyNotices(0);
    }

    @Test
    void revoke_validWithoutAPositionInAList_answersNotRevocable() throws Exception {
        Issuance issuance = seed(CredentialStatusEnum.VALID, ORG);

        expectProblem(revoke(operator(), issuance), 409, "not_revocable", issuance.getIssuanceId());

        assertThat(status(issuance)).isEqualTo(CredentialStatusEnum.VALID);
    }

    // ---------------------------------------------------------------- AC-05

    @Test
    void revoke_outOfScopeAndUnknown_answerTheSame() throws Exception {
        Issuance foreign = seed(CredentialStatusEnum.VALID, "ORG-B");
        UUID unknown = UUID.randomUUID();
        // The administrator of one organization: a tenant administrator's scope is the whole tenant (EUD-272).
        String bearer = token(ORG, List.of(Map.of("function", "Onboarding", "action", "Execute", "domain", TENANT, "type", "domain")));

        expectProblem(revoke(bearer, foreign), 404, "issuance_not_found", foreign.getIssuanceId());
        expectProblem(revoke(bearer, unknown, "{\"reason\":\"x\"}"), 404, "issuance_not_found", unknown);

        byte[] foreignBody = revoke(bearer, foreign).expectBody().returnResult().getResponseBody();
        byte[] unknownBody = revoke(bearer, unknown, "{\"reason\":\"x\"}").expectBody().returnResult().getResponseBody();
        assertThat(new String(foreignBody, StandardCharsets.UTF_8).replace(foreign.getIssuanceId().toString(), "ID"))
                .isEqualTo(new String(unknownBody, StandardCharsets.UTF_8).replace(unknown.toString(), "ID"));
        assertThat(status(foreign)).isEqualTo(CredentialStatusEnum.VALID);
    }

    @Test
    void revoke_withoutThePower_isForbidden_whetherOrNotTheIdExists() throws Exception {
        Issuance issuance = seed(CredentialStatusEnum.VALID, ORG);
        UUID unknown = UUID.randomUUID();
        String weak = token(ORG, List.of());

        expectProblem(revoke(weak, issuance), 403, "insufficient_permission", issuance.getIssuanceId());
        expectProblem(revoke(weak, unknown, "{\"reason\":\"x\"}"), 403, "insufficient_permission", unknown);
    }

    @Test
    void revoke_fromAnotherTenant_isTenantMismatch_whetherOrNotTheIdExists() throws Exception {
        Issuance issuance = seed(CredentialStatusEnum.VALID, ORG);
        UUID unknown = UUID.randomUUID();
        String foreignTenant = token(ORG, List.of(Map.of("function", "Onboarding", "action", "Execute", "domain", TENANT, "type", "organization")),
                "othertenant", Map.of());

        expectProblem(revoke(foreignTenant, issuance), 403, "tenant_mismatch", issuance.getIssuanceId());
        expectProblem(revoke(foreignTenant, unknown, "{\"reason\":\"x\"}"), 403, "tenant_mismatch", unknown);

        assertThat(status(issuance)).isEqualTo(CredentialStatusEnum.VALID);
    }

    /** The platform administrator only reads from the platform tenant: revoking is denied, also for an id that exists. */
    @Test
    void revoke_platformSysAdminFromThePlatformTenant_isForbidden() throws Exception {
        Issuance issuance = seed(CredentialStatusEnum.VALID, ORG, PLATFORM);
        UUID unknown = UUID.randomUUID();
        String sysAdmin = token(ORG, List.of(Map.of("function", "System", "action", List.of("Administration"), "domain", "EUDISTACK", "type", "organization")),
                PLATFORM, Map.of());

        expectProblem(revoke(sysAdmin, issuance.getIssuanceId(), "{\"reason\":\"x\"}", PLATFORM, null),
                403, "insufficient_permission", issuance.getIssuanceId());
        expectProblem(revoke(sysAdmin, unknown, "{\"reason\":\"x\"}", PLATFORM, null), 403, "insufficient_permission", unknown);

        CredentialStatusEnum stored = issuancePort.findByIssuanceId(issuance.getIssuanceId())
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, PLATFORM))
                .map(Issuance::getCredentialStatus)
                .block();
        assertThat(stored).isEqualTo(CredentialStatusEnum.VALID);
    }

    // ---------------------------------------------------------------- AC-02, AC-10 (actor)

    /** A system revokes like a person, and the trace names it by the DID of its mandatee, not by its sub (an IP). */
    @Test
    void revoke_bySystem_answersNoContent_andTracesItsDid() throws Exception {
        Issuance issuance = seedValidInList();
        String system = token(ORG, List.of(Map.of("function", "Onboarding", "action", "Execute", "domain", TENANT, "type", "organization")),
                TENANT, Map.of("sub", "127.0.0.1", "mandatee", Map.of("id", "did:key:zSystem", "ipAddress", "127.0.0.1")));

        revoke(system, issuance).expectStatus().isNoContent().expectBody().isEmpty();

        assertThat(status(issuance)).isEqualTo(CredentialStatusEnum.REVOKED);
        assertThat(bit(issuance)).isTrue();
        verify(auditService).auditSuccess(eq("credential.revoked"), eq("did:key:zSystem"), eq("credential"),
                eq(issuance.getIssuanceId().toString()), any());
    }

    /**
     * The X-ID-Token is read without checking its signature: one naming somebody else must not change the
     * actor, which only the verified access token names.
     */
    @Test
    void revoke_withAForgedIdToken_tracesTheActorOfTheAccessToken() throws Exception {
        Issuance issuance = seedValidInList();
        String forgedIdToken = unsigned(Map.of("email", "victim@example.com", "sub", "victim@example.com"));

        revoke(operator(), issuance.getIssuanceId(), "{\"reason\":\"" + REASON + "\"}", TENANT, forgedIdToken)
                .expectStatus().isNoContent();

        String id = issuance.getIssuanceId().toString();
        verify(auditService).auditAttempted(eq("credential.revoke.attempted"), eq("did:key:requester"), eq("credential"), eq(id), any());
        verify(auditService).auditSuccess(eq("credential.revoked"), eq("did:key:requester"), eq("credential"), eq(id), any());
        verify(auditService, never()).auditSuccess(eq("credential.revoked"), eq("victim@example.com"), any(), any(), any());
    }

    private static String unsigned(Map<String, Object> claims) throws Exception {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String header = encoder.encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = encoder.encodeToString(new ObjectMapper().writeValueAsBytes(claims));
        return header + "." + payload + ".not-a-signature";
    }

    // ---------------------------------------------------------------- AC-06

    @Test
    void revoke_withoutAValidReason_answersBadRequestWithViolations() throws Exception {
        Issuance issuance = seed(CredentialStatusEnum.VALID, ORG);
        UUID id = issuance.getIssuanceId();
        String bearer = operator();
        String tooLong = "{\"reason\":\"" + "x".repeat(281) + "\"}";

        for (String body : new String[]{null, "{}", "{\"reason\":\"\"}", "{\"reason\":null}", "{\"reason\":5}", "{\"reason\":true}", "{\"reason\":[\"x\"]}", tooLong, "{not json"}) {
            WebTestClient.ResponseSpec response = revoke(bearer, id, body);
            response.expectStatus().isBadRequest()
                    .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                    .expectBody()
                    .jsonPath("$.type").isEqualTo("BAD_REQUEST")
                    .jsonPath("$.instance").isEqualTo(path(id))
                    .jsonPath("$.violations[0].field").isEqualTo("reason");
        }

        assertThat(status(issuance)).isEqualTo(CredentialStatusEnum.VALID);
        assertThat(auditMessages()).anySatisfy(message ->
                assertThat(message).contains("event=credential.revoke.failed", "reason=BAD_REQUEST", "userId=did:key:requester"));
    }

    @Test
    void revoke_idNotAUuid_answersBadRequestWithViolations() throws Exception {
        revoke(operator(), "not-a-uuid", "{\"reason\":\"x\"}").expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.type").isEqualTo("BAD_REQUEST")
                .jsonPath("$.violations[0].field").isEqualTo("id");
    }

    @Test
    void revoke_withoutToken_isUnauthorized() {
        Issuance issuance = seed(CredentialStatusEnum.VALID, ORG);

        client.post().uri("/issuer" + path(issuance.getIssuanceId()))
                .header(X_TENANT_HEADER, TENANT)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"x\"}")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("authentication_error")
                .jsonPath("$.status").isEqualTo(401)
                .jsonPath("$.instance").isEqualTo(path(issuance.getIssuanceId()));

        org.mockito.ArgumentCaptor<java.util.Map<String, Object>> details = org.mockito.ArgumentCaptor.captor();
        verify(auditService).auditFailure(org.mockito.ArgumentMatchers.eq("credential.revoke.failed"),
                org.mockito.ArgumentMatchers.eq("anonymous"), org.mockito.ArgumentMatchers.anyString(), details.capture());
        assertThat(details.getValue()).containsKeys("resourceId", "reason", "declaredClientAddress");
    }

    // ---------------------------------------------------------------- AC-08

    @Test
    void revoke_sealFails_answersUnavailable_andChangesNothing() throws Exception {
        Issuance issuance = seedValidInList();
        when(signingProvider.sign(any(SigningRequest.class))).thenReturn(Mono.error(new RemoteSignatureException("QTSP down")));

        WebTestClient.ResponseSpec response = revoke(operator(), issuance);

        response.expectHeader().valueEquals(HttpHeaders.RETRY_AFTER, RevocationExceptionHandler.RETRY_AFTER_SECONDS);
        expectProblem(response, 503, "status_list_unavailable", issuance.getIssuanceId());
        assertThat(status(issuance)).isEqualTo(CredentialStatusEnum.VALID);
        assertThat(bit(issuance)).isFalse();
        verifyNotices(0);
    }

    /** The hole EUD-247 closes: before, the list stayed revoked with the process still Valid. */
    @Test
    void revoke_processWriteFails_rollsTheListBack() throws Exception {
        Issuance issuance = seedValidInList();
        String signedBefore = signedList(issuance);
        doReturn(Mono.error(new IllegalStateException("database down"))).when(issuancePort).save(any());

        expectProblem(revoke(operator(), issuance), 503, "status_list_unavailable", issuance.getIssuanceId());

        assertThat(status(issuance)).isEqualTo(CredentialStatusEnum.VALID);
        assertThat(bit(issuance)).isFalse();
        assertThat(signedList(issuance)).isEqualTo(signedBefore);
        verifyNotices(0);
    }

    private String signedList(Issuance issuance) throws SQLException {
        try (Connection conn = jdbc(); Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("""
                     SELECT l.signed_credential
                     FROM %1$s%2$s.status_list_index i
                     JOIN %1$s%2$s.status_list l ON l.id = i.status_list_id
                     WHERE i.issuance_id = '%3$s'
                     """.formatted(TENANT, SCHEMA_SUFFIX, issuance.getIssuanceId()))) {
            assertThat(rs.next()).isTrue();
            return rs.getString(1);
        }
    }

    // ---------------------------------------------------------------- AC-11

    @Test
    void revoke_twoAtOnce_appliesOne_andTheOtherAnswersAlreadyRevoked() throws Exception {
        Issuance issuance = seedValidInList();
        String bearer = operator();
        // Both requests pass the status check before either writes: the seal is what they wait on.
        when(signingProvider.sign(any(SigningRequest.class)))
                .thenAnswer(inv -> Mono.delay(Duration.ofMillis(300)).then(qtspSigns(inv.getArgument(0))));

        List<WebTestClient.ResponseSpec> responses = concurrently(() -> revoke(bearer, issuance), () -> revoke(bearer, issuance));

        List<Integer> statuses = responses.stream()
                .map(r -> r.returnResult(String.class).getStatus().value())
                .sorted()
                .toList();
        assertThat(statuses).containsExactly(204, 409);
        assertThat(status(issuance)).isEqualTo(CredentialStatusEnum.REVOKED);
        assertThat(bit(issuance)).isTrue();
        verifyNotices(1);
        assertThat(auditMessages()).filteredOn(m -> m.contains("event=credential.revoked")).hasSize(1);
        assertThat(auditMessages()).anySatisfy(m -> assertThat(m).contains("event=credential.revoke.failed", "reason=already_revoked"));
    }

    /** Sharing a list is the common case: the loser of the list's lock retries and must still apply. */
    @Test
    void revoke_twoAttestationsOfOneListAtOnce_bothApply() throws Exception {
        Issuance first = seedValidInList();
        Issuance second = seedValidInList();
        String bearer = operator();
        when(signingProvider.sign(any(SigningRequest.class)))
                .thenAnswer(inv -> Mono.delay(Duration.ofMillis(200)).then(qtspSigns(inv.getArgument(0))));

        List<WebTestClient.ResponseSpec> responses = concurrently(() -> revoke(bearer, first), () -> revoke(bearer, second));

        responses.forEach(response -> response.expectStatus().isNoContent());
        assertThat(status(first)).isEqualTo(CredentialStatusEnum.REVOKED);
        assertThat(status(second)).isEqualTo(CredentialStatusEnum.REVOKED);
        assertThat(bit(first)).isTrue();
        assertThat(bit(second)).isTrue();
        verifyNotices(2);
    }

    @SafeVarargs
    private static List<WebTestClient.ResponseSpec> concurrently(java.util.function.Supplier<WebTestClient.ResponseSpec>... calls) {
        List<CompletableFuture<WebTestClient.ResponseSpec>> futures = new ArrayList<>();
        for (java.util.function.Supplier<WebTestClient.ResponseSpec> call : calls) {
            futures.add(CompletableFuture.supplyAsync(call));
        }
        return futures.stream().map(CompletableFuture::join).toList();
    }

    // ---------------------------------------------------------------- AD-3

    @Test
    void revoke_bitLeftSetByAnOlderDivergence_completesTheProcess_withOneNotice() throws Exception {
        Issuance issuance = seedValidInList();
        statusListProvider.revoke(issuance.getIssuanceId().toString(), "seed-token", BASE_URL, Mono.empty())
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT))
                .block();
        assertThat(bit(issuance)).isTrue();
        assertThat(status(issuance)).isEqualTo(CredentialStatusEnum.VALID);

        revoke(operator(), issuance).expectStatus().isNoContent();

        assertThat(status(issuance)).isEqualTo(CredentialStatusEnum.REVOKED);
        verifyNotices(1);
    }

    // ---------------------------------------------------------------- The deprecated alias

    @Test
    void alias_stillRevokesWithoutReason_andKeepsItsErrorCodes() throws Exception {
        Issuance issuance = seedValidInList();
        String bearer = operator();
        String body = "{\"issuanceId\":\"" + issuance.getIssuanceId() + "\"}";

        alias(bearer, body).expectStatus().isNoContent();
        assertThat(status(issuance)).isEqualTo(CredentialStatusEnum.REVOKED);
        assertThat(bit(issuance)).isTrue();

        alias(bearer, body).expectStatus().isEqualTo(409).expectBody().jsonPath("$.type").isEqualTo("invalid_status");
    }

    private WebTestClient.ResponseSpec alias(String bearer, String body) {
        return client.post().uri("/issuer/w3c/v1/credentials/status/revoke")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + bearer)
                .header(X_TENANT_HEADER, TENANT)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange();
    }

    // ---------------------------------------------------------------- Tokens the decision cannot read

    private String tokenWithout(String... claims) throws Exception {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder(SignedJWT.parse(operator()).getJWTClaimsSet());
        for (String claim : claims) {
            builder.claim(claim, null);
        }
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(signingKey.getKeyID()).build(), builder.build());
        jwt.sign(new ECDSASigner(signingKey));
        return jwt.serialize();
    }

    @Test
    void revoke_tokenWithoutCredentialType_isDecidedByItsPowers() throws Exception {
        // EUD-272: the decision reads the powers, so the claim is not needed; a draft shows it was decided.
        Issuance issuance = seed(CredentialStatusEnum.DRAFT, ORG);

        expectProblem(revoke(tokenWithout("credential_type"), issuance), 409, "not_revocable", issuance.getIssuanceId());

        assertThat(status(issuance)).isEqualTo(CredentialStatusEnum.DRAFT);
    }

    @Test
    void revoke_tokenWithoutOrganization_isInvalidToken_notAnError() throws Exception {
        Issuance issuance = seed(CredentialStatusEnum.VALID, ORG);

        expectProblem(revoke(tokenWithout("mandator"), issuance), 401, "invalid_token", issuance.getIssuanceId());

        assertThat(status(issuance)).isEqualTo(CredentialStatusEnum.VALID);
    }
}
