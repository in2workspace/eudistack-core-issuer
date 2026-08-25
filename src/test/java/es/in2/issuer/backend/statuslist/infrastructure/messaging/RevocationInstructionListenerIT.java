package es.in2.issuer.backend.statuslist.infrastructure.messaging;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.model.dto.credential.SimpleIssuer;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.domain.spi.IssuancePort;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.infrastructure.adapter.DelegatingSigningProvider;
import es.in2.issuer.backend.statuslist.domain.model.StatusListFormat;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import es.in2.issuer.backend.statuslist.domain.model.dto.RevokeCredentialRequest;
import es.in2.issuer.backend.statuslist.domain.util.factory.IssuerFactory;
import es.in2.issuer.backend.statuslist.infrastructure.adapter.BitstringStatusListProvider;
import es.in2.issuer.backend.statuslist.infrastructure.messaging.config.RevocationMessagingConfig;
import es.in2.issuer.backend.statuslist.infrastructure.messaging.dto.RevocationInstructionMessage;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.rabbit.retry.RepublishMessageRecoverer;
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
import org.testcontainers.containers.RabbitMQContainer;
import org.testcontainers.utility.DockerImageName;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * First test of the revocation-instruction queue against a real broker (Testcontainers
 * RabbitMQ) and real Postgres (Testcontainers), EUD-225. The only mocked collaborators
 * are the two genuine external-system boundaries the flow crosses — {@link IssuerFactory}
 * (QTSP certificate resolution) and {@link DelegatingSigningProvider} (QTSP signing) — plus
 * {@link EmailService}, the titleholder notification side effect. Everything else (broker
 * topology, tenant resolution, idempotency inbox, status list persistence, credential status
 * transition) is real.
 * <p>
 * {@code awaitility} (pulled forward from T27, see the Story commit trail) replaces
 * {@code Thread.sleep} for the asynchronous convergence every scenario here needs: the
 * listener consumes on a background AMQP container thread, never on the test thread.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class RevocationInstructionListenerIT {

    private static final String TENANT_A = "e2e-tenant-a";
    private static final String TENANT_B = "e2e-tenant-b";
    private static final String CREDENTIAL_TYPE = "learcredential.employee.w3c.4";
    private static final String PUBLIC_BASE_URL = "https://issuer.example.com";
    private static final Duration AWAIT_TIMEOUT = Duration.ofSeconds(15);

    private static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>(DockerImageName.parse("postgres:16-alpine"))
                    .withInitScript("db/it/tenant-registry-init.sql");

    private static final RabbitMQContainer RABBITMQ =
            new RabbitMQContainer(DockerImageName.parse("rabbitmq:3.13-management-alpine"));

    static {
        POSTGRES.start();
        RABBITMQ.start();
    }

    @DynamicPropertySource
    static void registerProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.r2dbc.url", () -> "r2dbc:postgresql://" + POSTGRES.getHost()
                + ":" + POSTGRES.getFirstMappedPort() + "/" + POSTGRES.getDatabaseName());
        registry.add("spring.r2dbc.username", POSTGRES::getUsername);
        registry.add("spring.r2dbc.password", POSTGRES::getPassword);
        registry.add("spring.flyway.url", POSTGRES::getJdbcUrl);

        registry.add("issuer.messaging.revocation.enabled", () -> "true");
        // F13: the Testcontainers RabbitMQ image has no TLS listener configured -- same
        // documented escape hatch as the local Docker Compose profile.
        registry.add("issuer.messaging.revocation.allow-insecure-transport", () -> "true");
        registry.add("spring.rabbitmq.host", RABBITMQ::getHost);
        registry.add("spring.rabbitmq.port", RABBITMQ::getAmqpPort);
        registry.add("spring.rabbitmq.username", RABBITMQ::getAdminUsername);
        registry.add("spring.rabbitmq.password", RABBITMQ::getAdminPassword);
    }

    @Autowired
    private RabbitTemplate rabbitTemplate;

    @Autowired
    private IssuancePort issuancePort;

    @Autowired
    private BitstringStatusListProvider statusListProvider;

    @Autowired
    private ObjectMapper objectMapper;

    @LocalServerPort
    private int port;

    @MockitoBean
    private DelegatingSigningProvider delegatingSigningProvider;

    @MockitoBean
    private IssuerFactory issuerFactory;

    @MockitoBean
    private EmailService emailService;

    // ES-03 (T28): the operator's revoke endpoint runs through the real security filter
    // chain and policy rule chain; VerifierService is the only mocked collaborator there
    // too (it is an external system, not part of the safeguards under test) — same choice
    // BitstringStatusListControllerRevokeIT makes.
    @MockitoBean
    private VerifierService verifierService;

    private ECKey signingKey;

    // AC-02 (T30): a mocked AuditService would only prove the workflow *calls* it; only the
    // real Logback appender proves the audit event actually *lands* with the right shape
    // (actor, event, resourceId, no PII) -- same pattern as BitstringStatusListControllerRevokeIT
    // and AuditServiceImplTest.
    private ListAppender<ILoggingEvent> auditAppender;

    @BeforeEach
    void setUp() throws JOSEException {
        purgeQueues();
        attachAuditAppender();
        setUpFakes();
    }

    // Queues/DLQ are singleton beans shared by every test method in this class (cached Spring
    // context): without purging, a DLQ message left by one test pollutes the exact-count
    // assertions of the next.
    private void purgeQueues() {
        rabbitTemplate.execute(channel -> {
            channel.queuePurge(RevocationMessagingConfig.QUEUE_NAME);
            channel.queuePurge(RevocationMessagingConfig.DLQ_NAME);
            return null;
        });
    }

    private void attachAuditAppender() {
        Logger auditLogger = (Logger) LoggerFactory.getLogger("AUDIT");
        auditAppender = new ListAppender<>();
        auditAppender.start();
        auditLogger.addAppender(auditAppender);
    }

    @AfterEach
    void detachAuditAppender() {
        Logger auditLogger = (Logger) LoggerFactory.getLogger("AUDIT");
        auditLogger.detachAppender(auditAppender);
        auditAppender.stop();
    }

    private List<String> auditMessages() {
        return auditAppender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }

    private void setUpFakes() throws JOSEException {
        // Fakes the QTSP: echoes back whatever payload it was asked to sign as a
        // compact-JWT-shaped string, so the id/sub claim the real factories build always
        // matches PUBLIC_BASE_URL — exactly what PersistedStatusListPublicBaseUrlResolver
        // (AD-2) expects to find.
        when(delegatingSigningProvider.sign(any(SigningRequest.class))).thenAnswer(invocation -> {
            SigningRequest request = invocation.getArgument(0);
            return Mono.just(new SigningResult(request.type(), fakeJwt(request.data())));
        });
        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(SimpleIssuer.builder().id("did:elsi:VATES-TEST").build()));
        when(emailService.sendCredentialStatusChangeNotification(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());
        when(verifierService.verifyToken(anyString())).thenReturn(Mono.empty());
        signingKey = new ECKeyGenerator(Curve.P_256).keyID("test-signer").generate();
    }

    private String fakeJwt(String payloadJson) {
        String payloadSegment = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return "header." + payloadSegment + ".signature";
    }

    // ---------------------------------------------------------------- fixtures

    private Issuance seedIssuance(String tenant, CredentialStatusEnum status) {
        Issuance issuance = Issuance.builder()
                .credentialFormat("jwt_vc_json")
                .credentialDataSet("{}")
                .credentialStatus(status)
                .organizationIdentifier("ORG-A")
                .credentialType(CREDENTIAL_TYPE)
                .email("holder@example.com")
                .delivery("email")
                .build();
        return issuancePort.save(issuance)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant))
                .block();
    }

    /** Goes through the real allocation path so the fixture is structurally identical to
     *  what credential issuance produces (real status_list + status_list_index rows, real
     *  signed_credential via the faked QTSP). */
    private void allocateStatusListEntry(String tenant, String issuanceId) {
        statusListProvider.allocateEntry(StatusPurpose.REVOCATION, StatusListFormat.BITSTRING_VC,
                        issuanceId, "seed-token", PUBLIC_BASE_URL)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant))
                .block();
    }

    private CredentialStatusEnum currentStatus(String tenant, UUID issuanceId) {
        return issuancePort.findByIssuanceId(issuanceId)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant))
                .map(Issuance::getCredentialStatus)
                .block();
    }

    private void publish(String tenant, String issuanceId, String messageId, String reason) {
        RevocationInstructionMessage message = new RevocationInstructionMessage(
                "revocation-instruction/v1", messageId, tenant, issuanceId, reason, Instant.now().toString());
        rabbitTemplate.convertAndSend(RevocationMessagingConfig.EXCHANGE_NAME, RevocationMessagingConfig.ROUTING_KEY, message);
    }

    private void publishMalformed(byte[] body) {
        MessageProperties properties = new MessageProperties();
        properties.setContentType("application/json");
        rabbitTemplate.send(RevocationMessagingConfig.EXCHANGE_NAME, RevocationMessagingConfig.ROUTING_KEY,
                new Message(body, properties));
    }

    /** W2 (EUD-225 /verify): consumes (not just counts) the head of the DLQ so a test can
     *  assert on its headers -- e.g. F10's SafeDlqRecoverer classification. Call only after
     *  {@link #awaitDlqMessageCount} has already confirmed the message is there. */
    private Message receiveFromDlq() {
        return rabbitTemplate.receive(RevocationMessagingConfig.DLQ_NAME);
    }

    private long dlqMessageCount() {
        Long count = rabbitTemplate.execute(channel -> channel.messageCount(RevocationMessagingConfig.DLQ_NAME));
        return count == null ? 0L : count;
    }

    private void awaitDlqMessageCount(long expected) {
        Awaitility.await().atMost(AWAIT_TIMEOUT)
                .untilAsserted(() -> assertThat(dlqMessageCount()).isEqualTo(expected));
    }

    // ---------------------------------------------------------------- ES-03 (T28) operator-endpoint helpers

    private static Connection jdbcConnection() throws SQLException {
        return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }

    /** See BitstringStatusListControllerRevokeIT: admin_organization_id is not seeded by
     *  V1__Tenant_schema.sql, so PolicyContextFactory#resolveTenantAdmin would otherwise
     *  throw TenantConfigMissingException for any operator token against this schema. */
    private void seedAdminOrgPlaceholder(String tenant) throws SQLException {
        try (Connection conn = jdbcConnection(); Statement stmt = conn.createStatement()) {
            stmt.execute(("""
                    INSERT INTO "%s%s".tenant_config (config_key, config_value)
                    VALUES ('admin_organization_id', 'ADMIN-ORG-NONE')
                    ON CONFLICT (config_key) DO NOTHING
                    """).formatted(tenant, SCHEMA_SUFFIX));
        }
    }

    private WebTestClient webTestClient() {
        return WebTestClient.bindToServer()
                .baseUrl("http://localhost:" + port)
                .responseTimeout(Duration.ofSeconds(10))
                .build();
    }

    private String operatorToken(String orgId, String tenant, List<Map<String, Object>> powers) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("http://localhost:" + port + "/verifier")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 3_600_000L))
                .claim("credential_type", CREDENTIAL_TYPE)
                .claim("mandator", Map.of("organizationIdentifier", orgId))
                .claim("power", powers)
                .claim("tenant", tenant)
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(signingKey.getKeyID()).build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(signingKey));
        return jwt.serialize();
    }

    private static Map<String, Object> executePower(String domain) {
        return Map.of("function", "Onboarding", "action", "Execute", "domain", domain, "type", "organization");
    }

    private WebTestClient.ResponseSpec operatorRevoke(String tenant, String bearerToken, String issuanceId) {
        return webTestClient().post()
                .uri("/issuer/w3c/v1/credentials/status/revoke")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + bearerToken)
                .header(X_TENANT_HEADER, tenant)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new RevokeCredentialRequest(issuanceId, null))
                .exchange();
    }

    // ---------------------------------------------------------------- NFR-S-225-01 (T31): latency gate

    /**
     * Two-tier latency requirement (replanteado en el pase --update): the product objective
     * is p95 consumption-to-published-status &lt; 3s, but asserting that here would measure
     * Testcontainers cold-start and shared-runner CPU contention, not this Story's code --
     * see acceptance-criteria.md §5.1 for why that gate is deliberately not enforced in CI.
     * What <i>is</i> enforced here is a deliberately generous, non-flaky anti-regression
     * ceiling: &lt; 10s wall-clock per message, which only catches a pathological regression
     * (an oversized block() timeout, an unintended extra retry on the happy path). The
     * product objective itself is measured without a gate in the local-stack smoke (T18,
     * recorded in quality-report.md).
     */
    @Test
    void nfrS22501_happyPathCompletesWellWithinTheAntiRegressionCeiling() {
        Issuance issuance = seedIssuance(TENANT_A, CredentialStatusEnum.VALID);
        String issuanceId = issuance.getIssuanceId().toString();
        allocateStatusListEntry(TENANT_A, issuanceId);

        Instant startedAt = Instant.now();
        publish(TENANT_A, issuanceId, UUID.randomUUID().toString(), null);

        Awaitility.await().atMost(Duration.ofSeconds(10)).untilAsserted(() ->
                assertThat(currentStatus(TENANT_A, issuance.getIssuanceId())).isEqualTo(CredentialStatusEnum.REVOKED));

        assertThat(Duration.between(startedAt, Instant.now())).isLessThan(Duration.ofSeconds(10));
    }

    // ---------------------------------------------------------------- AC-01: happy path

    @Test
    void validInstructionOnValidCredential_revokesAndAcks() {
        Issuance issuance = seedIssuance(TENANT_A, CredentialStatusEnum.VALID);
        String issuanceId = issuance.getIssuanceId().toString();
        allocateStatusListEntry(TENANT_A, issuanceId);

        publish(TENANT_A, issuanceId, UUID.randomUUID().toString(), "Baja voluntaria");

        Awaitility.await().atMost(AWAIT_TIMEOUT).untilAsserted(() ->
                assertThat(currentStatus(TENANT_A, issuance.getIssuanceId())).isEqualTo(CredentialStatusEnum.REVOKED));

        awaitDlqMessageCount(0);
        verify(emailService, timeout(AWAIT_TIMEOUT.toMillis()))
                .sendCredentialStatusChangeNotification(anyString(), anyString(), anyString(), anyString());

        // AC-02 (T30): the real AUDIT-logger events, not a mocked AuditService call -- proves
        // the event actually lands with actor=system:revocation-instruction (never "unknown"),
        // the right resourceId, and no titleholder PII (email/name), not just that the workflow
        // invoked the service.
        Awaitility.await().atMost(AWAIT_TIMEOUT).untilAsserted(() -> {
            List<String> messages = auditMessages();
            assertThat(messages).anyMatch(m ->
                    m.contains("event=credential.revoke.attempted")
                            && m.contains("userId=system:revocation-instruction")
                            && m.contains("resourceId=" + issuanceId));
            assertThat(messages).anyMatch(m ->
                    m.contains("event=credential.revoked")
                            && m.contains("outcome=success")
                            && m.contains("userId=system:revocation-instruction")
                            && m.contains("resourceId=" + issuanceId)
                            && m.contains("reason=Baja voluntaria"));
        });
        assertThat(auditMessages()).noneMatch(m -> m.contains("userId=unknown") || m.contains("holder@example.com"));
    }

    // ---------------------------------------------------------------- AC-06: not revocable -> no-op, ack, no DLQ

    @Test
    void instructionOnAlreadyRevokedCredential_isSilentNoopWithAck() {
        Issuance issuance = seedIssuance(TENANT_A, CredentialStatusEnum.REVOKED);
        String issuanceId = issuance.getIssuanceId().toString();
        allocateStatusListEntry(TENANT_A, issuanceId);

        publish(TENANT_A, issuanceId, UUID.randomUUID().toString(), null);

        // No state to converge to (already REVOKED); assert absence of a DLQ side effect
        // after giving the consumer time to process.
        awaitDlqMessageCount(0);
        assertThat(currentStatus(TENANT_A, issuance.getIssuanceId())).isEqualTo(CredentialStatusEnum.REVOKED);
    }

    // ---------------------------------------------------------------- AC-07 / ES-01 / ES-02: permanent errors -> DLQ

    @Test
    void malformedPayload_routesToDlqWithoutBlockingSubsequentMessages() {
        publishMalformed("{ this is not valid json".getBytes(StandardCharsets.UTF_8));
        awaitDlqMessageCount(1);

        // Prove the consumer is still alive: a well-formed instruction right after still works.
        Issuance issuance = seedIssuance(TENANT_A, CredentialStatusEnum.VALID);
        String issuanceId = issuance.getIssuanceId().toString();
        allocateStatusListEntry(TENANT_A, issuanceId);
        publish(TENANT_A, issuanceId, UUID.randomUUID().toString(), null);

        Awaitility.await().atMost(AWAIT_TIMEOUT).untilAsserted(() ->
                assertThat(currentStatus(TENANT_A, issuance.getIssuanceId())).isEqualTo(CredentialStatusEnum.REVOKED));
    }

    @Test
    void unknownJsonField_isIgnoredAndProcessedNormally() {
        // B-EC06 (EUD-225 /verify): @JsonIgnoreProperties(ignoreUnknown = true) on
        // RevocationInstructionMessage is the right mechanism (EC-06, forward compatibility
        // with a later contract version), but nothing previously deserialized a raw JSON
        // payload with a genuinely unknown field through the *real* ObjectMapper end to end
        // -- the mapper test builds the record directly in Java, and every other publish()
        // in this class sends an already-constructed Java object (Jackson2JsonMessageConverter
        // serializes it, never exercising an extra key on the way back in). This publishes
        // raw bytes with a field no version of the contract has ever declared.
        Issuance issuance = seedIssuance(TENANT_A, CredentialStatusEnum.VALID);
        String issuanceId = issuance.getIssuanceId().toString();
        allocateStatusListEntry(TENANT_A, issuanceId);
        String messageId = UUID.randomUUID().toString();

        String rawJsonWithUnknownField = """
                {
                  "type": "revocation-instruction/v1",
                  "messageId": "%s",
                  "tenantId": "%s",
                  "issuanceId": "%s",
                  "reason": null,
                  "issuedAt": "%s",
                  "futureFieldFromANewerContractVersion": "must be ignored, not rejected"
                }
                """.formatted(messageId, TENANT_A, issuanceId, Instant.now());
        publishMalformed(rawJsonWithUnknownField.getBytes(StandardCharsets.UTF_8));

        Awaitility.await().atMost(AWAIT_TIMEOUT).untilAsserted(() ->
                assertThat(currentStatus(TENANT_A, issuance.getIssuanceId())).isEqualTo(CredentialStatusEnum.REVOKED));
        awaitDlqMessageCount(0);
    }

    @Test
    void nonExistentIssuance_routesToDlqWithoutStateChange() {
        String unknownIssuanceId = UUID.randomUUID().toString();
        publish(TENANT_A, unknownIssuanceId, UUID.randomUUID().toString(), null);

        awaitDlqMessageCount(1);
    }

    @Test
    void unknownTenant_routesToDlqWithoutStateChange() {
        Issuance issuance = seedIssuance(TENANT_A, CredentialStatusEnum.VALID);
        String issuanceId = issuance.getIssuanceId().toString();
        allocateStatusListEntry(TENANT_A, issuanceId);

        publish("no-such-tenant", issuanceId, UUID.randomUUID().toString(), null);

        awaitDlqMessageCount(1);
        assertThat(currentStatus(TENANT_A, issuance.getIssuanceId())).isEqualTo(CredentialStatusEnum.VALID);
    }

    // ---------------------------------------------------------------- AC-13: default mode never infers a tenant

    @Test
    void missingTenantId_inDefaultModeWithNoBindingConfigured_routesToDlqWithoutStateChange() {
        // Regression guard: this context declares no issuer.messaging.revocation.tenant-binding
        // (the default, multi-tenant mode) -- exactly today's behaviour, which AD-8's
        // single-tenant mode (tested separately, RevocationInstructionSingleTenantIT) must
        // never degrade. A message with no tenantId field at all must still go straight to
        // the DLQ, never attributed to any tenant (not the first in the registry, not the
        // only one seeded).
        Issuance issuance = seedIssuance(TENANT_A, CredentialStatusEnum.VALID);
        String issuanceId = issuance.getIssuanceId().toString();
        allocateStatusListEntry(TENANT_A, issuanceId);

        publish(null, issuanceId, UUID.randomUUID().toString(), null);

        awaitDlqMessageCount(1);
        assertThat(currentStatus(TENANT_A, issuance.getIssuanceId())).isEqualTo(CredentialStatusEnum.VALID);
    }

    // ---------------------------------------------------------------- AC-08: tenant isolation

    @Test
    void instructionDeclaringTenantA_onlyAffectsTenantACredential() {
        Issuance issuanceA = seedIssuance(TENANT_A, CredentialStatusEnum.VALID);
        Issuance issuanceB = seedIssuance(TENANT_B, CredentialStatusEnum.VALID);
        allocateStatusListEntry(TENANT_A, issuanceA.getIssuanceId().toString());
        allocateStatusListEntry(TENANT_B, issuanceB.getIssuanceId().toString());

        publish(TENANT_A, issuanceA.getIssuanceId().toString(), UUID.randomUUID().toString(), null);

        Awaitility.await().atMost(AWAIT_TIMEOUT).untilAsserted(() ->
                assertThat(currentStatus(TENANT_A, issuanceA.getIssuanceId())).isEqualTo(CredentialStatusEnum.REVOKED));

        assertThat(currentStatus(TENANT_B, issuanceB.getIssuanceId())).isEqualTo(CredentialStatusEnum.VALID);
    }

    @Test
    void instructionDeclaringTenantAWithTenantBIssuanceId_isTreatedAsNotFound() {
        Issuance issuanceB = seedIssuance(TENANT_B, CredentialStatusEnum.VALID);
        allocateStatusListEntry(TENANT_B, issuanceB.getIssuanceId().toString());

        publish(TENANT_A, issuanceB.getIssuanceId().toString(), UUID.randomUUID().toString(), null);

        awaitDlqMessageCount(1);
        assertThat(currentStatus(TENANT_B, issuanceB.getIssuanceId())).isEqualTo(CredentialStatusEnum.VALID);
    }

    // ---------------------------------------------------------------- AC-09 / ES-04: transient failure

    @Test
    void transientSigningFailure_retriesThenRecovers() {
        Issuance issuance = seedIssuance(TENANT_A, CredentialStatusEnum.VALID);
        String issuanceId = issuance.getIssuanceId().toString();
        allocateStatusListEntry(TENANT_A, issuanceId);

        AtomicInteger attempts = new AtomicInteger();
        when(delegatingSigningProvider.sign(any(SigningRequest.class))).thenAnswer(invocation -> {
            if (attempts.getAndIncrement() == 0) {
                // First call after allocateStatusListEntry() already succeeded once (seeding);
                // this stub replaces the setUp() stub, so the very next sign() call (the
                // re-signing during revoke) fails once, then recovers.
                return Mono.error(new es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException(
                        "QTSP transiently unavailable", new RuntimeException("timeout")));
            }
            SigningRequest request = invocation.getArgument(0);
            return Mono.just(new SigningResult(request.type(), fakeJwt(request.data())));
        });

        publish(TENANT_A, issuanceId, UUID.randomUUID().toString(), null);

        Awaitility.await().atMost(AWAIT_TIMEOUT).untilAsserted(() ->
                assertThat(currentStatus(TENANT_A, issuance.getIssuanceId())).isEqualTo(CredentialStatusEnum.REVOKED));
        awaitDlqMessageCount(0);
    }

    @Test
    void persistentSigningFailure_exhaustsRetriesAndRoutesToDlq() {
        Issuance issuance = seedIssuance(TENANT_A, CredentialStatusEnum.VALID);
        String issuanceId = issuance.getIssuanceId().toString();
        allocateStatusListEntry(TENANT_A, issuanceId);
        // W2: isolate the retry count assertion below from allocateStatusListEntry's own
        // (successful) sign() call during list creation -- only calls from here on are the
        // revoke path's own retry attempts.
        clearInvocations(delegatingSigningProvider);

        String internalDetail = "QTSP permanently unavailable at https://qtsp-internal.example:8443/sign";
        when(delegatingSigningProvider.sign(any(SigningRequest.class)))
                .thenReturn(Mono.error(new es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException(
                        internalDetail, new RuntimeException("down"))));

        publish(TENANT_A, issuanceId, UUID.randomUUID().toString(), null);

        awaitDlqMessageCount(1);
        assertThat(currentStatus(TENANT_A, issuance.getIssuanceId())).isEqualTo(CredentialStatusEnum.VALID);

        // NFR-S-225-02: exactly RevocationMessagingConfig.RETRY_MAX_ATTEMPTS (3) attempts
        // before giving up on a retryable failure.
        verify(delegatingSigningProvider, times(3)).sign(any(SigningRequest.class));

        // F10/NFR-S-225-03: the DLQ message carries a stable, sanitized error classification
        // (RevocationMessagingConfig.SafeDlqRecoverer), never the raw exception text/stack
        // trace that could otherwise cross into a broker plausibly operated by the client.
        Message dlqMessage = receiveFromDlq();
        assertThat(dlqMessage).isNotNull();
        Map<String, Object> headers = dlqMessage.getMessageProperties().getHeaders();
        assertThat(headers).containsKey(RepublishMessageRecoverer.X_EXCEPTION_MESSAGE);
        assertThat(headers).doesNotContainKey(RepublishMessageRecoverer.X_EXCEPTION_STACKTRACE);
        assertThat(headers.get(RepublishMessageRecoverer.X_EXCEPTION_MESSAGE).toString())
                .doesNotContain(internalDetail)
                .doesNotContain("qtsp-internal.example");
    }

    // ---------------------------------------------------------------- AC-05: redelivery of an already-processed message

    @Test
    void redeliveryOfAlreadyProcessedMessage_hasNoSecondEffect() {
        Issuance issuance = seedIssuance(TENANT_A, CredentialStatusEnum.VALID);
        String issuanceId = issuance.getIssuanceId().toString();
        allocateStatusListEntry(TENANT_A, issuanceId);
        String messageId = UUID.randomUUID().toString();

        publish(TENANT_A, issuanceId, messageId, null);

        Awaitility.await().atMost(AWAIT_TIMEOUT).untilAsserted(() ->
                assertThat(currentStatus(TENANT_A, issuance.getIssuanceId())).isEqualTo(CredentialStatusEnum.REVOKED));

        // Redeliver the exact same messageId.
        publish(TENANT_A, issuanceId, messageId, null);

        // Grace window past the point where a duplicate effect would already be visible.
        Awaitility.await().pollDelay(Duration.ofSeconds(3)).atMost(AWAIT_TIMEOUT).untilAsserted(() -> {
            assertThat(currentStatus(TENANT_A, issuance.getIssuanceId())).isEqualTo(CredentialStatusEnum.REVOKED);
            verify(emailService, times(1))
                    .sendCredentialStatusChangeNotification(anyString(), anyString(), anyString(), anyString());
        });
        awaitDlqMessageCount(0);
    }

    // ---------------------------------------------------------------- EC-05: two different messageIds, same credential

    @Test
    void twoDistinctInstructionsOnSameCredential_secondIsNoop() {
        Issuance issuance = seedIssuance(TENANT_A, CredentialStatusEnum.VALID);
        String issuanceId = issuance.getIssuanceId().toString();
        allocateStatusListEntry(TENANT_A, issuanceId);

        publish(TENANT_A, issuanceId, UUID.randomUUID().toString(), null);
        Awaitility.await().atMost(AWAIT_TIMEOUT).untilAsserted(() ->
                assertThat(currentStatus(TENANT_A, issuance.getIssuanceId())).isEqualTo(CredentialStatusEnum.REVOKED));

        publish(TENANT_A, issuanceId, UUID.randomUUID().toString(), null);

        awaitDlqMessageCount(0);
        assertThat(currentStatus(TENANT_A, issuance.getIssuanceId())).isEqualTo(CredentialStatusEnum.REVOKED);
    }

    // ---------------------------------------------------------------- ES-03 (T28, promoted): real race, queue vs operator

    /**
     * The queue-triggered instruction and an operator's HTTP revoke fire concurrently on the
     * same credential. Whoever wins the race, the outcome must be: revoked exactly once, the
     * status list bit written once, the titleholder emailed once, exactly one
     * {@code credential.revoked} audit event, and the instruction acked — never routed to the
     * DLQ. This depends on the *real* optimistic lock on {@code status_list} (RC-2) and the
     * *real* optimistic lock on {@code issuance.version} in
     * {@code updateIssuanceStatusToRevoked} (SD-04 fix, see spec-deltas.md) — a unit test
     * with mocks can only prove the exception gets translated, not that the race actually
     * resolves this way against Postgres. This test originally exposed SD-04 (intermittent
     * double-revoke / double-email under full-suite contention before the fix); it is kept
     * as the regression guard for that fix, not just as a new-feature test.
     */
    @Test
    void raceQueueVsOperatorRevoke_revokesExactlyOnceRegardlessOfWinner() throws Exception {
        Issuance issuance = seedIssuance(TENANT_A, CredentialStatusEnum.VALID);
        String issuanceId = issuance.getIssuanceId().toString();
        allocateStatusListEntry(TENANT_A, issuanceId);
        seedAdminOrgPlaceholder(TENANT_A);
        String bearer = operatorToken("ORG-A", TENANT_A, List.of(executePower(TENANT_A)));

        CountDownLatch startLine = new CountDownLatch(2);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<?> queueRunner = executor.submit(() -> {
                startLine.countDown();
                awaitStartLine(startLine);
                publish(TENANT_A, issuanceId, UUID.randomUUID().toString(), null);
            });
            Future<?> operatorRunner = executor.submit(() -> {
                startLine.countDown();
                awaitStartLine(startLine);
                operatorRevoke(TENANT_A, bearer, issuanceId).expectStatus().value(status ->
                        assertThat(status).isIn(200, 204, 409));
            });
            queueRunner.get(20, TimeUnit.SECONDS);
            operatorRunner.get(20, TimeUnit.SECONDS);
        } finally {
            executor.shutdown();
        }

        Awaitility.await().atMost(AWAIT_TIMEOUT).untilAsserted(() ->
                assertThat(currentStatus(TENANT_A, issuance.getIssuanceId())).isEqualTo(CredentialStatusEnum.REVOKED));

        // Grace window past the point where a duplicate effect (second email, second audit
        // event) would already be visible if the race were mishandled.
        Awaitility.await().pollDelay(Duration.ofSeconds(3)).atMost(AWAIT_TIMEOUT).untilAsserted(() -> {
            assertThat(currentStatus(TENANT_A, issuance.getIssuanceId())).isEqualTo(CredentialStatusEnum.REVOKED);
            verify(emailService, times(1))
                    .sendCredentialStatusChangeNotification(anyString(), anyString(), anyString(), anyString());
            // SD-04: exactly one credential.revoked/success audit event for this issuanceId,
            // regardless of which path won -- the loser's InvalidCredentialStatusTransitionException
            // (reconcileConcurrentRevoke) routes to a failure/skip event, never a second success.
            assertThat(auditMessages().stream()
                    .filter(m -> m.contains("event=credential.revoked")
                            && m.contains("outcome=success")
                            && m.contains("resourceId=" + issuanceId))
                    .count())
                    .isEqualTo(1);
        });
        awaitDlqMessageCount(0);
    }

    private static void awaitStartLine(CountDownLatch startLine) {
        try {
            startLine.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
