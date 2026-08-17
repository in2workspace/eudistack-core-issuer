package es.in2.issuer.backend.statuslist.infrastructure.messaging;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.credential.SimpleIssuer;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.infrastructure.repository.IssuanceRepository;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.infrastructure.adapter.DelegatingSigningProvider;
import es.in2.issuer.backend.statuslist.domain.model.StatusListFormat;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.RabbitMQContainer;
import org.testcontainers.utility.DockerImageName;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * AD-8 single-tenant deployment mode, bound to a <b>real</b> tenant
 * ({@code issuer.messaging.revocation.tenant-binding=e2e-tenant-a}): AC-11 (instruction
 * without {@code tenantId} attributed to the bound tenant) and AC-12 (discordant
 * {@code tenantId} rejected to the DLQ). EC-07 (bound to a tenant absent from the registry)
 * needs a different property value and therefore its own Spring context — it lives in
 * {@link RevocationInstructionSingleTenantUnresolvableIT} in this same file rather than as
 * a {@code @Nested} class: two {@code @Nested @SpringBootTest} siblings with distinct
 * {@code @DynamicPropertySource} values were found (the hard way) to risk Spring Test's
 * context-caching key not fully distinguishing them, leaking one nested class's broker
 * connection into the other's context.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class RevocationInstructionSingleTenantIT {

    private static final String BOUND_TENANT = "e2e-tenant-a";
    private static final String OTHER_TENANT = "e2e-tenant-b";

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
        registry.add("issuer.messaging.revocation.tenant-binding", () -> BOUND_TENANT);
        registry.add("spring.rabbitmq.host", RABBITMQ::getHost);
        registry.add("spring.rabbitmq.port", RABBITMQ::getAmqpPort);
        registry.add("spring.rabbitmq.username", RABBITMQ::getAdminUsername);
        registry.add("spring.rabbitmq.password", RABBITMQ::getAdminPassword);
    }

    @Autowired
    private RabbitTemplate rabbitTemplate;

    @Autowired
    private IssuanceRepository issuanceRepository;

    @Autowired
    private BitstringStatusListProvider statusListProvider;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private DelegatingSigningProvider delegatingSigningProvider;

    @MockitoBean
    private IssuerFactory issuerFactory;

    @MockitoBean
    private EmailService emailService;

    private ListAppender<ILoggingEvent> auditAppender;

    private static final String CREDENTIAL_TYPE = "learcredential.employee.w3c.4";
    private static final String PUBLIC_BASE_URL = "https://issuer.example.com";
    private static final Duration AWAIT_TIMEOUT = Duration.ofSeconds(15);

    @BeforeEach
    void setUpFakes() {
        when(delegatingSigningProvider.sign(any(SigningRequest.class))).thenAnswer(invocation -> {
            SigningRequest request = invocation.getArgument(0);
            return Mono.just(new SigningResult(request.type(), fakeJwt(request.data())));
        });
        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(SimpleIssuer.builder().id("did:elsi:VATES-TEST").build()));
        when(emailService.sendCredentialStatusChangeNotification(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());
    }

    @BeforeEach
    void purgeQueues() {
        rabbitTemplate.execute(channel -> {
            channel.queuePurge(RevocationMessagingConfig.QUEUE_NAME);
            channel.queuePurge(RevocationMessagingConfig.DLQ_NAME);
            return null;
        });
    }

    @BeforeEach
    void attachAuditAppender() {
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

    private static String fakeJwt(String payloadJson) {
        String payloadSegment = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return "header." + payloadSegment + ".signature";
    }

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
        return issuanceRepository.save(issuance)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant))
                .block();
    }

    private void allocateStatusListEntry(String tenant, String issuanceId) {
        statusListProvider.allocateEntry(StatusPurpose.REVOCATION, StatusListFormat.BITSTRING_VC,
                        issuanceId, "seed-token", PUBLIC_BASE_URL)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant))
                .block();
    }

    private CredentialStatusEnum currentStatus(String tenant, UUID issuanceId) {
        return issuanceRepository.findByIssuanceId(issuanceId)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant))
                .map(Issuance::getCredentialStatus)
                .block();
    }

    /** {@code tenantId == null} publishes a message with no tenant field at all (AC-11). */
    private void publish(String tenantId, String issuanceId, String messageId, String reason) {
        RevocationInstructionMessage message = new RevocationInstructionMessage(
                "revocation-instruction/v1", messageId, tenantId, issuanceId, reason, Instant.now().toString());
        rabbitTemplate.convertAndSend(RevocationMessagingConfig.EXCHANGE_NAME, RevocationMessagingConfig.ROUTING_KEY, message);
    }

    private long dlqMessageCount() {
        Long count = rabbitTemplate.execute(channel -> channel.messageCount(RevocationMessagingConfig.DLQ_NAME));
        return count == null ? 0L : count;
    }

    private void awaitDlqMessageCount(long expected) {
        Awaitility.await().atMost(AWAIT_TIMEOUT)
                .untilAsserted(() -> assertThat(dlqMessageCount()).isEqualTo(expected));
    }

    @Test
    void ac11_instructionWithoutTenantId_isAttributedToTheBoundTenant() {
        Issuance issuance = seedIssuance(BOUND_TENANT, CredentialStatusEnum.VALID);
        String issuanceId = issuance.getIssuanceId().toString();
        allocateStatusListEntry(BOUND_TENANT, issuanceId);

        publish(null, issuanceId, UUID.randomUUID().toString(), "Baja voluntaria");

        Awaitility.await().atMost(AWAIT_TIMEOUT).untilAsserted(() ->
                assertThat(currentStatus(BOUND_TENANT, issuance.getIssuanceId())).isEqualTo(CredentialStatusEnum.REVOKED));
        awaitDlqMessageCount(0);

        // The success audit write is the last step of the same reactive chain, after the
        // DB commit and the (mocked) email notification -- poll rather than assert once.
        Awaitility.await().atMost(AWAIT_TIMEOUT).untilAsserted(() ->
                assertThat(auditMessages()).anyMatch(m ->
                        m.contains("event=credential.revoked") && m.contains("tenantSource=deployment")));
    }

    @Test
    void ac12_instructionWithDiscordantTenantId_isRejectedToDlqWithoutStateChange() {
        Issuance boundIssuance = seedIssuance(BOUND_TENANT, CredentialStatusEnum.VALID);
        Issuance otherIssuance = seedIssuance(OTHER_TENANT, CredentialStatusEnum.VALID);
        allocateStatusListEntry(BOUND_TENANT, boundIssuance.getIssuanceId().toString());
        allocateStatusListEntry(OTHER_TENANT, otherIssuance.getIssuanceId().toString());

        // Message declares OTHER_TENANT while this deployment is bound to BOUND_TENANT.
        publish(OTHER_TENANT, otherIssuance.getIssuanceId().toString(), UUID.randomUUID().toString(), null);

        awaitDlqMessageCount(1);
        assertThat(currentStatus(BOUND_TENANT, boundIssuance.getIssuanceId())).isEqualTo(CredentialStatusEnum.VALID);
        assertThat(currentStatus(OTHER_TENANT, otherIssuance.getIssuanceId())).isEqualTo(CredentialStatusEnum.VALID);

        assertThat(auditMessages()).anyMatch(m ->
                m.contains("event=credential.revoke.failed") && m.contains("errorType=tenant_binding_mismatch"));
    }
}

/**
 * AD-8, EC-07: the deployment declares a tenant that does not exist in {@code tenant_registry}.
 * A separate top-level class (not {@code @Nested}, see the Javadoc on
 * {@link RevocationInstructionSingleTenantIT}) so its distinct
 * {@code tenant-binding} value gets its own, unambiguous Spring context.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class RevocationInstructionSingleTenantUnresolvableIT {

    private static final String UNRESOLVABLE_TENANT = "ghost-tenant";

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
        registry.add("issuer.messaging.revocation.tenant-binding", () -> UNRESOLVABLE_TENANT);
        registry.add("spring.rabbitmq.host", RABBITMQ::getHost);
        registry.add("spring.rabbitmq.port", RABBITMQ::getAmqpPort);
        registry.add("spring.rabbitmq.username", RABBITMQ::getAdminUsername);
        registry.add("spring.rabbitmq.password", RABBITMQ::getAdminPassword);
    }

    @Autowired
    private RabbitTemplate rabbitTemplate;

    @MockitoBean
    private DelegatingSigningProvider delegatingSigningProvider;

    @MockitoBean
    private IssuerFactory issuerFactory;

    @MockitoBean
    private EmailService emailService;

    private static final Duration AWAIT_TIMEOUT = Duration.ofSeconds(15);

    private void publish(String issuanceId, String messageId) {
        RevocationInstructionMessage message = new RevocationInstructionMessage(
                "revocation-instruction/v1", messageId, null, issuanceId, null, Instant.now().toString());
        rabbitTemplate.convertAndSend(RevocationMessagingConfig.EXCHANGE_NAME, RevocationMessagingConfig.ROUTING_KEY, message);
    }

    private long dlqMessageCount() {
        Long count = rabbitTemplate.execute(channel -> channel.messageCount(RevocationMessagingConfig.DLQ_NAME));
        return count == null ? 0L : count;
    }

    @Test
    void ec07_startsSuccessfully_thenRoutesToDlqOnFirstMessage() {
        // Reaching this test method at all IS the "starts successfully despite a tenant
        // binding that does not exist in the registry" assertion: a failed context refresh
        // would fail every test in this class, not just this one.
        publish(UUID.randomUUID().toString(), UUID.randomUUID().toString());

        Awaitility.await().atMost(AWAIT_TIMEOUT)
                .untilAsserted(() -> assertThat(dlqMessageCount()).isEqualTo(1));
    }
}
