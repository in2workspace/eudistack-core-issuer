package es.in2.issuer.backend.signing.infrastructure.onboarding.audit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingRejectedException;
import es.in2.issuer.backend.signing.domain.onboarding.RejectionReason;
import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged;
import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged.Operation;
import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged.Result;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.NewOwnKeyConfiguration;
import es.in2.issuer.backend.signing.infrastructure.onboarding.JdbcOwnKeyStore;
import es.in2.issuer.backend.signing.infrastructure.onboarding.OnboardingTestDatabase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import static es.in2.issuer.backend.signing.infrastructure.onboarding.OnboardingTestDatabase.execute;
import static es.in2.issuer.backend.signing.infrastructure.onboarding.OnboardingTestDatabase.query;
import static es.in2.issuer.backend.signing.infrastructure.onboarding.OnboardingTestDatabase.scalar;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The outbox audit sink with the real starter (built from the tag v0.1.0), on a real Postgres: the event is staged
 * in {@code public.audit_outbox} in the transaction of the configuration change, and only then. Compiled and run
 * only with {@code -PauditStarter}.
 */
class OutboxAuditSinkIT {

    private static final String CALLER = "arn:aws:sts::000000000000:assumed-role/own-key-operation/jane";
    private static final String KEY_ARN = "arn:aws:kms:eu-west-1:000000000000:key/secret-looking-id";
    private static final byte[] SPKI = HexFormat.of().parseHex("11".repeat(32));
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private OutboxAuditSinkFactory.OutboxHandle handle;
    private JdbcOwnKeyStore store;

    @BeforeEach
    void startTheOutbox() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource(OnboardingTestDatabase.POSTGRES.getJdbcUrl(),
                OnboardingTestDatabase.POSTGRES.getUsername(), OnboardingTestDatabase.POSTGRES.getPassword());
        handle = (OutboxAuditSinkFactory.OutboxHandle) new OutboxAuditSinkFactory().open(dataSource);
        OnboardingTestDatabase.reset();
        execute("TRUNCATE public.audit_outbox");
        store = new JdbcOwnKeyStore(dataSource, handle.sink());
    }

    @AfterEach
    void stopTheOutbox() {
        handle.close();
    }

    private static SigningConfigurationChanged success(String tenant) {
        return new SigningConfigurationChanged(tenant, Operation.CREATE, Result.SUCCESS, null, null,
                SigningModality.OWN_KEY, "ab".repeat(32), CALLER, Duration.ofMillis(5),
                Instant.parse("2026-10-27T12:00:00Z"), "op-1");
    }

    private void changeConfiguration(java.util.function.Consumer<es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.ConfigurationTransaction> after) {
        store.inTransaction(tx -> {
            var id = tx.activateOwnKey("cgcom", new NewOwnKeyConfiguration(KEY_ARN, List.of("QUJD")), CALLER);
            tx.reserveSpki(SPKI, "cgcom", id);
            tx.stage(success("cgcom"));
            after.accept(tx);
            return id;
        });
    }

    private JsonNode onlyOutboxPayload() throws Exception {
        assertThat(scalar("SELECT count(*) FROM public.audit_outbox")).isEqualTo(1L);
        return MAPPER.readTree((String) scalar("SELECT payload::text FROM public.audit_outbox"));
    }

    @Test
    void stage_inTheBusinessTransaction_landsInTheOutboxWithTheChange() throws Exception {
        changeConfiguration(tx -> { });

        assertThat(scalar("SELECT count(*) FROM cgcom_issuer.tenant_signing_config")).isEqualTo(1L);
        assertThat(query("SELECT tenant, event_type, status FROM public.audit_outbox"))
                .singleElement().isEqualTo(List.of("cgcom", "SigningConfigurationChanged", "PENDING"));
        JsonNode payload = onlyOutboxPayload();
        assertThat(payload.toString()).contains("\"ConfigureSigning\"", "\"Success\"", "\"Create\"", "\"OwnKey\"",
                "sha256:" + "ab".repeat(32), CALLER, "signing-configuration:cgcom");
    }

    @Test
    void stage_whenTheChangeRollsBack_isNotInTheOutbox() {
        execute("INSERT INTO public.signing_spki_reservation (public_key_spki_sha256, tenant_id, "
                + "signing_configuration_id) VALUES (?, 'kpmg', gen_random_uuid())", (Object) SPKI);

        assertThatThrownBy(() -> store.inTransaction(tx -> {
            var id = tx.activateOwnKey("cgcom", new NewOwnKeyConfiguration(KEY_ARN, List.of("QUJD")), CALLER);
            tx.stage(success("cgcom"));
            tx.reserveSpki(SPKI, "cgcom", id);
            return id;
        })).isInstanceOf(OnboardingRejectedException.class);

        assertThat(scalar("SELECT count(*) FROM public.audit_outbox")).isEqualTo(0L);
        assertThat(scalar("SELECT count(*) FROM cgcom_issuer.tenant_signing_config")).isEqualTo(0L);
    }

    @Test
    void stage_whenALaterStepFails_isNotInTheOutboxEither() {
        assertThatThrownBy(() -> changeConfiguration(tx -> {
            throw new IllegalStateException("fails after staging");
        })).hasMessage("fails after staging");

        assertThat(scalar("SELECT count(*) FROM public.audit_outbox")).isEqualTo(0L);
        assertThat(scalar("SELECT count(*) FROM cgcom_issuer.tenant_signing_config")).isEqualTo(0L);
    }

    @Test
    void recordInOwnTransaction_rejectedOnboarding_isInTheOutboxWithoutTouchingTheConfiguration() throws Exception {
        store.recordInOwnTransaction(new SigningConfigurationChanged("cgcom", Operation.CREATE, Result.DENIED,
                RejectionReason.KEY_IN_USE, null, SigningModality.OWN_KEY, "ab".repeat(32), CALLER, Duration.ZERO,
                Instant.parse("2026-10-27T12:00:00Z"), null));

        assertThat(scalar("SELECT count(*) FROM cgcom_issuer.tenant_signing_config")).isEqualTo(0L);
        assertThat(onlyOutboxPayload().toString()).contains("\"Denied\"", "\"KeyInUse\"", "\"cgcom\"");
    }

    @Test
    void recordInOwnTransaction_retireFailure_isInTheOutboxWithAFailureReasonAndNoModalityOrCertificate() throws Exception {
        store.recordInOwnTransaction(SigningConfigurationChanged.retire("cgcom", Result.FAILURE, RejectionReason.PROVIDER_UNAVAILABLE, CALLER,
                Duration.ZERO, Instant.parse("2026-10-27T12:00:00Z"), "00000000-0000-0000-0000-000000000001"));

        JsonNode payload = onlyOutboxPayload();
        assertThat(payload.toString()).contains("\"Failure\"", "\"ProviderUnavailable\"", "\"Retire\"");
        List<String> details = new ArrayList<>();
        payload.path("details").fieldNames().forEachRemaining(details::add);
        assertThat(details).containsExactlyInAnyOrder("operation", "previous_modality");
    }

    @Test
    void recordInOwnTransaction_unknownTenant_isStagedWithTheTenantAsGiven() {
        store.recordInOwnTransaction(new SigningConfigurationChanged("nobody", Operation.CREATE, Result.DENIED,
                RejectionReason.POLICY_DENIED, null, SigningModality.OWN_KEY, null, CALLER, Duration.ZERO,
                Instant.parse("2026-10-27T12:00:00Z"), null));

        assertThat(scalar("SELECT tenant FROM public.audit_outbox")).isEqualTo("nobody");
    }

    @Test
    void payload_hasOnlyTheCatalogueDetailsAndNoSecretNorKeyReference() throws Exception {
        changeConfiguration(tx -> { });

        JsonNode payload = onlyOutboxPayload();

        List<String> details = new ArrayList<>();
        payload.path("details").fieldNames().forEachRemaining(details::add);
        assertThat(details).containsExactlyInAnyOrder("operation", "new_modality", "signing_certificate");
        assertThat(payload.toString()).doesNotContain(KEY_ARN).doesNotContain("secret-looking-id")
                .doesNotContainIgnoringCase("password").doesNotContainIgnoringCase("private");
    }

    @Test
    void context_hasNoDispatcher_theToolNeverSendsEvents() {
        assertThat(handle.context().getBeanNamesForType(com.eudistack.auditoria.dispatch.OutboxDispatcher.class))
                .isEmpty();
        assertThat(handle.context().getBeanNamesForType(com.eudistack.auditoria.dispatch.DrainLoop.class)).isEmpty();
        assertThat(handle.context().getBeanNamesForType(com.eudistack.auditoria.port.AuditHttpClient.class)).isEmpty();
    }

    @Test
    void context_isNotWebAndHasNothingOfTheIssuer() {
        assertThat(handle.context().getBeanNamesForType(javax.sql.DataSource.class)).hasSize(1);
        assertThat(handle.context().getBeanDefinitionCount()).isLessThan(60);
        assertThat(handle.context().containsBean("tenantSchemaFlywayMigrator")).isFalse();
    }
}
