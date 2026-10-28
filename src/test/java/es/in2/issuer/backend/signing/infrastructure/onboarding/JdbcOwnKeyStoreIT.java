package es.in2.issuer.backend.signing.infrastructure.onboarding;

import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingRejectedException;
import es.in2.issuer.backend.signing.domain.onboarding.RejectionReason;
import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged;
import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged.Operation;
import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged.Result;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.ActiveConfiguration;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.NewOwnKeyConfiguration;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.SpkiReservation;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort.WithdrawnOwnKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static es.in2.issuer.backend.signing.infrastructure.onboarding.OnboardingTestDatabase.execute;
import static es.in2.issuer.backend.signing.infrastructure.onboarding.OnboardingTestDatabase.query;
import static es.in2.issuer.backend.signing.infrastructure.onboarding.OnboardingTestDatabase.scalar;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** {@link JdbcOwnKeyStore} against a real Postgres with the real migrations of the Issuer. */
class JdbcOwnKeyStoreIT {

    private static final String CALLER = "arn:aws:sts::000000000000:assumed-role/own-key-operation/jane";
    private static final String NEW_KEY = "arn:aws:kms:eu-west-1:000000000000:key/new";
    private static final byte[] SPKI = HexFormat.of().parseHex("11".repeat(32));
    private static final byte[] OTHER_SPKI = HexFormat.of().parseHex("22".repeat(32));
    private static final String QTSP_CONFIG = """
            {"url":"https://qtsp.example","authUrl":"https://auth.example","signPath":"sign-hash",
             "clientId":"client-1","qtspTenantId":"tenant-1","credentialPwd":"pwd","clientSecret":"secret",
             "accessKey":"access","credentialId":"credential"}""";

    private final RecordingAuditSink sink = new RecordingAuditSink();
    private final JdbcOwnKeyStore store = OnboardingTestDatabase.store(sink);

    /** Remembers what was staged and what was published after the commit; can be made to fail. */
    private static final class RecordingAuditSink implements SigningConfigurationAuditSink {

        final List<SigningConfigurationChanged> staged = new ArrayList<>();
        final List<SigningConfigurationChanged> published = new ArrayList<>();
        final List<Connection> connections = new ArrayList<>();
        boolean failOnStage;
        boolean failAfterCommit;

        @Override
        public void stage(Connection connection, SigningConfigurationChanged event) throws SQLException {
            if (failOnStage) {
                throw new SQLException("the outbox is not available");
            }
            connections.add(connection);
            staged.add(event);
        }

        @Override
        public void afterCommit(SigningConfigurationChanged event) {
            if (failAfterCommit) {
                throw new IllegalStateException("the dispatcher is not available");
            }
            published.add(event);
        }
    }

    @BeforeEach
    void emptyTables() {
        OnboardingTestDatabase.reset();
    }

    private static UUID insertQtspActive(String tenant) {
        UUID id = UUID.randomUUID();
        execute("INSERT INTO " + tenant + "_issuer.tenant_signing_config (id, provider, modality, status, "
                + "activated_by, provider_specific_config) VALUES (?, 'sandbox-qtsp', 'qtsp', 'active', 'seed', ?::jsonb)",
                id, QTSP_CONFIG);
        return id;
    }

    /** @param withdrawnSecondsAgo when the row was withdrawn; {@code null} for a row that is not */
    private static UUID insertOwnKey(String tenant, String status, String keyRef, Integer withdrawnSecondsAgo,
                                     Instant deletedAt) {
        UUID id = UUID.randomUUID();
        execute("INSERT INTO " + tenant + "_issuer.tenant_signing_config (id, provider, modality, status, activated_by, "
                + "withdrawn_at, withdrawn_by, own_key_kms_key_ref, own_key_algorithm, own_key_certificate_chain, "
                + "own_key_loaded_at, own_key_deleted_at) VALUES (?, 'aws-kms', 'own_key', ?, 'arn:before', "
                + "CASE WHEN ?::int IS NULL THEN NULL ELSE now() - make_interval(secs => ?::int) END, "
                + "CASE WHEN ?::int IS NULL THEN NULL ELSE 'arn:before' END, ?, 'ES256', '[\"AAAA\"]'::jsonb, now(), "
                + "?::timestamptz)",
                id, status, withdrawnSecondsAgo, withdrawnSecondsAgo, withdrawnSecondsAgo, keyRef,
                deletedAt == null ? null : Timestamp.from(deletedAt));
        return id;
    }

    private static void reserve(byte[] spki, String tenant, UUID configurationId) {
        execute("INSERT INTO public.signing_spki_reservation (public_key_spki_sha256, tenant_id, "
                + "signing_configuration_id) VALUES (?, ?, ?)", spki, tenant, configurationId);
    }

    private UUID replaceActive(String tenant, byte[] spki) {
        return store.inTransaction(tx -> {
            var previous = tx.lockActiveConfiguration(tenant);
            previous.ifPresent(active -> tx.withdraw(tenant, active, CALLER));
            UUID id = tx.activateOwnKey(tenant, new NewOwnKeyConfiguration(NEW_KEY, List.of("QUJD", "REVG")), CALLER);
            tx.reserveSpki(spki, tenant, id);
            tx.stage(new SigningConfigurationChanged(tenant, previous.isPresent() ? Operation.REPLACE : Operation.CREATE,
                    Result.SUCCESS, null, previous.map(ActiveConfiguration::modality).orElse(null),
                    SigningModality.OWN_KEY, "ab".repeat(32), CALLER, Duration.ZERO, Instant.now(), "op-1"));
            return id;
        });
    }

    @Test
    void findTenant_activeTenantWithoutConfiguration_isProvisionedWithNoModality() {
        var tenant = store.findTenant("cgcom").orElseThrow();

        assertThat(tenant.active()).isTrue();
        assertThat(tenant.schemaProvisioned()).isTrue();
        assertThat(tenant.activeModality()).isNull();
    }

    @Test
    void findTenant_tenantWithAnActiveQtspRow_reportsItsModality() {
        insertQtspActive("cgcom");

        assertThat(store.findTenant("cgcom").orElseThrow().activeModality()).isEqualTo(SigningModality.QTSP);
    }

    @Test
    void findTenant_inactiveTenant_isNotActive() {
        assertThat(store.findTenant("dormant").orElseThrow().active()).isFalse();
    }

    @Test
    void findTenant_registeredTenantWithoutSchema_isNotProvisioned() {
        assertThat(store.findTenant("ghost").orElseThrow().schemaProvisioned()).isFalse();
    }

    @Test
    void findTenant_unknownTenant_isEmpty() {
        assertThat(store.findTenant("nobody")).isEmpty();
    }

    @Test
    void findActiveTenants_returnsTheOnesTheRegistryMarksActive() {
        assertThat(store.findActiveTenants()).contains("cgcom", "kpmg", "ghost").doesNotContain("dormant");
    }

    @Test
    void findSpkiReservation_reservedHash_returnsTheTenantAndTheConfiguration() {
        UUID configuration = UUID.randomUUID();
        reserve(SPKI, "kpmg", configuration);

        assertThat(store.findSpkiReservation(SPKI)).contains(new SpkiReservation("kpmg", configuration));
        assertThat(store.findSpkiReservation(OTHER_SPKI)).isEmpty();
    }

    @Test
    void findTenant_tenantWithAnActiveOwnKeyRow_reportsItsIdAndKey() {
        UUID id = insertOwnKey("cgcom", "active", "arn:aws:kms:eu-west-1:000000000000:key/live", null, null);

        var tenant = store.findTenant("cgcom").orElseThrow();

        assertThat(tenant.activeConfigurationId()).isEqualTo(id);
        assertThat(tenant.activeKmsKeyRef()).isEqualTo("arn:aws:kms:eu-west-1:000000000000:key/live");
    }

    @Test
    void isKeyReferenced_looksAtEveryTenantSchemaAndAtTheStatusAsked() {
        insertOwnKey("kpmg", "active", "arn:in-kpmg", null, null);
        insertOwnKey("cgcom", "withdrawn", "arn:withdrawn", 600, null);

        assertThat(store.isKeyReferenced("arn:in-kpmg", true)).isTrue();
        assertThat(store.isKeyReferenced("arn:withdrawn", true)).isFalse();
        assertThat(store.isKeyReferenced("arn:withdrawn", false)).isTrue();
        assertThat(store.isKeyReferenced("arn:nowhere", false)).isFalse();
    }

    @Test
    void renewal_withdrawsTheOldRowMarksItHandledAndMovesTheReservationKeepingTheKey() {
        String key = "arn:aws:kms:eu-west-1:000000000000:key/kept";
        UUID previous = insertOwnKey("cgcom", "active", key, null, null);
        reserve(SPKI, "cgcom", previous);

        UUID created = store.inTransaction(tx -> {
            var active = tx.lockActiveConfiguration("cgcom").orElseThrow();
            tx.withdraw("cgcom", active, CALLER);
            tx.markKeyRetired("cgcom", new WithdrawnOwnKey(active.id(), "cgcom", active.kmsKeyRef()));
            UUID id = tx.activateOwnKey("cgcom", new NewOwnKeyConfiguration(key, List.of("QUJD")), CALLER);
            tx.reserveSpki(SPKI, "cgcom", id);
            return id;
        });

        assertThat(query("SELECT status, own_key_deleted_at IS NOT NULL FROM cgcom_issuer.tenant_signing_config "
                + "WHERE id = ?", previous)).singleElement().isEqualTo(List.of("withdrawn", true));
        assertThat(scalar("SELECT own_key_kms_key_ref FROM cgcom_issuer.tenant_signing_config WHERE id = ?", created))
                .isEqualTo(key);
        assertThat(scalar("SELECT signing_configuration_id FROM public.signing_spki_reservation "
                + "WHERE public_key_spki_sha256 = ?", (Object) SPKI)).isEqualTo(created);
        assertThat(store.findWithdrawnOwnKeysPendingKms("cgcom", Duration.ZERO)).isEmpty();
        assertThat(store.isKeyReferenced(key, true)).isTrue();
    }

    @Test
    void replacement_ofAQtspConfiguration_withdrawsItAndRemovesOnlyTheFourSecrets() {
        UUID previous = insertQtspActive("cgcom");

        UUID created = replaceActive("cgcom", SPKI);

        assertThat(query("SELECT status, withdrawn_by, withdrawn_at IS NOT NULL FROM cgcom_issuer.tenant_signing_config "
                + "WHERE id = ?", previous)).singleElement().isEqualTo(List.of("withdrawn", CALLER, true));
        String config = (String) scalar("SELECT provider_specific_config::text FROM cgcom_issuer.tenant_signing_config "
                + "WHERE id = ?", previous);
        assertThat(config).doesNotContain("credentialPwd", "clientSecret", "accessKey", "credentialId", "pwd",
                "secret", "access", "credential\"")
                .contains("\"url\"", "\"authUrl\"", "\"signPath\"", "\"clientId\"", "\"qtspTenantId\"");
        assertThat(query("SELECT status, modality, provider, activated_by, own_key_kms_key_ref, own_key_algorithm, "
                + "own_key_certificate_chain::text, own_key_loaded_at IS NOT NULL FROM cgcom_issuer.tenant_signing_config "
                + "WHERE id = ?", created)).singleElement().isEqualTo(List.of("active", "own_key", "aws-kms", CALLER,
                NEW_KEY, "ES256", "[\"QUJD\", \"REVG\"]", true));
        assertThat(query("SELECT tenant_id, signing_configuration_id FROM public.signing_spki_reservation "
                + "WHERE public_key_spki_sha256 = ?", (Object) SPKI)).singleElement().isEqualTo(List.of("cgcom", created));
    }

    @Test
    void replacement_ofAnOwnKeyConfiguration_withdrawsItAndKeepsItsReservationUntilItsKeyIsRetired() {
        String oldKey = "arn:aws:kms:eu-west-1:000000000000:key/old";
        UUID previous = insertOwnKey("cgcom", "active", oldKey, null, null);
        reserve(OTHER_SPKI, "cgcom", previous);

        UUID created = replaceActive("cgcom", SPKI);

        assertThat(scalar("SELECT status FROM cgcom_issuer.tenant_signing_config WHERE id = ?", previous))
                .isEqualTo("withdrawn");
        assertThat(scalar("SELECT signing_configuration_id FROM public.signing_spki_reservation "
                + "WHERE public_key_spki_sha256 = ?", (Object) OTHER_SPKI)).isEqualTo(previous);
        assertThat(scalar("SELECT signing_configuration_id FROM public.signing_spki_reservation "
                + "WHERE public_key_spki_sha256 = ?", (Object) SPKI)).isEqualTo(created);
        // the replaced key still exists in KMS: the same public key cannot go to another tenant yet
        assertThatThrownBy(() -> store.inTransaction(tx -> {
            tx.reserveSpki(OTHER_SPKI, "kpmg", UUID.randomUUID());
            return null;
        })).isInstanceOfSatisfying(OnboardingRejectedException.class,
                e -> assertThat(e.getReason()).isEqualTo(RejectionReason.KEY_IN_USE));

        store.inTransaction(tx -> {
            tx.markKeyRetired("cgcom", new WithdrawnOwnKey(previous, "cgcom", oldKey));
            return null;
        });

        assertThat(scalar("SELECT count(*) FROM public.signing_spki_reservation WHERE public_key_spki_sha256 = ?",
                (Object) OTHER_SPKI)).isEqualTo(0L);
        assertThat(scalar("SELECT count(*) FROM public.signing_spki_reservation WHERE public_key_spki_sha256 = ?",
                (Object) SPKI)).isEqualTo(1L);
        assertThatCode(() -> store.inTransaction(tx -> {
            tx.reserveSpki(OTHER_SPKI, "kpmg", UUID.randomUUID());
            return null;
        })).doesNotThrowAnyException();
    }

    @Test
    void replacement_firstConfigurationOfATenant_createsTheActiveRow() {
        UUID created = replaceActive("cgcom", SPKI);

        assertThat(scalar("SELECT count(*) FROM cgcom_issuer.tenant_signing_config WHERE status = 'active'"))
                .isEqualTo(1L);
        assertThat(scalar("SELECT id FROM cgcom_issuer.tenant_signing_config WHERE status = 'active'"))
                .isEqualTo(created);
    }

    @Test
    void replacement_doesNotTouchTheConfigurationOfAnotherTenant() {
        UUID other = insertQtspActive("kpmg");

        replaceActive("cgcom", SPKI);

        assertThat(scalar("SELECT status FROM kpmg_issuer.tenant_signing_config WHERE id = ?", other))
                .isEqualTo("active");
    }

    @Test
    void replacement_keyAlreadyReserved_isRejectedAndTheDatabaseIsUnchanged() {
        UUID previous = insertQtspActive("cgcom");
        reserve(SPKI, "kpmg", UUID.randomUUID());

        assertThatThrownBy(() -> replaceActive("cgcom", SPKI))
                .isInstanceOfSatisfying(OnboardingRejectedException.class,
                        e -> assertThat(e.getReason()).isEqualTo(RejectionReason.KEY_IN_USE));

        assertThat(scalar("SELECT status FROM cgcom_issuer.tenant_signing_config WHERE id = ?", previous))
                .isEqualTo("active");
        assertThat(scalar("SELECT count(*) FROM cgcom_issuer.tenant_signing_config")).isEqualTo(1L);
        assertThat(scalar("SELECT provider_specific_config::text FROM cgcom_issuer.tenant_signing_config "
                + "WHERE id = ?", previous).toString()).contains("credentialPwd");
        assertThat(sink.published).isEmpty();
    }

    @Test
    void replacement_commits_thenPublishesTheStagedEventOnTheSameConnection() {
        replaceActive("cgcom", SPKI);

        assertThat(sink.staged).hasSize(1);
        assertThat(sink.published).isEqualTo(sink.staged);
    }

    @Test
    void replacement_stagingTheEventFails_rollsTheWholeChangeBack() {
        UUID previous = insertQtspActive("cgcom");
        sink.failOnStage = true;

        assertThatThrownBy(() -> replaceActive("cgcom", SPKI)).hasMessageContaining("outbox is not available");

        assertThat(scalar("SELECT status FROM cgcom_issuer.tenant_signing_config WHERE id = ?", previous))
                .isEqualTo("active");
        assertThat(scalar("SELECT count(*) FROM cgcom_issuer.tenant_signing_config")).isEqualTo(1L);
        assertThat(scalar("SELECT count(*) FROM public.signing_spki_reservation")).isEqualTo(0L);
        assertThat(sink.published).isEmpty();
    }

    @Test
    void replacement_sinkThatFailsAfterTheCommit_doesNotFailOrUndoTheChange() {
        sink.failAfterCommit = true;

        UUID created = replaceActive("cgcom", SPKI);

        assertThat(scalar("SELECT status FROM cgcom_issuer.tenant_signing_config WHERE id = ?", created))
                .isEqualTo("active");
    }

    @Test
    void recordInOwnTransaction_stagesAndPublishesTheEventWithoutTouchingTheConfiguration() {
        UUID previous = insertQtspActive("cgcom");
        var event = new SigningConfigurationChanged("cgcom", Operation.CREATE, Result.DENIED,
                RejectionReason.INVALID_KEY, null, SigningModality.OWN_KEY, null, CALLER, Duration.ZERO, Instant.now(), null);

        store.recordInOwnTransaction(event);

        assertThat(sink.staged).containsExactly(event);
        assertThat(sink.published).containsExactly(event);
        assertThat(scalar("SELECT status FROM cgcom_issuer.tenant_signing_config WHERE id = ?", previous))
                .isEqualTo("active");
    }

    @Test
    void findWithdrawnOwnKeysPendingKms_returnsOnlyRowsPastTheGraceAndNotMarked() {
        UUID old = insertOwnKey("cgcom", "withdrawn", "arn:old", 600, null);
        insertOwnKey("cgcom", "withdrawn", "arn:recent", 10, null);
        insertOwnKey("cgcom", "withdrawn", "arn:marked", 600, Instant.now());
        insertOwnKey("cgcom", "active", "arn:active", null, null);
        insertQtspActive("kpmg");

        var rows = store.findWithdrawnOwnKeysPendingKms("cgcom", Duration.ofSeconds(160));

        assertThat(rows).extracting(WithdrawnOwnKey::id).containsExactly(old);
        assertThat(rows.getFirst().kmsKeyRef()).isEqualTo("arn:old");
    }

    @Test
    void lockNextWithdrawnOwnKey_respectsTheGraceAndTheExcludedRows() {
        UUID first = insertOwnKey("cgcom", "withdrawn", "arn:first", 900, null);
        UUID second = insertOwnKey("cgcom", "withdrawn", "arn:second", 600, null);
        insertOwnKey("cgcom", "withdrawn", "arn:recent", 10, null);

        var all = store.inTransaction(tx -> tx.lockNextWithdrawnOwnKey("cgcom", Duration.ofSeconds(160), Set.of()));
        var withoutFirst = store.inTransaction(
                tx -> tx.lockNextWithdrawnOwnKey("cgcom", Duration.ofSeconds(160), Set.of(first)));
        var none = store.inTransaction(
                tx -> tx.lockNextWithdrawnOwnKey("cgcom", Duration.ofSeconds(160), Set.of(first, second)));

        assertThat(all).map(WithdrawnOwnKey::id).contains(first);
        assertThat(withoutFirst).map(WithdrawnOwnKey::id).contains(second);
        assertThat(none).isEmpty();
    }

    @Test
    void activateOwnKey_keepsTheOperationThatActivatedTheRow_andTheReconcileReadsItBack() {
        UUID first = store.inTransaction(tx -> tx.activateOwnKey("cgcom",
                new NewOwnKeyConfiguration(NEW_KEY, List.of("QUJD"), "op-first"), CALLER));
        replaceActive("cgcom", SPKI);
        execute("UPDATE cgcom_issuer.tenant_signing_config SET withdrawn_at = now() - interval '10 minutes' WHERE id = ?",
                first);

        var pending = store.findWithdrawnOwnKeysPendingKms("cgcom", Duration.ofSeconds(160));
        var locked = store.inTransaction(tx -> tx.lockNextWithdrawnOwnKey("cgcom", Duration.ofSeconds(160), Set.of()));

        assertThat(scalar("SELECT own_key_operation_id FROM cgcom_issuer.tenant_signing_config WHERE id = ?", first))
                .isEqualTo("op-first");
        assertThat(pending).singleElement().satisfies(row -> assertThat(row.operationId()).isEqualTo("op-first"));
        assertThat(locked).map(WithdrawnOwnKey::operationId).contains("op-first");
    }

    @Test
    void lockNextWithdrawnOwnKey_rowWithoutTheOperationThatActivatedIt_hasNoOperationId() {
        insertOwnKey("cgcom", "withdrawn", "arn:old", 600, null);

        var locked = store.inTransaction(tx -> tx.lockNextWithdrawnOwnKey("cgcom", Duration.ofSeconds(160), Set.of()));

        assertThat(locked).hasValueSatisfying(row -> assertThat(row.operationId()).isNull());
    }

    @Test
    void markKeyRetired_setsTheDeletionDateAndTheRowIsNotSelectedAgain() {
        UUID id = insertOwnKey("cgcom", "withdrawn", "arn:old", 600, null);

        store.inTransaction(tx -> {
            var row = tx.lockNextWithdrawnOwnKey("cgcom", Duration.ofSeconds(160), Set.of()).orElseThrow();
            tx.markKeyRetired("cgcom", row);
            return null;
        });

        assertThat(scalar("SELECT own_key_deleted_at IS NOT NULL FROM cgcom_issuer.tenant_signing_config WHERE id = ?",
                id)).isEqualTo(true);
        assertThat(store.findWithdrawnOwnKeysPendingKms("cgcom", Duration.ZERO)).isEmpty();
    }

    @Test
    void markKeyStillInUse_marksTheRowHandledButKeepsItsSpkiReservation() {
        UUID id = insertOwnKey("cgcom", "withdrawn", "arn:old", 600, null);
        store.inTransaction(tx -> {
            tx.reserveSpki(SPKI, "cgcom", id);
            return null;
        });

        store.inTransaction(tx -> {
            var row = tx.lockNextWithdrawnOwnKey("cgcom", Duration.ofSeconds(160), Set.of()).orElseThrow();
            tx.markKeyStillInUse("cgcom", row);
            return null;
        });

        assertThat(scalar("SELECT own_key_deleted_at IS NOT NULL FROM cgcom_issuer.tenant_signing_config WHERE id = ?",
                id)).isEqualTo(true);
        assertThat(store.findWithdrawnOwnKeysPendingKms("cgcom", Duration.ZERO)).isEmpty();
        assertThat(store.findSpkiReservation(SPKI)).isPresent().get()
                .satisfies(reservation -> assertThat(reservation.configurationId()).isEqualTo(id));
    }

    @Test
    void markKeyRetired_releasesTheSpkiReservationOfTheRow() {
        UUID id = insertOwnKey("cgcom", "withdrawn", "arn:old", 600, null);
        store.inTransaction(tx -> {
            tx.reserveSpki(SPKI, "cgcom", id);
            return null;
        });

        store.inTransaction(tx -> {
            var row = tx.lockNextWithdrawnOwnKey("cgcom", Duration.ofSeconds(160), Set.of()).orElseThrow();
            tx.markKeyRetired("cgcom", row);
            return null;
        });

        assertThat(store.findSpkiReservation(SPKI)).isEmpty();
    }

    @Test
    void lockNextWithdrawnOwnKey_rowLockedByAnotherTransaction_isSkipped() throws Exception {
        UUID id = insertOwnKey("cgcom", "withdrawn", "arn:old", 600, null);

        try (Connection holder = OnboardingTestDatabase.open()) {
            holder.setAutoCommit(false);
            try (var statement = holder.prepareStatement(
                    "SELECT id FROM cgcom_issuer.tenant_signing_config WHERE id = ? FOR UPDATE")) {
                statement.setObject(1, id);
                statement.executeQuery().close();
            }

            var whileLocked = store.inTransaction(
                    tx -> tx.lockNextWithdrawnOwnKey("cgcom", Duration.ofSeconds(160), Set.of()));
            holder.rollback();
            var afterRelease = store.inTransaction(
                    tx -> tx.lockNextWithdrawnOwnKey("cgcom", Duration.ofSeconds(160), Set.of()));

            assertThat(whileLocked).isEmpty();
            assertThat(afterRelease).map(WithdrawnOwnKey::id).contains(id);
        }
    }

    @Test
    void inTransaction_activeRowLockedByAnotherTransaction_failsAfterTheLockTimeoutInsteadOfWaiting() throws Exception {
        insertQtspActive("cgcom");

        try (Connection holder = OnboardingTestDatabase.open()) {
            holder.setAutoCommit(false);
            try (var statement = holder.prepareStatement(
                    "SELECT id FROM cgcom_issuer.tenant_signing_config WHERE status = 'active' FOR UPDATE")) {
                statement.executeQuery().close();
            }
            long started = System.nanoTime();

            assertThatThrownBy(() -> store.inTransaction(tx -> tx.lockActiveConfiguration("cgcom")))
                    .hasMessageContaining("SQLState 55P03");

            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(20));
            holder.rollback();
        }
    }

    @Test
    void inTransactionAndRecordInOwnTransaction_runWithTheLockAndStatementTimeouts() {
        List<String> seen = new ArrayList<>();
        JdbcOwnKeyStore probed = OnboardingTestDatabase.store(new SigningConfigurationAuditSink() {
            @Override
            public void stage(Connection connection, SigningConfigurationChanged event) throws SQLException {
                seen.add(show(connection, "lock_timeout") + "/" + show(connection, "statement_timeout"));
            }

            @Override
            public void afterCommit(SigningConfigurationChanged event) {
                // nothing to publish
            }
        });
        var event = new SigningConfigurationChanged("cgcom", Operation.CREATE, Result.DENIED,
                RejectionReason.INVALID_KEY, null, SigningModality.OWN_KEY, null, CALLER, Duration.ZERO, Instant.now(), null);

        probed.inTransaction(tx -> {
            tx.stage(event);
            return null;
        });
        probed.recordInOwnTransaction(event);

        assertThat(seen).containsExactly("5s/30s", "5s/30s");
    }

    private static String show(Connection connection, String setting) throws SQLException {
        try (var statement = connection.createStatement(); var rs = statement.executeQuery("SHOW " + setting)) {
            rs.next();
            return rs.getString(1);
        }
    }

    @Test
    void lockNextWithdrawnOwnKey_tenantWithoutSchema_failsWithoutLeakingThePassword() {
        assertThatThrownBy(() -> store.inTransaction(
                tx -> tx.lockNextWithdrawnOwnKey("ghost", Duration.ZERO, Set.of())))
                .hasMessageContaining("database error")
                .hasMessageNotContaining(OnboardingTestDatabase.POSTGRES.getPassword());
    }

    @Test
    void tenantIdThatIsNotASchemaName_isNeverPutInAStatement() {
        assertThatThrownBy(() -> store.findWithdrawnOwnKeysPendingKms("x\"; DROP TABLE a; --", Duration.ZERO))
                .hasMessageContaining("not a valid tenant id");
    }

    @Test
    void tryLockOperation_aSecondRunOfTheSameOperationCannotTakeItUntilTheFirstReleasesIt() {
        JdbcOwnKeyStore anotherProcess = OnboardingTestDatabase.store(sink);

        try (var _ = store.tryLockOperation("op-1").orElseThrow()) {
            assertThat(anotherProcess.tryLockOperation("op-1")).as("the same operation").isEmpty();
            try (var other = anotherProcess.tryLockOperation("op-2").orElseThrow()) {
                assertThat(other).as("another operation can be locked meanwhile").isNotNull();
            }
        }

        try (var again = anotherProcess.tryLockOperation("op-1").orElseThrow()) {
            assertThat(again).as("after the release").isNotNull();
        }
    }

    @Test
    void tryLockOperation_sessionOfTheLockTerminated_isNoLongerHeldAndAnotherRunCanTakeIt() {
        JdbcOwnKeyStore anotherProcess = OnboardingTestDatabase.store(sink);

        try (var lock = store.tryLockOperation("op-1").orElseThrow()) {
            assertThat(lock.isHeld()).isTrue();

            Object pid = scalar("SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted AND objsubid = 2 "
                    + "AND objid = hashtext('op-1')::oid");
            assertThat(scalar("SELECT pg_terminate_backend(?)", pid)).isEqualTo(true);

            assertThat(lock.isHeld()).as("the session that held it is gone").isFalse();
            try (var taken = anotherProcess.tryLockOperation("op-1").orElseThrow()) {
                assertThat(taken.isHeld()).isTrue();
                assertThat(lock.isHeld()).as("held by another session now, not by this one").isFalse();
            }
        }
    }

    @Test
    void tryLockOperation_andTheTransactionLockOfATenantWithTheSameName_doNotBlockEachOther() {
        try (var _ = store.tryLockOperation("cgcom").orElseThrow()) {
            assertThatCode(() -> OnboardingTestDatabase.store(sink).inTransaction(
                    tx -> tx.lockActiveConfiguration("cgcom"))).doesNotThrowAnyException();
        }
    }

    @Test
    void tryLockOperation_theLockLastsAcrossTransactionsOfTheRun() {
        JdbcOwnKeyStore anotherProcess = OnboardingTestDatabase.store(sink);

        try (var _ = store.tryLockOperation("op-1").orElseThrow()) {
            store.inTransaction(tx -> tx.lockActiveConfiguration("cgcom"));
            store.findTenant("cgcom");

            assertThat(anotherProcess.tryLockOperation("op-1")).isEmpty();
        }
    }
}
