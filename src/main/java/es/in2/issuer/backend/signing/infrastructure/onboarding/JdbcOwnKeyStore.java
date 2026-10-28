package es.in2.issuer.backend.signing.infrastructure.onboarding;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.onboarding.CommitOutcomeUnknownException;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFailedException;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingRejectedException;
import es.in2.issuer.backend.signing.domain.onboarding.RejectionReason;
import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyStorePort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.regex.Pattern;
import javax.sql.DataSource;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;

/**
 * {@link OwnKeyStorePort} over JDBC with Spring transactions on a {@link DataSource} (the tool is not a Spring
 * Boot application; spring-jdbc is used for the transaction only). Every statement of a
 * tenant is schema-qualified with {@code <tenant>_issuer}, so no {@code search_path} is needed; the tenant id
 * is checked against the shape of a schema name before it is put in a statement.
 *
 * <p>The password is only handed to the driver; no message of this class includes it.
 */
@Slf4j
public class JdbcOwnKeyStore implements OwnKeyStorePort {

    private static final Pattern TENANT_ID = Pattern.compile("^[a-z][a-z0-9_-]{0,62}$");
    private static final String PROVIDER_AWS_KMS = "aws-kms";
    private static final String ALGORITHM_ES256 = "ES256";
    private static final String UNIQUE_VIOLATION = "23505";
    /** The four secret fields of a QTSP configuration, removed from a row that is withdrawn (H-7). */
    private static final String[] QTSP_SECRET_FIELDS = {"credentialPwd", "clientSecret", "accessKey", "credentialId"};
    private static final String ONBOARDING_LOCK_PREFIX = "eudistack.own_key_onboarding:";
    private static final String IMPORT_LOCK_PREFIX = "eudistack.own_key_import:";

    private final DataSource dataSource;
    private final TransactionTemplate transactions;
    private final SigningConfigurationAuditSink auditSink;
    private final ObjectMapper objectMapper = new ObjectMapper();

    /** @param dataSource the one every transaction and every audit sink uses, so that they share the transaction */
    public JdbcOwnKeyStore(DataSource dataSource, SigningConfigurationAuditSink auditSink) {
        this.dataSource = dataSource;
        this.transactions = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        this.auditSink = auditSink;
    }

    public JdbcOwnKeyStore(String url, String user, String password, SigningConfigurationAuditSink auditSink) {
        this(new DriverManagerDataSource(url, user, password), auditSink);
    }

    @Override
    public Optional<RegisteredTenant> findTenant(String tenantId) {
        return read(connection -> {
            String status = queryString(connection,
                    "SELECT status FROM public.tenant_registry WHERE schema_name = ?", tenantId);
            if (status == null) {
                return Optional.<RegisteredTenant>empty();
            }
            boolean provisioned = queryString(connection, "SELECT table_name FROM information_schema.tables "
                    + "WHERE table_schema = ? AND table_name = 'tenant_signing_config'", schemaName(tenantId)) != null;
            if (!provisioned) {
                return Optional.of(new RegisteredTenant(tenantId, "active".equals(status), false, null, null, null));
            }
            try (PreparedStatement statement = connection.prepareStatement("SELECT id, modality, own_key_kms_key_ref FROM "
                    + table(tenantId) + " WHERE status = 'active'");
                 ResultSet rs = statement.executeQuery()) {
                boolean active = "active".equals(status);
                return rs.next()
                        ? Optional.of(new RegisteredTenant(tenantId, active, true, modalityOf(rs.getString(2)),
                                rs.getObject(1, UUID.class), rs.getString(3)))
                        : Optional.of(new RegisteredTenant(tenantId, active, true, null, null, null));
            }
        });
    }

    @Override
    public List<String> findActiveTenants() {
        return read(connection -> {
            List<String> tenants = new ArrayList<>();
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT schema_name FROM public.tenant_registry WHERE status = 'active' ORDER BY schema_name");
                 ResultSet rs = statement.executeQuery()) {
                while (rs.next()) {
                    tenants.add(rs.getString(1));
                }
            }
            return tenants;
        });
    }

    @Override
    public Optional<OperationLock> tryLockOperation(String operationId) {
        Connection connection = null;
        try {
            connection = open();
            try (PreparedStatement statement = connection.prepareStatement("SELECT pg_try_advisory_lock(hashtext(?))")) {
                statement.setString(1, IMPORT_LOCK_PREFIX + operationId);
                try (ResultSet rs = statement.executeQuery()) {
                    if (rs.next() && rs.getBoolean(1)) {
                        return Optional.of(new SessionLock(connection, operationId));
                    }
                }
            }
            connection.close();
            return Optional.empty();
        } catch (SQLException e) {
            closeQuietly(connection);
            throw databaseFailure(e);
        }
    }

    /** A session advisory lock: it belongs to the connection, which stays open until the lock is released. */
    private static final class SessionLock implements OperationLock {

        private final Connection connection;
        private final String operationId;

        private SessionLock(Connection connection, String operationId) {
            this.connection = connection;
            this.operationId = operationId;
        }

        @Override
        public void close() {
            try (PreparedStatement statement = connection.prepareStatement("SELECT pg_advisory_unlock(hashtext(?))")) {
                statement.setString(1, IMPORT_LOCK_PREFIX + operationId);
                statement.execute();
            } catch (SQLException e) {
                // Closing the connection below releases the lock of the session anyway.
                log.warn("The lock of operation {} could not be released explicitly: {}", operationId, e.getMessage());
            } finally {
                closeQuietly(connection);
            }
        }
    }

    private static void closeQuietly(Connection connection) {
        if (connection == null) {
            return;
        }
        try {
            connection.close();
        } catch (SQLException e) {
            log.debug("A connection could not be closed: {}", e.getMessage());
        }
    }

    @Override
    public Optional<SpkiReservation> findSpkiReservation(byte[] spkiSha256) {
        return read(connection -> {
            try (PreparedStatement statement = connection.prepareStatement("SELECT tenant_id, signing_configuration_id "
                    + "FROM public.signing_spki_reservation WHERE public_key_spki_sha256 = ?")) {
                statement.setBytes(1, spkiSha256);
                try (ResultSet rs = statement.executeQuery()) {
                    return rs.next()
                            ? Optional.of(new SpkiReservation(rs.getString(1), rs.getObject(2, UUID.class)))
                            : Optional.<SpkiReservation>empty();
                }
            }
        });
    }

    /**
     * Looks in the schema of every tenant that has a signing configuration table, as the catalogue lists them
     * ({@code pg_catalog} shows tables whatever the privileges of the role, unlike {@code information_schema}), so
     * a registered tenant whose table the role cannot read is still found. It fails closed: if the table of a tenant cannot be read, the key cannot be
     * shown to be unreferenced, so the call fails and the caller does not touch the key.
     *
     * @throws OnboardingFailedException if the signing configurations of some tenant cannot be read
     */
    @Override
    public boolean isKeyReferenced(String kmsKeyRef, boolean activeOnly) {
        return read(connection -> {
            Set<String> tenants = new TreeSet<>();
            try (PreparedStatement statement = connection.prepareStatement("SELECT n.nspname FROM pg_catalog.pg_class c "
                    + "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                    + "WHERE c.relname = 'tenant_signing_config' AND c.relkind IN ('r', 'p')");
                 ResultSet rs = statement.executeQuery()) {
                while (rs.next()) {
                    String schema = rs.getString(1);
                    if (schema.endsWith(SCHEMA_SUFFIX)) {
                        String tenant = schema.substring(0, schema.length() - SCHEMA_SUFFIX.length());
                        if (TENANT_ID.matcher(tenant).matches()) {
                            tenants.add(tenant);
                        }
                    }
                }
            }
            String where = " WHERE own_key_kms_key_ref = ?" + (activeOnly ? " AND status = 'active'" : "");
            for (String tenant : tenants) {
                try (PreparedStatement statement = connection.prepareStatement(
                        "SELECT EXISTS (SELECT 1 FROM " + table(tenant) + where + ")")) {
                    statement.setString(1, kmsKeyRef);
                    try (ResultSet rs = statement.executeQuery()) {
                        if (rs.next() && rs.getBoolean(1)) {
                            return true;
                        }
                    }
                } catch (SQLException e) {
                    throw new OnboardingFailedException("the signing configurations of tenant '" + tenant
                            + "' cannot be read (SQLState " + e.getSQLState() + "), so the key cannot be shown to be "
                            + "unreferenced: nothing was done with it", e);
                }
            }
            return false;
        });
    }

    @Override
    public List<WithdrawnOwnKey> findWithdrawnOwnKeysPendingKms(String tenantId, Duration grace) {
        return read(connection -> {
            List<WithdrawnOwnKey> rows = new ArrayList<>();
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT id, own_key_kms_key_ref FROM " + table(tenantId) + " WHERE modality = 'own_key' "
                            + "AND status = 'withdrawn' AND own_key_deleted_at IS NULL "
                            + "AND withdrawn_at < now() - make_interval(secs => ?) ORDER BY withdrawn_at")) {
                statement.setDouble(1, seconds(grace));
                try (ResultSet rs = statement.executeQuery()) {
                    while (rs.next()) {
                        rows.add(new WithdrawnOwnKey(rs.getObject(1, UUID.class), tenantId, rs.getString(2)));
                    }
                }
            }
            return rows;
        });
    }

    /**
     * One Spring transaction on the data source: whatever else runs on the same {@link DataSource} inside
     * {@code work}, such as the outbox of the audit starter, joins it. A failure of the commit itself leaves the
     * outcome unknown (the server may have committed before the connection broke), which the caller must not treat
     * as a rollback.
     */
    @Override
    public <T> T inTransaction(Function<ConfigurationTransaction, T> work) {
        AtomicBoolean started = new AtomicBoolean();
        AtomicBoolean completed = new AtomicBoolean();
        List<SigningConfigurationChanged> staged = new ArrayList<>();
        T result;
        try {
            result = transactions.execute(status -> {
                started.set(true);
                JdbcConfigurationTransaction transaction = new JdbcConfigurationTransaction(
                        DataSourceUtils.getConnection(dataSource), staged);
                T value = work.apply(transaction);
                completed.set(true);
                return value;
            });
        } catch (TransactionException e) {
            if (started.get() && completed.get()) {
                throw new CommitOutcomeUnknownException("the database did not confirm the commit: " + e.getMessage(), e);
            }
            throw databaseFailure(e);
        }
        staged.forEach(this::publish);
        return result;
    }

    @Override
    public void recordInOwnTransaction(SigningConfigurationChanged event) {
        try {
            transactions.executeWithoutResult(status -> {
                try {
                    auditSink.stage(DataSourceUtils.getConnection(dataSource), event);
                } catch (SQLException e) {
                    throw databaseFailure(e);
                }
            });
        } catch (TransactionException e) {
            throw databaseFailure(e);
        }
        publish(event);
    }

    /** The change is already committed: a sink that fails cannot undo it. */
    private void publish(SigningConfigurationChanged event) {
        try {
            auditSink.afterCommit(event);
        } catch (RuntimeException e) {
            log.error("The audit event of tenant '{}' could not be published after the commit: {}",
                    event.tenant(), e.toString());
        }
    }

    private final class JdbcConfigurationTransaction implements ConfigurationTransaction {

        private final Connection connection;
        private final List<SigningConfigurationChanged> staged;

        private JdbcConfigurationTransaction(Connection connection, List<SigningConfigurationChanged> staged) {
            this.connection = connection;
            this.staged = staged;
        }

        @Override
        public Optional<ActiveConfiguration> lockActiveConfiguration(String tenantId) {
            return run(() -> {
                try (PreparedStatement lock = connection.prepareStatement("SELECT pg_advisory_xact_lock(hashtext(?))")) {
                    lock.setString(1, ONBOARDING_LOCK_PREFIX + tenantId);
                    lock.execute();
                }
                try (PreparedStatement statement = connection.prepareStatement("SELECT id, modality, own_key_kms_key_ref FROM "
                        + table(tenantId) + " WHERE status = 'active' FOR UPDATE");
                     ResultSet rs = statement.executeQuery()) {
                    return rs.next()
                            ? Optional.of(new ActiveConfiguration(rs.getObject(1, UUID.class),
                                    modalityOf(rs.getString(2)), rs.getString(3)))
                            : Optional.<ActiveConfiguration>empty();
                }
            });
        }

        @Override
        public void withdraw(String tenantId, ActiveConfiguration configuration, String withdrawnBy) {
            run(() -> {
                try (PreparedStatement statement = connection.prepareStatement("UPDATE " + table(tenantId)
                        + " SET status = 'withdrawn', withdrawn_at = now(), withdrawn_by = ?, updated_at = now(), "
                        + "provider_specific_config = CASE WHEN modality = 'qtsp' "
                        + "THEN provider_specific_config - ?::text[] ELSE provider_specific_config END "
                        + "WHERE id = ? AND status = 'active'")) {
                    statement.setString(1, withdrawnBy);
                    statement.setArray(2, connection.createArrayOf("text", QTSP_SECRET_FIELDS));
                    statement.setObject(3, configuration.id());
                    requireOneRow(statement.executeUpdate(), "withdraw the active signing configuration");
                }
                return null;
            });
        }

        @Override
        public UUID activateOwnKey(String tenantId, NewOwnKeyConfiguration configuration, String activatedBy) {
            return run(() -> {
                try (PreparedStatement statement = connection.prepareStatement("INSERT INTO " + table(tenantId)
                        + " (provider, modality, status, activated_at, activated_by, own_key_kms_key_ref, "
                        + "own_key_algorithm, own_key_certificate_chain, own_key_loaded_at) "
                        + "VALUES (?, 'own_key', 'active', now(), ?, ?, ?, ?::jsonb, now()) RETURNING id")) {
                    statement.setString(1, PROVIDER_AWS_KMS);
                    statement.setString(2, activatedBy);
                    statement.setString(3, configuration.kmsKeyRef());
                    statement.setString(4, ALGORITHM_ES256);
                    statement.setString(5, chainJson(configuration.certificateChain()));
                    try (ResultSet rs = statement.executeQuery()) {
                        rs.next();
                        return rs.getObject(1, UUID.class);
                    }
                }
            });
        }

        @Override
        public void reserveSpki(byte[] spkiSha256, String tenantId, UUID configurationId) {
            run(() -> {
                try (PreparedStatement statement = connection.prepareStatement(
                        "INSERT INTO public.signing_spki_reservation "
                                + "(public_key_spki_sha256, tenant_id, signing_configuration_id) VALUES (?, ?, ?)")) {
                    statement.setBytes(1, spkiSha256);
                    statement.setString(2, tenantId);
                    statement.setObject(3, configurationId);
                    statement.executeUpdate();
                } catch (SQLException e) {
                    if (UNIQUE_VIOLATION.equals(e.getSQLState())) {
                        throw new OnboardingRejectedException(RejectionReason.KEY_IN_USE,
                                "the key was reserved by another onboarding in the meantime");
                    }
                    throw e;
                }
                return null;
            });
        }

        @Override
        public Optional<WithdrawnOwnKey> lockNextWithdrawnOwnKey(String tenantId, Duration grace, Set<UUID> excluding) {
            return run(() -> {
                try (PreparedStatement statement = connection.prepareStatement("SELECT id, own_key_kms_key_ref FROM "
                        + table(tenantId) + " WHERE modality = 'own_key' AND status = 'withdrawn' "
                        + "AND own_key_deleted_at IS NULL AND withdrawn_at < now() - make_interval(secs => ?) "
                        + "AND id <> ALL (?) ORDER BY withdrawn_at LIMIT 1 FOR UPDATE SKIP LOCKED")) {
                    statement.setDouble(1, seconds(grace));
                    statement.setArray(2, connection.createArrayOf("uuid", excluding.toArray()));
                    try (ResultSet rs = statement.executeQuery()) {
                        return rs.next()
                                ? Optional.of(new WithdrawnOwnKey(rs.getObject(1, UUID.class), tenantId, rs.getString(2)))
                                : Optional.<WithdrawnOwnKey>empty();
                    }
                }
            });
        }

        @Override
        public void markKeyStillInUse(String tenantId, WithdrawnOwnKey key) {
            run(() -> {
                markHandled(tenantId, key);
                return null;
            });
        }

        private void markHandled(String tenantId, WithdrawnOwnKey key) throws SQLException {
            try (PreparedStatement statement = connection.prepareStatement("UPDATE " + table(tenantId)
                    + " SET own_key_deleted_at = now(), updated_at = now() WHERE id = ?")) {
                statement.setObject(1, key.id());
                requireOneRow(statement.executeUpdate(), "mark the handled key");
            }
        }

        @Override
        public void markKeyRetired(String tenantId, WithdrawnOwnKey key) {
            run(() -> {
                markHandled(tenantId, key);
                // The public key stays reserved for the tenant until its key is retired. A renewal marks the old row
                // handled before it reserves the same key for the new one, which is how the reservation moves.
                try (PreparedStatement statement = connection.prepareStatement("DELETE FROM "
                        + "public.signing_spki_reservation WHERE tenant_id = ? AND signing_configuration_id = ?")) {
                    statement.setString(1, tenantId);
                    statement.setObject(2, key.id());
                    statement.executeUpdate();
                }
                return null;
            });
        }

        @Override
        public void stage(SigningConfigurationChanged event) {
            run(() -> {
                auditSink.stage(connection, event);
                staged.add(event);
                return null;
            });
        }
    }

    @FunctionalInterface
    private interface SqlWork<T> {
        T run() throws SQLException;
    }

    /** SQL failures of a transaction become an {@link OnboardingFailedException}; rejections pass through. */
    private static <T> T run(SqlWork<T> work) {
        try {
            return work.run();
        } catch (SQLException e) {
            throw databaseFailure(e);
        }
    }

    @FunctionalInterface
    private interface ConnectionWork<T> {
        T apply(Connection connection) throws SQLException;
    }

    private <T> T read(ConnectionWork<T> work) {
        try (Connection connection = open()) {
            return work.apply(connection);
        } catch (SQLException e) {
            throw databaseFailure(e);
        }
    }

    private Connection open() throws SQLException {
        return dataSource.getConnection();
    }

    private static String queryString(Connection connection, String sql, String... parameters) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            for (int i = 0; i < parameters.length; i++) {
                statement.setString(i + 1, parameters[i]);
            }
            try (ResultSet rs = statement.executeQuery()) {
                return rs.next() ? rs.getString(1) : null;
            }
        }
    }

    private String chainJson(List<String> chain) throws SQLException {
        try {
            return objectMapper.writeValueAsString(chain);
        } catch (JsonProcessingException e) {
            throw new SQLException("The certificate chain cannot be serialised", e);
        }
    }

    private static void requireOneRow(int updated, String what) {
        if (updated != 1) {
            throw new OnboardingFailedException("could not " + what + ": " + updated + " rows were updated");
        }
    }

    private static double seconds(Duration duration) {
        return duration.toMillis() / 1000.0;
    }

    private static SigningModality modalityOf(String value) {
        if (value == null) {
            return null;
        }
        return "own_key".equals(value) ? SigningModality.OWN_KEY : SigningModality.QTSP;
    }

    private static String schemaName(String tenantId) {
        if (tenantId == null || !TENANT_ID.matcher(tenantId).matches()) {
            throw new OnboardingFailedException("'" + tenantId + "' is not a valid tenant id");
        }
        return tenantId + SCHEMA_SUFFIX;
    }

    /** The schema-qualified, quoted table of a tenant. */
    private static String table(String tenantId) {
        return "\"" + schemaName(tenantId) + "\".tenant_signing_config";
    }

    /** The message is the driver's, which has no credentials: the URL and the SQL state at most. */
    private static OnboardingFailedException databaseFailure(Exception cause) {
        return new OnboardingFailedException("database error (SQLState "
                + (cause instanceof SQLException sql ? sql.getSQLState() : "n/a") + "): " + cause.getMessage(), cause);
    }
}
