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

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.regex.Pattern;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;

/**
 * {@link OwnKeyStorePort} over plain JDBC (the tool is not a Spring application). Every statement of a
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

    private final String url;
    private final String user;
    private final String password;
    private final SigningConfigurationAuditSink auditSink;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public JdbcOwnKeyStore(String url, String user, String password, SigningConfigurationAuditSink auditSink) {
        this.url = url;
        this.user = user;
        this.password = password;
        this.auditSink = auditSink;
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

    /** Looks in the schema of every tenant that has a signing configuration table, not only the registered ones. */
    @Override
    public boolean isKeyReferenced(String kmsKeyRef, boolean activeOnly) {
        return read(connection -> {
            List<String> schemas = new ArrayList<>();
            try (PreparedStatement statement = connection.prepareStatement("SELECT table_schema FROM "
                    + "information_schema.tables WHERE table_name = 'tenant_signing_config'");
                 ResultSet rs = statement.executeQuery()) {
                while (rs.next()) {
                    String schema = rs.getString(1);
                    if (!schema.endsWith(SCHEMA_SUFFIX)) {
                        continue;
                    }
                    String tenant = schema.substring(0, schema.length() - SCHEMA_SUFFIX.length());
                    if (TENANT_ID.matcher(tenant).matches()) {
                        schemas.add(tenant);
                    }
                }
            }
            if (schemas.isEmpty()) {
                return false;
            }
            String where = " WHERE own_key_kms_key_ref = ?" + (activeOnly ? " AND status = 'active'" : "");
            String union = String.join(" UNION ALL ", schemas.stream()
                    .map(tenant -> "SELECT 1 FROM " + table(tenant) + where).toList());
            try (PreparedStatement statement = connection.prepareStatement("SELECT EXISTS (" + union + ")")) {
                for (int i = 1; i <= schemas.size(); i++) {
                    statement.setString(i, kmsKeyRef);
                }
                try (ResultSet rs = statement.executeQuery()) {
                    return rs.next() && rs.getBoolean(1);
                }
            }
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

    @Override
    public <T> T inTransaction(Function<ConfigurationTransaction, T> work) {
        try (Connection connection = open()) {
            connection.setAutoCommit(false);
            JdbcConfigurationTransaction transaction = new JdbcConfigurationTransaction(connection);
            T result;
            try {
                result = work.apply(transaction);
            } catch (RuntimeException e) {
                rollback(connection, e);
                throw e;
            }
            commit(connection);
            transaction.staged.forEach(this::publish);
            return result;
        } catch (SQLException e) {
            throw databaseFailure(e);
        }
    }

    @Override
    public void recordInOwnTransaction(SigningConfigurationChanged event) {
        try (Connection connection = open()) {
            connection.setAutoCommit(false);
            try {
                auditSink.stage(connection, event);
            } catch (SQLException | RuntimeException e) {
                rollback(connection, e);
                throw e;
            }
            connection.commit();
            publish(event);
        } catch (SQLException e) {
            throw databaseFailure(e);
        }
    }

    /**
     * A failure of the commit itself leaves the outcome unknown (the server may have committed before the
     * connection broke), which the caller must not treat as a rollback.
     */
    private static void commit(Connection connection) {
        try {
            connection.commit();
        } catch (SQLException e) {
            throw new CommitOutcomeUnknownException("the database did not confirm the commit (SQLState "
                    + e.getSQLState() + "): " + e.getMessage(), e);
        }
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
        private final List<SigningConfigurationChanged> staged = new ArrayList<>();

        private JdbcConfigurationTransaction(Connection connection) {
            this.connection = connection;
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
                if (configuration.modality() == SigningModality.OWN_KEY) {
                    try (PreparedStatement statement = connection.prepareStatement("DELETE FROM "
                            + "public.signing_spki_reservation WHERE tenant_id = ? AND signing_configuration_id = ?")) {
                        statement.setString(1, tenantId);
                        statement.setObject(2, configuration.id());
                        statement.executeUpdate();
                    }
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
        public void markKeyRetired(String tenantId, WithdrawnOwnKey key) {
            run(() -> {
                try (PreparedStatement statement = connection.prepareStatement("UPDATE " + table(tenantId)
                        + " SET own_key_deleted_at = now(), updated_at = now() WHERE id = ?")) {
                    statement.setObject(1, key.id());
                    requireOneRow(statement.executeUpdate(), "mark the retired key");
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
        return DriverManager.getConnection(url, user, password);
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

    private static void rollback(Connection connection, Exception cause) {
        try {
            connection.rollback();
        } catch (SQLException e) {
            cause.addSuppressed(e);
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
