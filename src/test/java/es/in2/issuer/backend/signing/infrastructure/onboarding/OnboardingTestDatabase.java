package es.in2.issuer.backend.signing.infrastructure.onboarding;

import org.flywaydb.core.Flyway;
import org.testcontainers.containers.PostgreSQLContainer;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * A real Postgres for the onboarding integration tests, started once per JVM (the Testcontainers singleton
 * pattern). It holds what the platform provisions around the Issuer ({@code public.tenant_registry}) and what
 * the Issuer migrates itself: {@code public.signing_spki_reservation} and the schema of each tenant, with the
 * same Flyway settings as {@code TenantSchemaFlywayMigrator}.
 */
final class OnboardingTestDatabase {

    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    private static final List<String> MIGRATED_TENANTS = List.of("cgcom", "kpmg", "dormant");

    static {
        POSTGRES.start();
        try (Connection connection = open(); Statement statement = connection.createStatement()) {
            statement.execute("CREATE TABLE public.tenant_registry (schema_name VARCHAR(64) PRIMARY KEY, "
                    + "display_name VARCHAR(255) NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'active')");
            statement.execute("INSERT INTO public.tenant_registry (schema_name, display_name, status) VALUES "
                    + "('cgcom', 'CGCOM', 'active'), ('kpmg', 'KPMG', 'active'), ('dormant', 'Dormant', 'inactive'), "
                    + "('ghost', 'Registered but never migrated', 'active')");
        } catch (SQLException e) {
            throw new IllegalStateException("Could not provision the tenant registry", e);
        }
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/public").defaultSchema("public").schemas("public").createSchemas(false)
                .table("flyway_issuer_public_history").baselineOnMigrate(true).baselineVersion("0").load().migrate();
        for (String tenant : MIGRATED_TENANTS) {
            String schema = tenant + "_issuer";
            Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                    .locations("classpath:db/tenant").defaultSchema(schema).schemas(schema).createSchemas(true)
                    .table("flyway_schema_history").baselineOnMigrate(true).load().migrate();
        }
    }

    private OnboardingTestDatabase() {}

    static Connection open() throws SQLException {
        return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }

    static JdbcOwnKeyStore store(SigningConfigurationAuditSink sink) {
        return new JdbcOwnKeyStore(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword(), sink);
    }

    /** Empties the signing configurations of the tenants and the reservations. */
    static void reset() {
        execute("TRUNCATE cgcom_issuer.tenant_signing_config, kpmg_issuer.tenant_signing_config, "
                + "dormant_issuer.tenant_signing_config, public.signing_spki_reservation");
    }

    static void execute(String sql, Object... parameters) {
        try (Connection connection = open(); PreparedStatement statement = connection.prepareStatement(sql)) {
            bind(statement, parameters);
            statement.execute();
        } catch (SQLException e) {
            throw new IllegalStateException("Could not run " + sql, e);
        }
    }

    /** The rows of a query, each as a list of its columns. */
    static List<List<Object>> query(String sql, Object... parameters) {
        try (Connection connection = open(); PreparedStatement statement = connection.prepareStatement(sql)) {
            bind(statement, parameters);
            List<List<Object>> rows = new ArrayList<>();
            try (ResultSet rs = statement.executeQuery()) {
                int columns = rs.getMetaData().getColumnCount();
                while (rs.next()) {
                    List<Object> row = new ArrayList<>();
                    for (int i = 1; i <= columns; i++) {
                        row.add(rs.getObject(i));
                    }
                    rows.add(row);
                }
            }
            return rows;
        } catch (SQLException e) {
            throw new IllegalStateException("Could not run " + sql, e);
        }
    }

    static Object scalar(String sql, Object... parameters) {
        List<List<Object>> rows = query(sql, parameters);
        return rows.isEmpty() ? null : rows.getFirst().getFirst();
    }

    private static void bind(PreparedStatement statement, Object[] parameters) throws SQLException {
        for (int i = 0; i < parameters.length; i++) {
            statement.setObject(i + 1, parameters[i]);
        }
    }
}
