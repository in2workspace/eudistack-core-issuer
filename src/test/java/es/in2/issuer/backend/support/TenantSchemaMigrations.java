package es.in2.issuer.backend.support;

import org.flywaydb.core.Flyway;
import org.springframework.boot.autoconfigure.flyway.FlywayProperties;
import org.springframework.boot.autoconfigure.r2dbc.R2dbcProperties;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;

/**
 * Drives the tenant Flyway migrations by hand for an unregistered tenant schema, so an IT can
 * stop at a given version, seed data, and migrate on -- or simply get a fully migrated schema
 * of its own that no other IT touches.
 */
public final class TenantSchemaMigrations {

    private TenantSchemaMigrations() {
    }

    public static String schemaOf(String tenant) {
        return tenant + SCHEMA_SUFFIX;
    }

    /** Creates the schema if needed and migrates it up to {@code targetVersion} ({@code null} = latest). */
    public static void migrate(FlywayProperties flywayProperties, R2dbcProperties r2dbcProperties,
                               String tenant, String targetVersion) {
        String schema = schemaOf(tenant);
        var configuration = Flyway.configure()
                .dataSource(flywayProperties.getUrl(), r2dbcProperties.getUsername(), r2dbcProperties.getPassword())
                .locations("classpath:db/tenant")
                .defaultSchema(schema)
                .schemas(schema)
                .createSchemas(true)
                .table("flyway_schema_history");
        if (targetVersion != null) {
            configuration.target(targetVersion);
        }
        configuration.load().migrate();
    }
}
