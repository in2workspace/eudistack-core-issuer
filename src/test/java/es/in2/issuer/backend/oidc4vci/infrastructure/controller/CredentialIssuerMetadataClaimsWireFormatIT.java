package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.CREDENTIAL_ISSUER_METADATA_WELL_KNOWN_PATH;

/**
 * End-to-end coverage of the claims description objects on
 * `/.well-known/openid-credential-issuer`: boots the real Spring context against a real
 * Postgres (Testcontainers), loads a real credential profile from disk through
 * {@code CredentialProfileRegistry}, and asserts the wire JSON carries the OID4VCI 1.0 Final
 * Appendix B.1 members only.
 *
 * <p>The fixture profile deliberately still declares `value_map`: a profile may carry members
 * the spec does not define, but they must not reach the published metadata — the OIDF
 * conformance suite reports any such member as an unexpected metadata field.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class CredentialIssuerMetadataClaimsWireFormatIT {

    private static final String TENANT = "labeltest";
    private static final String CONFIGURATION_ID = "gx.labelcredential.w3c.2";

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
        registry.add("credential.profiles.path", () -> "classpath:it-value-map-profiles");
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
                    VALUES ('%s', 'Label Test Tenant', 'multi_org', 'active')
                    ON CONFLICT (schema_name) DO NOTHING
                    """.formatted(TENANT));
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to seed tenant_registry for IT", e);
        }
    }

    private static Connection jdbcConnection() throws SQLException {
        return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }

    @LocalServerPort
    private int port;

    private WebTestClient webTestClient;

    @BeforeEach
    void setUp() throws SQLException {
        // spring.webflux.base-path defaults to /issuer (application.yml) and applies to every
        // route once the full context is up — unlike the @WebFluxTest controller slice, which
        // binds directly to the router without that prefix.
        webTestClient = WebTestClient.bindToServer().baseUrl("http://localhost:" + port + "/issuer").build();
        enableCredentialConfigurationForTenant();
    }

    // The tenant catalog is deny-by-default (CredentialIssuerMetadataServiceImpl advertises
    // nothing until the tenant's tenant_credential_profile table has an enabled row) — the
    // schema/table only exist after TenantSchemaFlywayMigrator has run them against our seeded
    // tenant, which happens during context startup, ahead of this @BeforeEach.
    private void enableCredentialConfigurationForTenant() throws SQLException {
        try (Connection conn = jdbcConnection(); Statement stmt = conn.createStatement()) {
            stmt.execute(("""
                    INSERT INTO %s%s.tenant_credential_profile (credential_configuration_id, enabled)
                    VALUES ('%s', true)
                    ON CONFLICT (credential_configuration_id) DO UPDATE SET enabled = true
                    """).formatted(TENANT, SCHEMA_SUFFIX, CONFIGURATION_ID));
        }
    }

    @Test
    void getCredentialIssuerMetadata_forProfileWithNonSpecClaimMembers_publishesOnlySpecMembers() {
        String claim = "$.credential_configurations_supported['" + CONFIGURATION_ID
                + "'].credential_metadata.claims[0]";

        webTestClient.get()
                .uri(CREDENTIAL_ISSUER_METADATA_WELL_KNOWN_PATH)
                .header(X_TENANT_HEADER, TENANT)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.credential_configurations_supported['" + CONFIGURATION_ID + "']").exists()
                .jsonPath(claim + ".path").exists()
                .jsonPath(claim + ".display").exists()
                .jsonPath(claim + ".value_map").doesNotExist();
    }

}
