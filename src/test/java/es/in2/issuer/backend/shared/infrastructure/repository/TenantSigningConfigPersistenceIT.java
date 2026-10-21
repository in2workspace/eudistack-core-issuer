package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.shared.domain.service.TenantSigningConfigService;
import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * EUD-289 B2: the active signing configuration is read from a real Postgres with the V15
 * schema (JSONB chain, TIMESTAMPTZ columns, status filter).
 */
class TenantSigningConfigPersistenceIT extends PostgresIntegrationBase {

    private static final String TENANT = "e2e";
    private static final String TABLE = "\"" + TENANT + SCHEMA_SUFFIX + "\".tenant_signing_config";

    @Autowired
    private TenantSigningConfigRepository repository;

    @Autowired
    private TenantSigningConfigService service;

    @BeforeEach
    @AfterEach
    void cleanTable() {
        exec("DELETE FROM " + TABLE);
    }

    private void exec(String sql) {
        databaseClient.sql(sql).then().block();
    }

    private void insertWithdrawnQtsp() {
        exec("INSERT INTO " + TABLE + " (provider, csc_api_version, provider_specific_config, status, withdrawn_at, "
                + "created_at) VALUES ('old', 'v2', '{\"url\":\"https://old.test\"}'::jsonb, 'withdrawn', now(), "
                + "now() + interval '1 hour')");
    }

    private void insertActiveOwnKey() {
        exec("INSERT INTO " + TABLE + " (provider, modality, status, own_key_kms_key_ref, own_key_algorithm, "
                + "own_key_certificate_chain, own_key_cert_subject, own_key_cert_not_before, own_key_cert_not_after, "
                + "own_key_spki_sha256) VALUES ('aws-kms', 'own_key', 'active', "
                + "'arn:aws:kms:eu-west-1:111122223333:key/k', 'ES256', '[\"MIIB-leaf\",\"MIIB-int\"]'::jsonb, "
                + "'CN=leaf', '2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z', '" + "b".repeat(64) + "')");
    }

    @Test
    void findActive_ignoresWithdrawnRowsEvenIfNewer() {
        insertWithdrawnQtsp();
        insertActiveOwnKey();

        var row = repository.findFirstByStatusOrderByCreatedAtDesc("active")
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT))
                .block();

        assertThat(row).isNotNull();
        assertThat(row.modality()).isEqualTo("own_key");
        assertThat(row.status()).isEqualTo("active");
    }

    @Test
    void findActive_withOnlyWithdrawnRows_isEmpty() {
        insertWithdrawnQtsp();

        var row = repository.findFirstByStatusOrderByCreatedAtDesc("active")
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT))
                .block();

        assertThat(row).isNull();
    }

    @Test
    void getActiveSigningConfig_ownKeyRow_roundTripsChainAndTimestamps() {
        insertWithdrawnQtsp();
        insertActiveOwnKey();

        var config = service.getActiveSigningConfig()
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT))
                .block();

        assertThat(config).isNotNull();
        assertThat(config.modality()).isEqualTo(SigningModality.OWN_KEY);
        assertThat(config.ownKey().certificateChain()).containsExactly("MIIB-leaf", "MIIB-int");
        assertThat(config.ownKey().certificateNotBefore()).hasToString("2026-01-01T00:00:00Z");
        assertThat(config.ownKey().certificateNotAfter()).hasToString("2027-01-01T00:00:00Z");
        assertThat(config.ownKey().spkiSha256()).isEqualTo("b".repeat(64));
    }
}
