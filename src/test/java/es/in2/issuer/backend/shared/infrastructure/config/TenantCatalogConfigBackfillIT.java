package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.catalog.ClaimPath;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.spi.CatalogEntryPort;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import reactor.util.context.Context;

import java.util.List;
import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs {@link TenantCatalogConfigBackfill} against two tenant schemas seeded the way platform-dev
 * seeds them (only the {@code credential_configuration_id}), with the credential types of
 * {@code src/test/resources/catalog-profiles}. The runner itself fires at start-up on empty tables;
 * the tests seed afterwards and invoke it directly.
 */
class TenantCatalogConfigBackfillIT extends PostgresIntegrationBase {

    private static final String TENANT_A = "e2e-tenant-a";
    private static final String TENANT_B = "e2e-tenant-b";

    @DynamicPropertySource
    static void useCatalogProfiles(DynamicPropertyRegistry registry) {
        registry.add("credential.profiles.path", () -> "classpath:catalog-profiles");
    }

    @Autowired private TenantCatalogConfigBackfill backfill;
    @Autowired private CatalogEntryPort port;

    @BeforeEach
    void seedBothTenants() {
        clearCatalog(TENANT_A);
        clearCatalog(TENANT_B);
        seed(TENANT_A, "doctorid.sd.1", null);
        seed(TENANT_A, "learcredential.employee.sd.1", "email");
        seed(TENANT_B, "learcredential.employee.w3c.4", null);
        seed(TENANT_B, "gx.labelcredential.w3c.2", null);
        seed(TENANT_B, "removed.type.1", null);
    }

    @AfterEach
    void clearBothTenants() {
        clearCatalog(TENANT_A);
        clearCatalog(TENANT_B);
    }

    @Test
    void backfillAllTenants_fillsTheSchemaOfEachTenant() {
        Integer filled = backfill.backfillAllTenants().block();

        assertThat(filled).isEqualTo(4);

        CatalogEntry doctorId = entry(TENANT_A, "doctorid.sd.1");
        assertThat(doctorId.schemaUri()).isEqualTo("https://registry.eudistack.net/schemas/doctorid/1.0.0/dc+sd-jwt");
        assertThat(doctorId.deliveryModes()).containsExactlyInAnyOrder(DeliveryMode.EMAIL, DeliveryMode.UI);
        assertThat(doctorId.validity()).isEqualTo(new CatalogEntry.Validity(36500, false, null));
        assertThat(doctorId.subject().fields()).containsExactly(ClaimPath.of("givenName"), ClaimPath.of("familyName"));
        assertThat(doctorId.version()).isEqualTo(1);

        CatalogEntry lear = entry(TENANT_A, "learcredential.employee.sd.1");
        assertThat(lear.schemaUri()).isNull();
        assertThat(lear.deliveryModes()).as("a stored value is kept").containsExactly(DeliveryMode.EMAIL);
        assertThat(lear.subject().fields()).containsExactly(
                ClaimPath.of("mandate", "mandatee", "firstName"), ClaimPath.of("mandate", "mandatee", "lastName"));

        CatalogEntry w3c = entry(TENANT_B, "learcredential.employee.w3c.4");
        assertThat(w3c.subject().fields()).containsExactly(
                ClaimPath.of("credentialSubject", "mandate", "mandatee", "firstName"),
                ClaimPath.of("credentialSubject", "mandate", "mandatee", "lastName"));

        CatalogEntry gx = entry(TENANT_B, "gx.labelcredential.w3c.2");
        assertThat(gx.deliveryModes()).containsExactlyInAnyOrder(DeliveryMode.values());
        assertThat(gx.subject().fields()).containsExactly(ClaimPath.of("credentialSubject", "id"));
    }

    @Test
    void backfillAllTenants_doesNotMixTenantsAndLeavesTypesWithoutFileUnfilled() {
        backfill.backfillAllTenants().block();

        assertThat(ids(TENANT_A)).containsExactlyInAnyOrder("doctorid.sd.1", "learcredential.employee.sd.1");
        assertThat(ids(TENANT_B)).containsExactlyInAnyOrder(
                "learcredential.employee.w3c.4", "gx.labelcredential.w3c.2", "removed.type.1");
        assertThat(entry(TENANT_B, "removed.type.1").isFilled()).isFalse();
    }

    @Test
    void backfillAllTenants_aSecondRunChangesNothing() {
        backfill.backfillAllTenants().block();
        Map<String, Object> afterFirst = snapshot();

        Integer filledAgain = backfill.backfillAllTenants().block();

        assertThat(filledAgain).isZero();
        assertThat(snapshot()).isEqualTo(afterFirst);
    }

    // ---- helpers ---------------------------------------------------------------

    private CatalogEntry entry(String tenant, String ccid) {
        return port.findById(ccid).contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, tenant)).block();
    }

    private List<CatalogEntry> entries(String tenant) {
        return port.findAll().collectList().contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, tenant)).block();
    }

    private List<String> ids(String tenant) {
        return entries(tenant).stream().map(CatalogEntry::credentialConfigurationId).toList();
    }

    private Map<String, Object> snapshot() {
        return Map.of(TENANT_A, entries(TENANT_A), TENANT_B, entries(TENANT_B));
    }

    private void seed(String tenant, String ccid, String deliveryModes) {
        databaseClient.sql("INSERT INTO \"" + tenant + SCHEMA_SUFFIX + "\".tenant_credential_profile "
                        + "(credential_configuration_id, delivery_modes) VALUES ('" + ccid + "', "
                        + (deliveryModes == null ? "NULL" : "'" + deliveryModes + "'") + ")")
                .then().block();
    }

    private void clearCatalog(String tenant) {
        databaseClient.sql("DELETE FROM \"" + tenant + SCHEMA_SUFFIX + "\".tenant_credential_profile")
                .then().block();
    }
}
