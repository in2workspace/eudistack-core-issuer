package es.in2.issuer.backend.support;

import com.networknt.schema.ValidationMessage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The contract validation of the catalog ITs is only worth something if it can fail: this proves the setup
 * (dialect 2020-12, {@code $ref} resolution, {@code unevaluatedProperties}, format assertions) rejects what
 * the contract forbids.
 */
class ContractSchemasTest {

    private static final String VALID_ENTRY = """
            {
              "credential_configuration_id": "doctorid.sd.1",
              "schema_uri": "https://registry.eudistack.net/schemas/doctorid/1.0.0/dc+sd-jwt",
              "enabled": true,
              "delivery_modes": ["email", "ui"],
              "validity": { "default_days": 36500, "requester_can_set_dates": false },
              "subject": { "fields": [["givenName"], ["familyName"]], "separator": " " },
              "search_identifiers": [ { "name": "colegiado", "field": ["personal_administrative_number"] } ],
              "created": "2026-10-19T08:00:00Z",
              "updated": "2026-10-19T08:00:00+02:00"
            }""";

    private static final String VALID_CREATE = """
            {
              "schema_uri": "https://registry.eudistack.net/schemas/doctorid/1.0.0/dc+sd-jwt",
              "enabled": true,
              "delivery_modes": ["email", "ui"],
              "validity": { "default_days": 36500, "requester_can_set_dates": false }
            }""";

    private static final String VALID_PROBLEM = """
            {
              "type": "field_not_in_schema",
              "title": "Bad Request",
              "status": 400,
              "detail": "Field [nationalId] is not in the schema",
              "instance": "/issuer/api/v1/attestation-catalog",
              "violations": [ { "field": "search_identifiers[1].field", "message": "not in the schema" } ]
            }""";

    @Test
    void validDocuments_conform() {
        ContractSchemas.assertConforms("CatalogEntry", VALID_ENTRY);
        ContractSchemas.assertConforms("CatalogEntryCreate", VALID_CREATE);
        ContractSchemas.assertConforms("Problem", VALID_PROBLEM);
    }

    @Test
    void referencedSchemas_areResolved_soAnInvalidClaimPathInsideAnEntryFails() {
        String emptyPath = VALID_ENTRY.replace("[\"givenName\"], [\"familyName\"]", "[], [\"familyName\"]");

        assertThat(ContractSchemas.validate("CatalogEntry", emptyPath)).isNotEmpty();
    }

    @Test
    void entryWithoutARequiredMember_fails() {
        assertThat(ContractSchemas.validate("CatalogEntry", VALID_ENTRY.replace("\"enabled\": true,", ""))).isNotEmpty();
        assertThat(ContractSchemas.validate("CatalogEntry",
                VALID_ENTRY.replace("\"credential_configuration_id\": \"doctorid.sd.1\",", ""))).isNotEmpty();
    }

    @Test
    void create_withAnUnknownTopLevelField_fails_becauseOfUnevaluatedProperties() {
        Set<ValidationMessage> violations =
                ContractSchemas.validate("CatalogEntryCreate", VALID_CREATE.replace("\"enabled\": true,",
                        "\"enabled\": true, \"surprise\": 1,"));

        assertThat(violations).isNotEmpty().anySatisfy(v -> assertThat(v.getMessage()).contains("surprise"));
    }

    @Test
    void createWithTheKnownFieldsOfTheEmbeddedSchemas_isNotRejectedByUnevaluatedProperties() {
        // schema_uri comes from the first allOf branch, the rest from the referenced configuration.
        assertThat(ContractSchemas.validate("CatalogEntryCreate", VALID_CREATE)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"not a uri", "relative/path", ""})
    void schemaUri_mustBeAUri(String schemaUri) {
        String entry = VALID_ENTRY.replace("https://registry.eudistack.net/schemas/doctorid/1.0.0/dc+sd-jwt", schemaUri);

        assertThat(ContractSchemas.validate("CatalogEntry", entry)).as("format uri is asserted").isNotEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"yesterday", "2026-10-19", "2026-10-19T08:00:00"})
    void created_mustBeADateTimeWithOffset(String created) {
        String entry = VALID_ENTRY.replace("2026-10-19T08:00:00Z", created);

        assertThat(ContractSchemas.validate("CatalogEntry", entry)).as("format date-time is asserted").isNotEmpty();
    }

    @Test
    void problemInstance_mustBeAUriReference() {
        String problem = VALID_PROBLEM.replace("/issuer/api/v1/attestation-catalog", "http://[bad");

        assertThat(ContractSchemas.validate("Problem", problem)).as("format uri-reference is asserted").isNotEmpty();
    }

    @Test
    void problemWithoutATitle_fails() {
        assertThat(ContractSchemas.validate("Problem", VALID_PROBLEM.replace("\"title\": \"Bad Request\",", ""))).isNotEmpty();
    }

    @Test
    void anUnknownSchemaName_isAnError() {
        assertThatThrownBy(() -> ContractSchemas.validate("Nope", "{}"))
                .isInstanceOf(AssertionError.class);
    }
}
