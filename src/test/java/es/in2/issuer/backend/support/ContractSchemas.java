package es.in2.issuer.backend.support;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SchemaValidatorsConfig;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Validates JSON documents against the {@code components.schemas} of the Attestation Catalogue API contract
 * ({@code contract/attestation-catalog-schemas.yaml}, a verbatim copy of the contract's block).
 *
 * <p>The contract is OpenAPI 3.1, whose schemas are JSON Schema 2020-12: it is the dialect used here, and the
 * one that gives {@code unevaluatedProperties} (which {@code CatalogEntryCreate} relies on to reject unknown
 * attributes) its meaning. Format assertions are switched on, because 2020-12 treats {@code format} as an
 * annotation by default, and the contract's {@code uri}, {@code uri-reference} and {@code date-time} would then
 * check nothing. Each schema is validated through a root that only adds a {@code $ref} to
 * {@code #/components/schemas/<name>}, so the contract's own references resolve untouched.
 */
public final class ContractSchemas {

    private static final String RESOURCE = "/contract/attestation-catalog-schemas.yaml";

    private static final JsonSchemaFactory FACTORY = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012);
    private static final SchemaValidatorsConfig CONFIG = SchemaValidatorsConfig.builder()
            .formatAssertionsEnabled(true)
            .build();
    private static final YAMLMapper YAML = new YAMLMapper();
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Map<String, JsonSchema> SCHEMAS = new ConcurrentHashMap<>();

    private ContractSchemas() {
    }

    /** The violations of {@code json} against the contract schema {@code schemaName}; empty when it conforms. */
    public static Set<ValidationMessage> validate(String schemaName, String json) {
        try {
            return schema(schemaName).validate(JSON.readTree(json));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static void assertConforms(String schemaName, String json) {
        assertThat(validate(schemaName, json))
                .as("%s against the contract schema %s", json, schemaName)
                .isEmpty();
    }

    private static JsonSchema schema(String schemaName) {
        return SCHEMAS.computeIfAbsent(schemaName, name -> {
            try (InputStream in = ContractSchemas.class.getResourceAsStream(RESOURCE)) {
                ObjectNode root = (ObjectNode) YAML.readTree(in);
                assertThat(root.at("/components/schemas/" + name).isObject())
                        .as("the contract defines the schema %s", name).isTrue();
                root.put("$schema", "https://json-schema.org/draft/2020-12/schema");
                root.put("$ref", "#/components/schemas/" + name);
                return FACTORY.getSchema(root, CONFIG);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });
    }
}
