package es.in2.issuer.backend.shared.domain.exception;

import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;

import java.util.List;

/** The schema URI does not resolve to any credential type loaded in the issuer (HTTP 400 {@code unknown_schema}). */
public class UnknownSchemaException extends CatalogConfigurationException {

    public UnknownSchemaException(String schemaUri) {
        super(GlobalErrorTypes.UNKNOWN_SCHEMA.getCode(),
                "The schema '" + schemaUri + "' does not exist or is not available to the tenant",
                List.of(new Violation("schema_uri", "is not a known schema")));
    }
}
