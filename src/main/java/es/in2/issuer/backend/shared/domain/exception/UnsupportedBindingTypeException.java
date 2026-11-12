package es.in2.issuer.backend.shared.domain.exception;

import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;

import java.util.List;

/**
 * The credential type requires a holder binding other than {@code key} or {@code none}
 * (HTTP 400 {@code unsupported_binding_type}).
 */
public class UnsupportedBindingTypeException extends CatalogConfigurationException {

    public UnsupportedBindingTypeException(String schemaUri) {
        super(GlobalErrorTypes.UNSUPPORTED_BINDING_TYPE.getCode(),
                "The schema '" + schemaUri + "' requires claim or biometric binding; only key and none are supported",
                List.of(new Violation("schema_uri", "requires an unsupported binding type")));
    }
}
