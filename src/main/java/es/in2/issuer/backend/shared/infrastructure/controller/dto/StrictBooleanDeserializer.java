package es.in2.issuer.backend.shared.infrastructure.controller.dto;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import java.io.IOException;

/**
 * A {@code boolean} of the Attestation Catalogue contract: only the JSON literals {@code true} and
 * {@code false}. Jackson's own coercion would also take {@code "true"}, {@code "false"} and, for some
 * settings, numbers. A JSON {@code null} never reaches this class: the member stays {@code null}.
 *
 * <p>Applied member by member with {@code @JsonDeserialize}, so the global mapper stays as it is.
 */
final class StrictBooleanDeserializer extends StdDeserializer<Boolean> {

    StrictBooleanDeserializer() {
        super(Boolean.class);
    }

    @Override
    public Boolean deserialize(JsonParser parser, DeserializationContext context) throws IOException {
        JsonToken token = parser.currentToken();
        if (token == JsonToken.VALUE_TRUE) {
            return Boolean.TRUE;
        }
        if (token == JsonToken.VALUE_FALSE) {
            return Boolean.FALSE;
        }
        return (Boolean) context.handleUnexpectedToken(Boolean.class, parser);
    }
}
