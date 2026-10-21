package es.in2.issuer.backend.shared.infrastructure.controller.dto;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import java.io.IOException;

/**
 * A {@code string} of the Attestation Catalogue contract: only a JSON string. Jackson's own coercion would
 * also take a number or a boolean and turn it into its text ({@code 1} into {@code "1"}). A JSON
 * {@code null} never reaches this class: the member stays {@code null}.
 *
 * <p>Applied member by member with {@code @JsonDeserialize}, so the global mapper stays as it is.
 */
final class StrictStringDeserializer extends StdDeserializer<String> {

    StrictStringDeserializer() {
        super(String.class);
    }

    @Override
    public String deserialize(JsonParser parser, DeserializationContext context) throws IOException {
        if (parser.currentToken() == JsonToken.VALUE_STRING) {
            return parser.getText();
        }
        return (String) context.handleUnexpectedToken(String.class, parser);
    }
}
