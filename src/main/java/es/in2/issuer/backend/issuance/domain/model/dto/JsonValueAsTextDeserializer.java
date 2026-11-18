package es.in2.issuer.backend.issuance.domain.model.dto;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;

/**
 * Reads a field whose value the workflow checks against a closed set ({@code delivery},
 * {@code grant_type}) from any JSON value: a string as its text, anything else (a list, a number, an
 * object, a boolean) as its JSON form. None of those forms is one of the accepted values, so the
 * workflow answers its own contract error ({@code invalid_delivery_mode}, {@code invalid_grant_type})
 * instead of a {@code 400 BAD_REQUEST} on the shape of the body (EUD-254: any list is
 * {@code invalid_delivery_mode}). JSON {@code null} stays {@code null}, as an absent field.
 */
public class JsonValueAsTextDeserializer extends JsonDeserializer<String> {

    @Override
    public String deserialize(JsonParser parser, DeserializationContext context) throws IOException {
        if (parser.currentToken() == JsonToken.VALUE_STRING) {
            return parser.getText();
        }
        JsonNode value = parser.readValueAsTree();
        return value.toString();
    }
}
