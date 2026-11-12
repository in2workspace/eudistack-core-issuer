package es.in2.issuer.backend.shared.infrastructure.controller.dto;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import java.io.IOException;

/**
 * An {@code integer} of the Attestation Catalogue contract: only a JSON number without fraction or
 * exponent that fits in an {@code int}. Jackson's own coercion would also take {@code "30"} and truncate
 * {@code 30.5}. A JSON {@code null} never reaches this class: the member stays {@code null}.
 *
 * <p>Applied member by member with {@code @JsonDeserialize}, so the global mapper stays as it is.
 */
final class StrictIntegerDeserializer extends StdDeserializer<Integer> {

    StrictIntegerDeserializer() {
        super(Integer.class);
    }

    @Override
    public Integer deserialize(JsonParser parser, DeserializationContext context) throws IOException {
        if (parser.currentToken() == JsonToken.VALUE_NUMBER_INT && parser.getNumberType() == JsonParser.NumberType.INT) {
            return parser.getIntValue();
        }
        return (Integer) context.handleUnexpectedToken(Integer.class, parser);
    }
}
