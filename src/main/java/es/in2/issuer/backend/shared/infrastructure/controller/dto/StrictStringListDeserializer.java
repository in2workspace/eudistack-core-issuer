package es.in2.issuer.backend.shared.infrastructure.controller.dto;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * A {@code ClaimPath} of the Attestation Catalogue contract inside a list of them ({@code subject.fields}):
 * a JSON array of strings, each one read with {@link StrictStringDeserializer}. A failing item keeps its
 * index in the path of the error, so the violation names it ({@code subject.fields[0][1]}).
 */
final class StrictStringListDeserializer extends StdDeserializer<List<String>> {

    private static final StrictStringDeserializer ITEM = new StrictStringDeserializer();

    StrictStringListDeserializer() {
        super(List.class);
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<String> deserialize(JsonParser parser, DeserializationContext context) throws IOException {
        if (!parser.isExpectedStartArrayToken()) {
            return (List<String>) context.handleUnexpectedToken(List.class, parser);
        }
        List<String> items = new ArrayList<>();
        for (JsonToken token = parser.nextToken(); token != JsonToken.END_ARRAY; token = parser.nextToken()) {
            try {
                items.add(token == JsonToken.VALUE_NULL ? null : ITEM.deserialize(parser, context));
            } catch (JsonMappingException e) {
                throw JsonMappingException.wrapWithPath(e, items, items.size());
            }
        }
        return items;
    }
}
