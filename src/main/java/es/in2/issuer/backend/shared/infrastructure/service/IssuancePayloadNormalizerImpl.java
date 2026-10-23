package es.in2.issuer.backend.shared.infrastructure.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.issuer.backend.shared.domain.service.IssuancePayloadNormalizer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class IssuancePayloadNormalizerImpl implements IssuancePayloadNormalizer {

    private static final String TYPE = "type";
    private static final String PROPERTIES = "properties";
    private static final String REQUIRED = "required";
    private static final String ITEMS = "items";
    private static final String STRING = "string";
    private static final String OBJECT = "object";
    private static final String ARRAY = "array";

    private final PayloadSubschemaResolver payloadSubschemaResolver;

    @Override
    public JsonNode normalize(String credentialConfigurationId, JsonNode payload) {
        if (payload == null || !payload.isObject()) {
            return payload;
        }
        return payloadSubschemaResolver.resolve(credentialConfigurationId)
                .map(subschema -> {
                    JsonNode copy = payload.deepCopy();
                    normalizeObject((ObjectNode) copy, subschema.schema(), "$");
                    return copy;
                })
                .orElse(payload);
    }

    private void normalizeObject(ObjectNode node, JsonNode schema, String path) {
        JsonNode properties = schema.path(PROPERTIES);
        if (!properties.isObject()) {
            return;
        }
        Set<String> required = requiredNames(schema);

        for (Map.Entry<String, JsonNode> property : properties.properties()) {
            String name = property.getKey();
            JsonNode rule = property.getValue();
            JsonNode value = node.get(name);
            if (value == null) {
                continue;
            }
            String propertyPath = path + "." + name;

            if (hasType(rule, STRING) && isNullOrEmptyText(value)) {
                removeIfNotKeptByRequired(node, name, value, required.contains(name), propertyPath);
            } else if (hasType(rule, OBJECT) && value.isObject()) {
                normalizeObject((ObjectNode) value, rule, propertyPath);
            } else if (hasType(rule, ARRAY) && value.isArray()) {
                normalizeArrayItems((ArrayNode) value, rule.path(ITEMS), propertyPath);
            }
        }
    }

    private void normalizeArrayItems(ArrayNode array, JsonNode itemSchema, String path) {
        if (!itemSchema.isObject() || !itemSchema.path(PROPERTIES).isObject()) {
            return;
        }
        for (int index = 0; index < array.size(); index++) {
            if (array.get(index).isObject()) {
                normalizeObject((ObjectNode) array.get(index), itemSchema, path + "[" + index + "]");
            }
        }
    }

    // A required property that is null is dropped so the schema reports it as missing; a required
    // empty string is left alone, since the profile schema accepts it and it is not ours to reject.
    private void removeIfNotKeptByRequired(ObjectNode node, String name, JsonNode value, boolean required, String path) {
        if (required && !value.isNull()) {
            return;
        }
        node.remove(name);
        log.debug("Removed {} from the issuance payload at {}", value.isNull() ? "null" : "empty", path);
    }

    private static boolean isNullOrEmptyText(JsonNode value) {
        return value.isNull() || (value.isTextual() && value.asText().isEmpty());
    }

    private static Set<String> requiredNames(JsonNode schema) {
        Set<String> names = new HashSet<>();
        schema.path(REQUIRED).forEach(name -> names.add(name.asText()));
        return names;
    }

    private static boolean hasType(JsonNode rule, String type) {
        JsonNode declared = rule.path(TYPE);
        if (declared.isTextual()) {
            return type.equals(declared.asText());
        }
        if (declared.isArray()) {
            for (JsonNode candidate : declared) {
                if (type.equals(candidate.asText())) {
                    return true;
                }
            }
        }
        return false;
    }
}
