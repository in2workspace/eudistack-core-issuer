package es.in2.issuer.backend.shared.infrastructure.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.issuer.backend.shared.domain.service.IssuancePayloadNormalizer;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
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
    private static final String REASON_NULL = "null";
    private static final String REASON_EMPTY = "empty";

    private final PayloadSubschemaResolver payloadSubschemaResolver;
    private final IssuanceMetrics issuanceMetrics;

    @Override
    public JsonNode normalize(String credentialConfigurationId, JsonNode payload) {
        if (payload == null || !payload.isObject()) {
            return payload;
        }
        return payloadSubschemaResolver.resolve(credentialConfigurationId)
                .map(subschema -> {
                    JsonNode copy = payload.deepCopy();
                    normalizeObject((ObjectNode) copy, subschema.schema(), "$", credentialConfigurationId);
                    return copy;
                })
                .orElse(payload);
    }

    private void normalizeObject(ObjectNode node, JsonNode schema, String path, String credentialConfigurationId) {
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

            // Only the first matching branch applies: a property typed ["string", "object"] holding an
            // object is not walked. No shipped profile declares such a union, and neither does it
            // resolve $ref / allOf; extend this when the first one appears.
            if (hasType(rule, STRING) && isNullOrEmptyText(value)) {
                removeIfNotKeptByRequired(node, name, value, required.contains(name), propertyPath, credentialConfigurationId);
            } else if (hasType(rule, OBJECT) && value.isObject()) {
                normalizeObject((ObjectNode) value, rule, propertyPath, credentialConfigurationId);
            } else if (hasType(rule, ARRAY) && value.isArray()) {
                normalizeArrayItems((ArrayNode) value, rule.path(ITEMS), propertyPath, credentialConfigurationId);
            }
        }
    }

    private void normalizeArrayItems(ArrayNode array, JsonNode itemSchema, String path, String credentialConfigurationId) {
        if (!itemSchema.isObject() || !itemSchema.path(PROPERTIES).isObject()) {
            return;
        }
        for (int index = 0; index < array.size(); index++) {
            if (array.get(index).isObject()) {
                normalizeObject((ObjectNode) array.get(index), itemSchema, path + "[" + index + "]", credentialConfigurationId);
            }
        }
    }

    // A required property that is null is dropped so the schema reports it as missing; a required
    // empty string is left alone, since the profile schema accepts it and it is not ours to reject.
    private void removeIfNotKeptByRequired(ObjectNode node, String name, JsonNode value, boolean required,
                                           String path, String credentialConfigurationId) {
        if (required && !value.isNull()) {
            return;
        }
        node.remove(name);
        String reason = value.isNull() ? REASON_NULL : REASON_EMPTY;
        log.debug("Removed {} from the issuance payload at {}", reason, path);
        // Array positions are dropped from the tag: $.power[0].domain and $.power[7].domain are the same property.
        issuanceMetrics.recordOptionalStringRemoved(credentialConfigurationId, path.replaceAll("\\[\\d+]", "[]"), reason);
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
