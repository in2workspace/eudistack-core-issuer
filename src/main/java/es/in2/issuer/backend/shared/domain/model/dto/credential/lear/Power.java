package es.in2.issuer.backend.shared.domain.model.dto.credential.lear;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.Builder;

import java.util.List;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public record Power(
        @JsonProperty("action") @JsonAlias("tmf_action") Object action,
        @JsonProperty("domain") @JsonAlias("tmf_domain") String domain,
        @JsonProperty("function") @JsonAlias("tmf_function") String function,
        @JsonProperty("type") @JsonAlias("tmf_type") String type
) {

    private static final List<String> FIELDS = List.of("action", "domain", "function", "type");
    private static final String ALIAS_PREFIX = "tmf_";

    /**
     * Whether a field and its {@code tmf_} alias say different things. Jackson resolves each field on its
     * own, the last key wins, so such a power can be read as a combination of both sets of keys that no
     * rule ever decided: it is rejected at issuance and does not count in a token.
     */
    public static boolean hasConflictingAlias(JsonNode power) {
        return FIELDS.stream().anyMatch(field -> {
            JsonNode plain = power.get(field);
            JsonNode alias = power.get(ALIAS_PREFIX + field);
            return plain != null && alias != null && !plain.equals(alias);
        });
    }

    /**
     * The same power with each field under one key. Jackson fails when a key arrives once it has every
     * field of the record, so a power with both keys would be readable or not depending on their order.
     */
    public static JsonNode withoutAliases(JsonNode power) {
        if (!(power instanceof ObjectNode object)) {
            return power;
        }
        ObjectNode copy = object.deepCopy();
        for (String field : FIELDS) {
            JsonNode alias = copy.remove(ALIAS_PREFIX + field);
            if (alias != null && !copy.has(field)) {
                copy.set(field, alias);
            }
        }
        return copy;
    }
}