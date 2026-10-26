package es.in2.issuer.backend.shared.domain.model.audit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The names of the attributes a credential data set carries, as dotted paths and without their values.
 * Only the claims count: the envelope of the credential (identifiers, validity, issuer, status, holder
 * key) is left out, and so is the subject identifier the Issuer generates.
 */
public final class IssuedAttributeNames {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String W3C_SUBJECT = "credentialSubject";
    private static final String SUBJECT_ID = "id";
    private static final Set<String> SD_JWT_ENVELOPE =
            Set.of("vct", "iss", "iat", "nbf", "exp", "validFrom", "validUntil", "cnf", "status");

    private IssuedAttributeNames() {
    }

    public static List<String> of(String credentialDataSet) {
        if (credentialDataSet == null || credentialDataSet.isBlank()) {
            return List.of();
        }
        try {
            JsonNode root = OBJECT_MAPPER.readTree(credentialDataSet);
            Set<String> names = new LinkedHashSet<>();
            if (root.has(W3C_SUBJECT)) {
                collect(root.get(W3C_SUBJECT), "", Set.of(SUBJECT_ID), names);
            } else {
                collect(root, "", SD_JWT_ENVELOPE, names);
            }
            return new ArrayList<>(names);
        } catch (IOException _) {
            return List.of();
        }
    }

    private static void collect(JsonNode node, String path, Set<String> skipped, Set<String> names) {
        if (node.isObject()) {
            node.fields().forEachRemaining(field -> {
                if (!skipped.contains(field.getKey())) {
                    collect(field.getValue(), path.isEmpty() ? field.getKey() : path + "." + field.getKey(), Set.of(), names);
                }
            });
        } else if (node.isArray() && node.size() > 0 && node.get(0).isObject()) {
            node.forEach(element -> collect(element, path, Set.of(), names));
        } else if (!path.isEmpty()) {
            names.add(path);
        }
    }
}
