package es.in2.issuer.backend.shared.domain.model.audit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * The identity document of the holder of an attestation, read from its credential data set for the
 * {@code holder} block of an audit event (AC-13). It goes only to the encrypted audit store, never to a log.
 *
 * <p>The claims are tried in this order, wherever they sit in the data set (the root of an SD-JWT one, under
 * {@code credentialSubject} in a W3C one): {@code document_number}, {@code personal_administrative_number}
 * and {@code mandatee.employeeId}. What counts as the document of each attestation type is still for product
 * to define; until then an attestation with none of them has no document.
 */
public final class HolderDocument {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final List<String> CLAIMS =
            List.of("document_number", "personal_administrative_number", "mandatee.employeeId");

    /**
     * Branches of the data set that describe someone other than the holder: the document of the mandator or of
     * the signer must never be reported as the document of the person the attestation is for.
     */
    private static final java.util.Set<String> OTHER_PARTIES = java.util.Set.of("mandator", "signer", "issuer");

    private HolderDocument() {
    }

    public static Optional<String> of(String credentialDataSet) {
        if (credentialDataSet == null || credentialDataSet.isBlank()) {
            return Optional.empty();
        }
        try {
            JsonNode root = OBJECT_MAPPER.readTree(credentialDataSet);
            return CLAIMS.stream()
                    .map(claim -> find(root, "", claim))
                    .flatMap(Optional::stream)
                    .findFirst();
        } catch (IOException _) {
            return Optional.empty();
        }
    }

    /** The first non-blank text whose dotted path is {@code claim} or ends with it, outside the other parties' branches. */
    private static Optional<String> find(JsonNode node, String path, String claim) {
        if (node.isObject()) {
            for (var fields = node.fields(); fields.hasNext(); ) {
                var field = fields.next();
                if (OTHER_PARTIES.contains(field.getKey())) {
                    continue;
                }
                String childPath = path.isEmpty() ? field.getKey() : path + "." + field.getKey();
                Optional<String> found = find(field.getValue(), childPath, claim);
                if (found.isPresent()) {
                    return found;
                }
            }
            return Optional.empty();
        }
        if (node.isTextual() && !node.asText().isBlank() && (path.equals(claim) || path.endsWith("." + claim))) {
            return Optional.of(node.asText());
        }
        return Optional.empty();
    }
}
