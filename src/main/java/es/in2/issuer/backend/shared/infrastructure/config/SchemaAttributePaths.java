package es.in2.issuer.backend.shared.infrastructure.config;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.shared.domain.model.catalog.ClaimPath;

import java.util.ArrayList;
import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Constants.DC_SD_JWT;

/**
 * Derives the attribute paths a credential type's schema ({@code properties} of its type file)
 * describes. Objects are traversed down to their leaves; an array, or an object that declares no
 * {@code properties}, is a leaf. SD-JWT schemas describe only the data, so every path counts. W3C
 * schemas describe the whole credential, so only the paths under {@code credentialSubject} count:
 * the envelope ({@code issuer}, {@code credentialStatus}, {@code validFrom}, ...) is not part of
 * what a catalog entry can point at. The legacy W3C types ({@code learcredential.employee.w3c.2/3},
 * {@code learcredential.machine.w3c.1/2}) describe the credential under a top-level {@code vc}
 * instead of {@code properties}; their {@code credentialSubject} is read from there.
 */
final class SchemaAttributePaths {

    private static final String CREDENTIAL_SUBJECT = "credentialSubject";
    private static final String PROPERTIES = "properties";
    private static final String LEGACY_VC = "vc";

    private SchemaAttributePaths() {
    }

    static List<ClaimPath> of(JsonNode rawProfile, String format) {
        JsonNode properties = rawProfile.path(PROPERTIES);
        List<String> prefix = List.of();
        if (!DC_SD_JWT.equals(format)) {
            JsonNode credentialSubject = properties.path(CREDENTIAL_SUBJECT);
            if (credentialSubject.isMissingNode()) {
                credentialSubject = rawProfile.path(LEGACY_VC).path(CREDENTIAL_SUBJECT);
            }
            properties = credentialSubject.path(PROPERTIES);
            prefix = List.of(CREDENTIAL_SUBJECT);
        }
        List<ClaimPath> paths = new ArrayList<>();
        collectLeaves(properties, prefix, paths);
        return List.copyOf(paths);
    }

    private static void collectLeaves(JsonNode properties, List<String> prefix, List<ClaimPath> paths) {
        properties.fields().forEachRemaining(property -> {
            List<String> path = new ArrayList<>(prefix);
            path.add(property.getKey());
            JsonNode nested = property.getValue().path(PROPERTIES);
            if (nested.isObject() && !nested.isEmpty()) {
                collectLeaves(nested, path, paths);
            } else {
                paths.add(new ClaimPath(path));
            }
        });
    }
}
