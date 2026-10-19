package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.catalog.ClaimPath;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Constants.DC_SD_JWT;

/**
 * Converts the {@code subject_extraction} of a credential type file into the list paths of a catalog
 * entry (D2).
 *
 * <p>The type files hold dotted paths resolved against the <em>request payload</em>; a catalog entry
 * holds list paths resolved against the <em>credential</em> as built. With the {@code direct} strategy
 * the payload is the credential body, so the path is unchanged. Otherwise the payload sits under
 * {@code mandate} (SD-JWT) or {@code credentialSubject.mandate} (W3C) and that prefix is added -- unless
 * the path already carries it, as some fixtures do.
 */
public final class SubjectPathConverter {

    private static final String DIRECT_STRATEGY = "direct";
    private static final List<String> SD_JWT_PREFIX = List.of("mandate");
    private static final List<String> W3C_PREFIX = List.of("credentialSubject", "mandate");

    private SubjectPathConverter() {
    }

    /** One path per field of the type's {@code subject_extraction}; empty when it declares none. */
    @SuppressWarnings("deprecation")
    public static List<ClaimPath> toClaimPaths(CredentialProfile profile) {
        CredentialProfile.SubjectExtraction extraction = profile.subjectExtraction();
        if (extraction == null || extraction.fields() == null) {
            return List.of();
        }
        List<String> prefix = prefixOf(profile);
        return extraction.fields().stream()
                .map(field -> new ClaimPath(prefixed(prefix, Arrays.asList(field.split("\\.")))))
                .toList();
    }

    private static List<String> prefixOf(CredentialProfile profile) {
        if (DIRECT_STRATEGY.equals(profile.credentialSubjectStrategy())) {
            return List.of();
        }
        return DC_SD_JWT.equals(profile.format()) ? SD_JWT_PREFIX : W3C_PREFIX;
    }

    /**
     * Adds only the part of the prefix the path lacks: a path already starting with the whole prefix
     * is kept; one starting at {@code mandate} in a W3C type only lacks {@code credentialSubject}.
     */
    private static List<String> prefixed(List<String> prefix, List<String> path) {
        for (int skipped = 0; skipped < prefix.size(); skipped++) {
            List<String> carried = prefix.subList(skipped, prefix.size());
            if (path.size() > carried.size() && path.subList(0, carried.size()).equals(carried)) {
                List<String> result = new ArrayList<>(prefix.subList(0, skipped));
                result.addAll(path);
                return result;
            }
        }
        List<String> result = new ArrayList<>(prefix);
        result.addAll(path);
        return result;
    }
}
