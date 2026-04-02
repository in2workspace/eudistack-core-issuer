package es.in2.issuer.backend.shared.domain.util.sdjwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Builds an SD-JWT VC payload from a stored credential JSON.
 * Supports nested sd_claims using dot-notation (e.g., "mandate.mandatee").
 * When sd_claims share a common parent (e.g., "mandate"), the _sd digests
 * are placed inside that parent object rather than at the top level.
 */
@Component
@RequiredArgsConstructor
public class SdJwtPayloadBuilder {

    private final ObjectMapper objectMapper;

    public SdJwtComponents build(String decodedCredentialJson, CredentialProfile profile, Map<String, Object> cnf) {
        try {
            JsonNode credential = objectMapper.readTree(decodedCredentialJson);
            CredentialProfile.SdJwtConfig sdJwtConfig = profile.sdJwt();

            if (sdJwtConfig == null) {
                throw new IllegalArgumentException("Profile does not have sd_jwt configuration");
            }

            List<Disclosure> disclosures = new ArrayList<>();
            List<String> sdDigests = new ArrayList<>();

            // Group sd_claims by parent: "mandate.mandatee" → parent="mandate", leaf="mandatee"
            String commonParent = detectCommonParent(sdJwtConfig.sdClaims());

            for (String claimPath : sdJwtConfig.sdClaims()) {
                JsonNode claimNode = navigatePath(credential, claimPath);
                if (!claimNode.isMissingNode()) {
                    // Disclosure name is the leaf (e.g., "mandatee" from "mandate.mandatee")
                    String leafName = claimPath.contains(".")
                            ? claimPath.substring(claimPath.lastIndexOf('.') + 1)
                            : claimPath;
                    Object claimValue = objectMapper.convertValue(claimNode, Object.class);
                    Disclosure disclosure = Disclosure.create(leafName, claimValue);
                    disclosures.add(disclosure);
                    sdDigests.add(disclosure.digest());
                }
            }

            // Build the final payload
            Map<String, Object> payload = new LinkedHashMap<>();

            payload.put("iss", credential.path("iss").asText(""));
            String sub = credential.path("sub").asText(null);
            if (sub != null && !sub.isBlank()) {
                payload.put("sub", sub);
            }
            payload.put("iat", credential.path("iat").asLong());
            payload.put("nbf", credential.path("nbf").asLong());
            payload.put("exp", credential.path("exp").asLong());
            payload.put("vct", credential.path("vct").asText());

            if (!sdDigests.isEmpty()) {
                Map<String, Object> sdContainer = new LinkedHashMap<>();
                sdContainer.put("_sd_alg", sdJwtConfig.sdAlg());
                sdContainer.put("_sd", sdDigests);

                if (commonParent != null) {
                    // Nested: place _sd inside the parent object (e.g., "mandate")
                    payload.put(commonParent, sdContainer);
                } else {
                    // Flat: place _sd at top level
                    payload.put("_sd_alg", sdJwtConfig.sdAlg());
                    payload.put("_sd", sdDigests);
                }
            }

            // Copy status if present
            JsonNode statusNode = credential.path("status");
            if (!statusNode.isMissingNode()) {
                payload.put("status", objectMapper.convertValue(statusNode, Object.class));
            }

            // Add cnf (key binding) only when required by the profile
            if (profile.cnfRequired() && cnf != null && !cnf.isEmpty()) {
                payload.put("cnf", cnf);
            }

            String payloadJson = objectMapper.writeValueAsString(payload);
            return new SdJwtComponents(payloadJson, disclosures);

        } catch (Exception e) {
            throw new RuntimeException("Failed to build SD-JWT payload", e);
        }
    }

    /**
     * Detects if all sd_claims share a common parent prefix.
     * E.g., ["mandate.mandatee", "mandate.mandator", "mandate.power"] → "mandate"
     * Returns null if claims are top-level or have different parents.
     */
    private String detectCommonParent(List<String> sdClaims) {
        if (sdClaims == null || sdClaims.isEmpty()) return null;

        String firstParent = null;
        for (String claim : sdClaims) {
            int dot = claim.indexOf('.');
            if (dot < 0) return null; // Top-level claim, no common parent
            String parent = claim.substring(0, dot);
            if (firstParent == null) {
                firstParent = parent;
            } else if (!firstParent.equals(parent)) {
                return null; // Different parents
            }
        }
        return firstParent;
    }

    private JsonNode navigatePath(JsonNode root, String dotPath) {
        String[] segments = dotPath.split("\\.");
        JsonNode current = root;
        for (String segment : segments) {
            if (current == null || current.isMissingNode()) {
                return MissingNode.getInstance();
            }
            current = current.path(segment);
        }
        return current;
    }

    /** Value object returned by build(). */
    public record SdJwtComponents(String payloadJson, List<Disclosure> disclosures) {}
}
