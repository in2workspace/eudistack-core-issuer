package es.in2.issuer.backend.shared.domain.util.sdjwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds an SD-JWT VC payload from a stored flat credential JSON.
 * The input credential is already in SD-JWT flat format (built by GenericCredentialBuilder),
 * with iss, sub, iat, exp, vct, and claims at top level.
 * This builder creates selective disclosures and produces the final unsigned payload.
 */
@Component
@RequiredArgsConstructor
public class SdJwtPayloadBuilder {

    private final ObjectMapper objectMapper;

    /**
     * Builds an SD-JWT payload from a flat credential JSON and profile.
     *
     * @param decodedCredentialJson the flat SD-JWT credential (with iss, sub, mandate, etc. at top level)
     * @param profile               the credential profile (must have sdJwt config)
     * @param cnf                   the holder key binding (cnf claim), may be null
     * @return SdJwtComponents containing the unsigned payload JSON and the list of disclosures
     */
    public SdJwtComponents build(String decodedCredentialJson, CredentialProfile profile, Map<String, Object> cnf) {
        try {
            JsonNode credential = objectMapper.readTree(decodedCredentialJson);
            CredentialProfile.SdJwtConfig sdJwtConfig = profile.sdJwt();

            if (sdJwtConfig == null) {
                throw new IllegalArgumentException("Profile does not have sd_jwt configuration");
            }

            // Build disclosures for each sd_claim directly from the flat credential
            List<Disclosure> disclosures = new ArrayList<>();
            List<String> sdDigests = new ArrayList<>();

            for (String claimName : sdJwtConfig.sdClaims()) {
                JsonNode claimNode = credential.path(claimName);
                if (!claimNode.isMissingNode()) {
                    Object claimValue = objectMapper.convertValue(claimNode, Object.class);
                    Disclosure disclosure = Disclosure.create(claimName, claimValue);
                    disclosures.add(disclosure);
                    sdDigests.add(disclosure.digest());
                }
            }

            // Build the final payload: copy standard claims, replace sd_claims with _sd digests
            Map<String, Object> payload = new LinkedHashMap<>();

            // Standard JWT claims from the flat credential
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
                payload.put("_sd_alg", sdJwtConfig.sdAlg());
                payload.put("_sd", sdDigests);
            }

            // Copy status if present
            JsonNode statusNode = credential.path("status");
            if (!statusNode.isMissingNode()) {
                payload.put("status", objectMapper.convertValue(statusNode, Object.class));
            }

            // Add cnf (key binding)
            if (cnf != null && !cnf.isEmpty()) {
                payload.put("cnf", cnf);
            }

            String payloadJson = objectMapper.writeValueAsString(payload);
            return new SdJwtComponents(payloadJson, disclosures);

        } catch (Exception e) {
            throw new RuntimeException("Failed to build SD-JWT payload", e);
        }
    }

    /** Value object returned by build(). */
    public record SdJwtComponents(String payloadJson, List<Disclosure> disclosures) {}
}
