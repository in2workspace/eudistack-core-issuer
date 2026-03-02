package es.in2.issuer.backend.shared.domain.util.sdjwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds an SD-JWT VC payload from a stored W3C VC JSON credential.
 * The W3C VC JSON is the decoded credential (pre-signing) that was built
 * by GenericCredentialBuilder and stored in the credential procedure.
 * This builder converts it to the flat SD-JWT payload structure per SD-JWT VC draft-14.
 */
@Component
@RequiredArgsConstructor
public class SdJwtPayloadBuilder {

    private final ObjectMapper objectMapper;

    /**
     * Builds an SD-JWT payload from a W3C VC JSON credential and profile.
     *
     * @param decodedCredentialJson the W3C VC JSON (with issuer, credentialSubject.id, etc. already bound)
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

            // Extract standard JWT claims from the W3C VC
            String issuer = extractIssuerId(credential);
            String subject = extractSubjectId(credential);
            long iat = parseDateToUnixTime(credential.path("validFrom").asText());
            long exp = parseDateToUnixTime(credential.path("validUntil").asText());

            // Build disclosures for each sd_claim (e.g., "mandate")
            JsonNode credentialSubject = credential.path("credentialSubject");
            List<Disclosure> disclosures = new ArrayList<>();
            List<String> sdDigests = new ArrayList<>();

            for (String claimName : sdJwtConfig.sdClaims()) {
                JsonNode claimNode = credentialSubject.path(claimName);
                if (!claimNode.isMissingNode()) {
                    Object claimValue = objectMapper.convertValue(claimNode, Object.class);
                    Disclosure disclosure = Disclosure.create(claimName, claimValue);
                    disclosures.add(disclosure);
                    sdDigests.add(disclosure.digest());
                }
            }

            // Build the flat SD-JWT payload
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("iss", issuer);
            if (subject != null && !subject.isBlank()) {
                payload.put("sub", subject);
            }
            payload.put("iat", iat);
            payload.put("nbf", iat);
            payload.put("exp", exp);
            payload.put("vct", sdJwtConfig.vct());

            if (!sdDigests.isEmpty()) {
                payload.put("_sd_alg", sdJwtConfig.sdAlg());
                payload.put("_sd", sdDigests);
            }

            // Map credentialStatus → status_list
            JsonNode statusNode = credential.path("credentialStatus");
            if (!statusNode.isMissingNode()) {
                String statusListUri = statusNode.path("statusListCredential").asText(null);
                int statusListIdx = statusNode.path("statusListIndex").asInt(-1);
                if (statusListUri != null && statusListIdx >= 0) {
                    payload.put("status", Map.of("status_list",
                            Map.of("uri", statusListUri, "idx", statusListIdx)));
                }
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

    private String extractIssuerId(JsonNode credential) {
        JsonNode issuer = credential.path("issuer");
        if (issuer.isTextual()) return issuer.asText();
        if (issuer.isObject()) return issuer.path("id").asText("");
        return "";
    }

    private String extractSubjectId(JsonNode credential) {
        JsonNode id = credential.path("credentialSubject").path("id");
        if (!id.isMissingNode() && id.isTextual()) return id.asText();
        // Fallback for machine credentials
        JsonNode mandateeId = credential.path("credentialSubject").path("mandate").path("mandatee").path("id");
        if (!mandateeId.isMissingNode() && mandateeId.isTextual()) return mandateeId.asText();
        return null;
    }

    private long parseDateToUnixTime(String date) {
        if (date == null || date.isBlank()) return Instant.now().getEpochSecond();
        try {
            return ZonedDateTime.parse(date, DateTimeFormatter.ISO_ZONED_DATE_TIME).toInstant().getEpochSecond();
        } catch (Exception e) {
            return Instant.parse(date).getEpochSecond();
        }
    }

    /** Value object returned by build(). */
    public record SdJwtComponents(String payloadJson, List<Disclosure> disclosures) {}
}
