package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialBuildResult;
import es.in2.issuer.backend.statuslist.domain.util.factory.IssuerFactory;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class GenericCredentialBuilder {

    private final ObjectMapper objectMapper;
    private final IssuerFactory issuerFactory;
    private final AccessTokenService accessTokenService;

    private static final String DC_SD_JWT = "dc+sd-jwt";

    /**
     * Builds an unsigned credential from a profile definition and input payload.
     * Dispatches by format: W3C VCDM for jwt_vc_json/cwt_vc, flat structure for dc+sd-jwt.
     * No issuer/cnf/credentialStatus — those are injected at signing time.
     */
    public Mono<CredentialBuildResult> buildCredential(
            CredentialProfile profile,
            JsonNode payload) {

        Instant now = Instant.now();
        String validFrom;
        String validUntil;

        if (profile.validityDays() > 0) {
            validFrom = now.toString();
            validUntil = now.plus(profile.validityDays(), ChronoUnit.DAYS).toString();
        } else {
            validFrom = payload.has("validFrom") ? payload.get("validFrom").asText() : now.toString();
            validUntil = payload.has("validUntil") ? payload.get("validUntil").asText()
                    : now.plus(365, ChronoUnit.DAYS).toString();
        }

        String credentialJson;
        if (DC_SD_JWT.equals(profile.format()) && profile.sdJwt() != null) {
            credentialJson = buildSdJwtFlatCredential(profile, payload, validFrom, validUntil);
        } else {
            credentialJson = buildW3cCredential(profile, payload, validFrom, validUntil);
        }

        if (credentialJson == null) {
            return Mono.error(new IllegalStateException("Failed to serialize credential"));
        }

        String subject = extractSubject(profile, payload);

        return extractOrganizationIdentifier(profile, payload)
                .map(orgId -> CredentialBuildResult.builder()
                        .credentialDataSet(credentialJson)
                        .subject(subject)
                        .organizationIdentifier(orgId)
                        .validFrom(Timestamp.from(parseInstant(validFrom)))
                        .validUntil(Timestamp.from(parseInstant(validUntil)))
                        .build());
    }

    /**
     * Builds a W3C VCDM credential structure.
     * Used for jwt_vc_json and cwt_vc formats.
     * No credentialStatus — injected at signing time via injectCredentialStatus().
     */
    private String buildW3cCredential(CredentialProfile profile, JsonNode payload,
                                       String validFrom, String validUntil) {
        ObjectNode credential = objectMapper.createObjectNode();

        credential.set("@context", objectMapper.valueToTree(profile.credentialDefinition().context()));
        credential.put("id", "urn:uuid:" + UUID.randomUUID());
        credential.set("type", objectMapper.valueToTree(profile.credentialDefinition().type()));

        if (profile.description() != null) {
            credential.put("description", profile.description());
        }

        ObjectNode credentialSubjectNode;
        if ("direct".equals(profile.credentialSubjectStrategy())) {
            JsonNode cs = payload.get("credentialSubject");
            credentialSubjectNode = (cs != null) ? cs.deepCopy() : payload.deepCopy();
        } else {
            credentialSubjectNode = objectMapper.createObjectNode();
            credentialSubjectNode.set("mandate", payload);
        }
        // W3C VCDM 2.0: credentialSubject.id is required for jwt_vc_json
        credentialSubjectNode.put("id", "urn:uuid:" + UUID.randomUUID());
        credential.set("credentialSubject", credentialSubjectNode);

        credential.put("validFrom", validFrom);
        credential.put("validUntil", validUntil);

        try {
            return objectMapper.writeValueAsString(credential);
        } catch (Exception e) {
            log.error("Failed to serialize W3C credential", e);
            return null;
        }
    }

    /**
     * Builds a flat SD-JWT VC structure directly.
     * No W3C wrapper — payload claims go at top level.
     * Structure: {vct, iss(placeholder), iat, nbf, exp, mandator, mandatee, power, validFrom, validUntil}
     * No status — injected at signing time via injectCredentialStatus().
     */
    private String buildSdJwtFlatCredential(CredentialProfile profile, JsonNode payload,
                                             String validFrom, String validUntil) {
        ObjectNode credential = objectMapper.createObjectNode();

        credential.put("vct", profile.sdJwt().vct());

        // iss is a placeholder — bound later by bindIssuer
        credential.put("iss", "");

        long iat = parseDateToUnixTime(validFrom);
        long exp = parseDateToUnixTime(validUntil);
        credential.put("iat", iat);
        credential.put("nbf", iat);
        credential.put("exp", exp);

        // Payload goes directly at top level (e.g., "mandator", "mandatee", "power")
        if ("direct".equals(profile.credentialSubjectStrategy())) {
            payload.properties().forEach(entry -> credential.set(entry.getKey(), entry.getValue()));
        } else {
            credential.set("mandate", payload);
        }

        // Store validFrom/validUntil as metadata for later use
        credential.put("validFrom", validFrom);
        credential.put("validUntil", validUntil);

        try {
            return objectMapper.writeValueAsString(credential);
        } catch (Exception e) {
            log.error("Failed to serialize SD-JWT flat credential", e);
            return null;
        }
    }

    /**
     * Creates and binds an Issuer to the decoded credential.
     * Format-aware: W3C sets issuer object, SD-JWT sets iss string.
     */
    public Mono<String> bindIssuer(CredentialProfile profile, String decodedCredentialJson,
                                   String issuanceId, String email) {
        return switch (profile.issuerType()) {
            case DETAILED -> issuerFactory.createDetailedIssuer()
                    .flatMap(issuer -> setIssuerField(profile, decodedCredentialJson, issuer));
            case SIMPLE -> issuerFactory.createSimpleIssuer()
                    .flatMap(issuer -> setIssuerField(profile, decodedCredentialJson, issuer));
        };
    }

    private Mono<String> setIssuerField(CredentialProfile profile, String decodedCredentialJson, Object issuer) {
        try {
            ObjectNode credential = (ObjectNode) objectMapper.readTree(decodedCredentialJson);
            JsonNode issuerNode = objectMapper.valueToTree(issuer);

            if (DC_SD_JWT.equals(profile.format())) {
                // SD-JWT: iss is a string (the issuer DID)
                String issuerId = extractIssuerIdFromNode(issuerNode);
                credential.put("iss", issuerId);
            } else {
                // W3C: issuer is an object
                if (issuerNode.isObject()) {
                    ((ObjectNode) issuerNode).remove("id");
                }
                credential.set("issuer", issuerNode);
            }

            return Mono.just(objectMapper.writeValueAsString(credential));
        } catch (Exception e) {
            return Mono.error(new IllegalStateException("Failed to bind issuer", e));
        }
    }

    private String extractIssuerIdFromNode(JsonNode issuerNode) {
        if (issuerNode.isTextual()) return issuerNode.asText();
        if (issuerNode.has("organizationIdentifier")) {
            return issuerNode.get("organizationIdentifier").asText();
        }
        if (issuerNode.has("id")) return issuerNode.get("id").asText();
        return "";
    }

    /**
     * Injects credentialStatus into an already-built credential JSON.
     * Format-aware: W3C sets "credentialStatus" object, SD-JWT sets "status.status_list".
     */
    public String injectCredentialStatus(String credentialJson, CredentialStatus status, String format) {
        try {
            ObjectNode credential = (ObjectNode) objectMapper.readTree(credentialJson);

            if (DC_SD_JWT.equals(format)) {
                int idx = Integer.parseInt(status.statusListIndex());
                credential.set("status", objectMapper.valueToTree(
                        Map.of("status_list", Map.of("uri", status.statusListCredential(), "idx", idx))));
            } else {
                credential.set("credentialStatus", objectMapper.valueToTree(status));
            }

            return objectMapper.writeValueAsString(credential);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to inject credentialStatus", e);
        }
    }

    /**
     * Builds a generic JWT payload for signing.
     * Structure: {jti, iss, sub, iat, exp, nbf, vc, cnf?}
     */
    public Mono<String> buildJwtPayload(CredentialProfile profile, String decodedCredentialJson,
                                        Map<String, Object> cnf) {
        return Mono.fromCallable(() -> {
            JsonNode credential = objectMapper.readTree(decodedCredentialJson);

            if (profile.cnfRequired()) {
                if (cnf == null || cnf.isEmpty()) {
                    throw new IllegalStateException("Missing cnf (expected kid/jwk/x5c)");
                }
                validateCnfShape(cnf);
            }

            String issuerId = extractIssuerId(credential);
            String subjectId = extractSubjectId(credential);
            String validFrom = credential.get("validFrom").asText();
            String validUntil = credential.get("validUntil").asText();

            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("jti", UUID.randomUUID().toString());
            payload.put("sub", subjectId);
            payload.put("nbf", parseDateToUnixTime(validFrom));
            payload.put("iss", issuerId);
            payload.put("exp", parseDateToUnixTime(validUntil));
            payload.put("iat", parseDateToUnixTime(validFrom));
            payload.put("vc", objectMapper.readValue(decodedCredentialJson, Object.class));

            if (profile.cnfRequired() && cnf != null && !cnf.isEmpty()) {
                payload.put("cnf", cnf);
            }

            return objectMapper.writeValueAsString(payload);
        });
    }

    private String extractSubject(CredentialProfile profile, JsonNode payload) {
        CredentialProfile.SubjectExtraction extraction = profile.subjectExtraction();
        if (extraction == null || extraction.fields() == null || extraction.fields().isEmpty()) {
            return "";
        }

        List<String> values = extraction.fields().stream()
                .map(field -> resolveFieldValue(payload, field))
                .filter(v -> v != null && !v.isBlank())
                .toList();

        if ("concat".equals(extraction.strategy())) {
            String separator = extraction.separator() != null ? extraction.separator() : " ";
            return String.join(separator, values);
        }

        // "field" strategy — return first value
        return values.isEmpty() ? "" : values.getFirst();
    }

    private Mono<String> extractOrganizationIdentifier(CredentialProfile profile, JsonNode payload) {
        CredentialProfile.OrganizationExtraction extraction = profile.organizationExtraction();
        if (extraction == null) {
            return Mono.just("");
        }

        if ("session".equals(extraction.strategy())) {
            return accessTokenService.getOrganizationIdFromCurrentSession();
        }

        // "field" strategy
        String value = resolveFieldValue(payload, extraction.field());
        return Mono.just(value != null ? value : "");
    }

    private String resolveFieldValue(JsonNode node, String fieldPath) {
        if (node == null || fieldPath == null) {
            return null;
        }

        String[] parts = fieldPath.split("\\.");
        JsonNode current = node;
        for (String part : parts) {
            if (current == null || !current.has(part)) {
                return null;
            }
            current = current.get(part);
        }
        return current != null && current.isTextual() ? current.asText() : null;
    }

    private String extractIssuerId(JsonNode credential) {
        JsonNode issuer = credential.get("issuer");
        if (issuer == null) {
            // SD-JWT: iss is set directly at top level
            JsonNode iss = credential.get("iss");
            return iss != null && iss.isTextual() ? iss.asText() : "";
        }
        if (issuer.isTextual()) {
            return issuer.asText();
        }
        if (issuer.has("organizationIdentifier")) {
            return issuer.get("organizationIdentifier").asText();
        }
        if (issuer.has("id")) {
            return issuer.get("id").asText();
        }
        return "";
    }

    private String extractSubjectId(JsonNode credential) {
        JsonNode subject = credential.path("credentialSubject").path("id");
        if (!subject.isMissingNode() && subject.isTextual()) {
            return subject.asText();
        }
        return "";
    }

    private void validateCnfShape(Map<String, Object> cnf) {
        boolean hasKid = cnf.containsKey("kid");
        boolean hasJwk = cnf.containsKey("jwk");
        boolean hasX5c = cnf.containsKey("x5c");

        int count = (hasKid ? 1 : 0) + (hasJwk ? 1 : 0) + (hasX5c ? 1 : 0);
        if (count != 1) {
            throw new IllegalStateException("Invalid cnf (expected exactly one of kid/jwk/x5c)");
        }
    }

    private long parseDateToUnixTime(String date) {
        try {
            return ZonedDateTime.parse(date, DateTimeFormatter.ISO_ZONED_DATE_TIME).toInstant().getEpochSecond();
        } catch (Exception e) {
            return Instant.parse(date).getEpochSecond();
        }
    }

    private Instant parseInstant(String date) {
        try {
            return ZonedDateTime.parse(date, DateTimeFormatter.ISO_ZONED_DATE_TIME).toInstant();
        } catch (Exception e) {
            return Instant.parse(date);
        }
    }

}
