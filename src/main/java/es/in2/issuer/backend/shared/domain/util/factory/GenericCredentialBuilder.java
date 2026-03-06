package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
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
     */
    public Mono<CredentialProcedureCreationRequest> buildCredential(
            CredentialProfile profile,
            String procedureId,
            JsonNode payload,
            CredentialStatus credentialStatus,
            String email) {

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
            credentialJson = buildSdJwtFlatCredential(profile, payload, credentialStatus, validFrom, validUntil);
        } else {
            credentialJson = buildW3cCredential(profile, payload, credentialStatus, validFrom, validUntil);
        }

        if (credentialJson == null) {
            return Mono.error(new IllegalStateException("Failed to serialize credential"));
        }

        String subject = extractSubject(profile, payload);

        return extractOrganizationIdentifier(profile, payload)
                .map(orgId -> CredentialProcedureCreationRequest.builder()
                        .procedureId(procedureId)
                        .organizationIdentifier(orgId)
                        .credentialDataSet(credentialJson)
                        .credentialType(profile.credentialConfigurationId())
                        .subject(subject)
                        .validUntil(Timestamp.from(parseInstant(validUntil)))
                        .email(email)
                        .build());
    }

    /**
     * Builds a W3C VCDM credential structure.
     * Used for jwt_vc_json and cwt_vc formats.
     */
    private String buildW3cCredential(CredentialProfile profile, JsonNode payload,
                                       CredentialStatus credentialStatus,
                                       String validFrom, String validUntil) {
        ObjectNode credential = objectMapper.createObjectNode();

        credential.set("@context", objectMapper.valueToTree(profile.credentialDefinition().context()));
        credential.put("id", "urn:uuid:" + UUID.randomUUID());
        credential.set("type", objectMapper.valueToTree(profile.credentialDefinition().type()));

        if (profile.description() != null) {
            credential.put("description", profile.description());
        }

        JsonNode credentialSubjectNode;
        if ("direct".equals(profile.credentialSubjectStrategy())) {
            JsonNode cs = payload.get("credentialSubject");
            credentialSubjectNode = (cs != null) ? cs : payload;
        } else {
            ObjectNode mandateWrapper = objectMapper.createObjectNode();
            mandateWrapper.set("mandate", payload);
            credentialSubjectNode = mandateWrapper;
        }
        credential.set("credentialSubject", credentialSubjectNode);

        credential.put("validFrom", validFrom);
        credential.put("validUntil", validUntil);
        credential.set("credentialStatus", objectMapper.valueToTree(credentialStatus));

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
     * Structure: {vct, iss(placeholder), sub(placeholder), iat, nbf, exp, mandate, status}
     */
    private String buildSdJwtFlatCredential(CredentialProfile profile, JsonNode payload,
                                             CredentialStatus credentialStatus,
                                             String validFrom, String validUntil) {
        ObjectNode credential = objectMapper.createObjectNode();

        credential.put("vct", profile.sdJwt().vct());

        // iss and sub are placeholders — bound later by bindIssuer/bindSubjectId
        credential.put("iss", "");
        credential.put("sub", "");

        long iat = parseDateToUnixTime(validFrom);
        long exp = parseDateToUnixTime(validUntil);
        credential.put("iat", iat);
        credential.put("nbf", iat);
        credential.put("exp", exp);

        // Payload goes directly at top level (e.g., "mandate": {...})
        if ("direct".equals(profile.credentialSubjectStrategy())) {
            // For "direct" strategy, merge all payload fields into top level
            payload.properties().forEach(entry -> credential.set(entry.getKey(), entry.getValue()));
        } else {
            // Default: payload is the mandate content
            credential.set("mandate", payload);
        }

        // Map credentialStatus → status_list
        if (credentialStatus != null) {
            String statusListUri = credentialStatus.statusListCredential();
            String statusListIdx = credentialStatus.statusListIndex();
            if (statusListUri != null && statusListIdx != null) {
                try {
                    int idx = Integer.parseInt(statusListIdx);
                    credential.set("status", objectMapper.valueToTree(
                            Map.of("status_list", Map.of("uri", statusListUri, "idx", idx))));
                } catch (NumberFormatException e) {
                    credential.set("status", objectMapper.valueToTree(
                            Map.of("status_list", Map.of("uri", statusListUri, "idx", statusListIdx))));
                }
            }
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
     * Binds a DID to the credential subject.
     * Format-aware: W3C sets credentialSubject.id, SD-JWT sets sub + mandate.mandatee.id.
     */
    public Mono<String> bindSubjectId(CredentialProfile profile, String decodedCredentialJson, String subjectDid) {
        try {
            ObjectNode credential = (ObjectNode) objectMapper.readTree(decodedCredentialJson);

            if (DC_SD_JWT.equals(profile.format())) {
                credential.put("sub", subjectDid);
                JsonNode mandate = credential.get("mandate");
                if (mandate != null && mandate.has("mandatee")) {
                    ((ObjectNode) mandate.get("mandatee")).put("id", subjectDid);
                }
            } else {
                ObjectNode credentialSubject = (ObjectNode) credential.get("credentialSubject");
                if (credentialSubject == null) {
                    return Mono.error(new IllegalStateException("Missing credentialSubject in credential"));
                }
                credentialSubject.put("id", subjectDid);
            }

            return Mono.just(objectMapper.writeValueAsString(credential));
        } catch (Exception e) {
            return Mono.error(new IllegalStateException("Failed to bind subject ID", e));
        }
    }

    /**
     * Creates and binds an Issuer to the decoded credential.
     * Format-aware: W3C sets issuer object, SD-JWT sets iss string.
     */
    public Mono<String> bindIssuer(CredentialProfile profile, String decodedCredentialJson,
                                   String procedureId, String email) {
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
        if (issuerNode.has("id")) return issuerNode.get("id").asText();
        if (issuerNode.has("organizationIdentifier")) {
            return "did:elsi:" + issuerNode.get("organizationIdentifier").asText();
        }
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
            return "";
        }
        if (issuer.isTextual()) {
            return issuer.asText();
        }
        if (issuer.has("id")) {
            return issuer.get("id").asText();
        }
        if (issuer.has("organizationIdentifier")) {
            return "did:elsi:" + issuer.get("organizationIdentifier").asText();
        }
        return "";
    }

    private String extractSubjectId(JsonNode credential) {
        JsonNode subject = credential.path("credentialSubject").path("id");
        if (!subject.isMissingNode() && subject.isTextual()) {
            return subject.asText();
        }
        // Fallback for machine credentials: mandatee.id
        JsonNode mandateeId = credential.path("credentialSubject").path("mandate").path("mandatee").path("id");
        if (!mandateeId.isMissingNode() && mandateeId.isTextual()) {
            return mandateeId.asText();
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
