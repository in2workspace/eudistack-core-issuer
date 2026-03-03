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

    /**
     * Builds a W3C VCDM credential from a profile definition and input payload.
     * Replaces the type-specific mapAndBuild*() methods.
     */
    public Mono<CredentialProcedureCreationRequest> buildCredential(
            CredentialProfile profile,
            String procedureId,
            JsonNode payload,
            CredentialStatus credentialStatus,
            String operationMode,
            String email) {

        ObjectNode credential = objectMapper.createObjectNode();

        // @context
        credential.set("@context", objectMapper.valueToTree(profile.credentialDefinition().context()));

        // id
        String credentialId = "urn:uuid:" + UUID.randomUUID();
        credential.put("id", credentialId);

        // type
        credential.set("type", objectMapper.valueToTree(profile.credentialDefinition().type()));

        // description (if present)
        if (profile.description() != null) {
            credential.put("description", profile.description());
        }

        // credentialSubject — strategy-based
        JsonNode credentialSubjectNode;
        if ("direct".equals(profile.credentialSubjectStrategy())) {
            // payload is the full credential; extract its credentialSubject directly
            JsonNode cs = payload.get("credentialSubject");
            credentialSubjectNode = (cs != null) ? cs : payload;
        } else {
            // default: wrap payload as mandate
            ObjectNode mandateWrapper = objectMapper.createObjectNode();
            mandateWrapper.set("mandate", payload);
            credentialSubjectNode = mandateWrapper;
        }
        credential.set("credentialSubject", credentialSubjectNode);

        // validFrom / validUntil
        Instant now = Instant.now();
        String validFrom;
        String validUntil;

        if (profile.validityDays() > 0) {
            validFrom = now.toString();
            validUntil = now.plus(profile.validityDays(), ChronoUnit.DAYS).toString();
        } else {
            // Use values from payload (LabelCredential case)
            // The payload for LabelCredential comes as a full credential, not just mandate
            validFrom = payload.has("validFrom") ? payload.get("validFrom").asText() : now.toString();
            validUntil = payload.has("validUntil") ? payload.get("validUntil").asText()
                    : now.plus(365, ChronoUnit.DAYS).toString();
        }
        credential.put("validFrom", validFrom);
        credential.put("validUntil", validUntil);

        // credentialStatus
        credential.set("credentialStatus", objectMapper.valueToTree(credentialStatus));

        String credentialJson;
        try {
            credentialJson = objectMapper.writeValueAsString(credential);
        } catch (Exception e) {
            return Mono.error(new IllegalStateException("Failed to serialize credential", e));
        }

        // Extract subject and organization
        String subject = extractSubject(profile, payload);

        return extractOrganizationIdentifier(profile, payload)
                .map(orgId -> CredentialProcedureCreationRequest.builder()
                        .procedureId(procedureId)
                        .organizationIdentifier(orgId)
                        .credentialDecoded(credentialJson)
                        .credentialType(profile.credentialConfigurationId())
                        .subject(subject)
                        .validUntil(Timestamp.from(parseInstant(validUntil)))
                        .operationMode(operationMode)
                        .email(email)
                        .build());
    }

    /**
     * Binds a DID to credentialSubject.id in the decoded credential JSON.
     * Generic — works for any credential type.
     */
    public Mono<String> bindSubjectId(String decodedCredentialJson, String subjectDid) {
        try {
            ObjectNode credential = (ObjectNode) objectMapper.readTree(decodedCredentialJson);
            ObjectNode credentialSubject = (ObjectNode) credential.get("credentialSubject");

            if (credentialSubject == null) {
                return Mono.error(new IllegalStateException("Missing credentialSubject in credential"));
            }

            credentialSubject.put("id", subjectDid);
            return Mono.just(objectMapper.writeValueAsString(credential));
        } catch (Exception e) {
            return Mono.error(new IllegalStateException("Failed to bind subject ID", e));
        }
    }

    /**
     * Creates and binds an Issuer to the decoded credential.
     * Uses profile.issuerType() to determine DetailedIssuer vs SimpleIssuer.
     */
    public Mono<String> bindIssuer(CredentialProfile profile, String decodedCredentialJson,
                                   String procedureId, String email) {
        return switch (profile.issuerType()) {
            case DETAILED -> issuerFactory.createDetailedIssuerAndNotifyOnError(procedureId, email)
                    .flatMap(issuer -> setIssuerField(decodedCredentialJson, issuer));
            case SIMPLE -> issuerFactory.createSimpleIssuerAndNotifyOnError(procedureId, email)
                    .flatMap(issuer -> setIssuerField(decodedCredentialJson, issuer));
        };
    }

    private Mono<String> setIssuerField(String decodedCredentialJson, Object issuer) {
        try {
            ObjectNode credential = (ObjectNode) objectMapper.readTree(decodedCredentialJson);
            credential.set("issuer", objectMapper.valueToTree(issuer));
            return Mono.just(objectMapper.writeValueAsString(credential));
        } catch (Exception e) {
            return Mono.error(new IllegalStateException("Failed to bind issuer", e));
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
