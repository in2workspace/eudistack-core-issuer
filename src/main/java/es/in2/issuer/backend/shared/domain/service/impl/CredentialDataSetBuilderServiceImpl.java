package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.issuer.backend.shared.domain.exception.CredentialTypeUnsupportedException;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedCredentialDataRequest;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.CredentialDataSetBuilderService;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class CredentialDataSetBuilderServiceImpl implements CredentialDataSetBuilderService {

    private static final String DEFAULT_DELIVERY = "email";

    private final ObjectMapper objectMapper;
    private final CredentialProfileRegistry credentialProfileRegistry;
    private final AccessTokenService accessTokenService;

    @Override
    @Observed(name = "issuance.build-dataset", contextualName = "build-credential-data-set")
    public Mono<IssuanceCreationRequest> buildDataSet(
            String issuanceId,
            PreSubmittedCredentialDataRequest request) {

        String configId = request.credentialConfigurationId();
        CredentialProfile profile = resolveProfile(configId);
        if (profile == null) {
            return Mono.error(new CredentialTypeUnsupportedException(configId));
        }

        JsonNode payload = request.payload();
        ObjectNode credential = objectMapper.createObjectNode();

        // @context
        credential.set("@context", objectMapper.valueToTree(profile.credentialDefinition().context()));

        // id
        credential.put("id", "urn:uuid:" + UUID.randomUUID());

        // type
        credential.set("type", objectMapper.valueToTree(profile.credentialDefinition().type()));

        // description
        if (profile.description() != null) {
            credential.put("description", profile.description());
        }

        // credentialSubject
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

        // validFrom / validUntil
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
        credential.put("validFrom", validFrom);
        credential.put("validUntil", validUntil);

        // No credentialStatus, issuer, or cnf — those are injected at signing time

        String credentialJson;
        try {
            credentialJson = objectMapper.writeValueAsString(credential);
        } catch (Exception e) {
            return Mono.error(new IllegalStateException("Failed to serialize credential dataset", e));
        }

        String subject = extractSubject(profile, payload);
        String delivery = request.delivery() != null ? request.delivery() : DEFAULT_DELIVERY;

        return extractOrganizationIdentifier(profile, payload)
                .map(orgId -> IssuanceCreationRequest.builder()
                        .issuanceId(issuanceId)
                        .organizationIdentifier(orgId)
                        .credentialDataSet(credentialJson)
                        .credentialType(profile.credentialConfigurationId())
                        .credentialFormat(profile.format())
                        .subject(subject)
                        .validUntil(Timestamp.from(parseInstant(validUntil)))
                        .email(request.email())
                        .delivery(delivery)
                        .build())
                .doOnSuccess(req -> log.info("Built credential dataset for issuanceId: {}, type: {}", issuanceId, configId));
    }

    private CredentialProfile resolveProfile(String configId) {
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(configId);
        if (profile == null) {
            profile = credentialProfileRegistry.getByCredentialType(configId);
        }
        return profile;
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

    private Instant parseInstant(String date) {
        try {
            return ZonedDateTime.parse(date, DateTimeFormatter.ISO_ZONED_DATE_TIME).toInstant();
        } catch (Exception e) {
            return Instant.parse(date);
        }
    }

}
