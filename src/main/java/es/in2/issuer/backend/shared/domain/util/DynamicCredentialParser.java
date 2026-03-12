package es.in2.issuer.backend.shared.domain.util;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialFormatException;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class DynamicCredentialParser {

    private final ObjectMapper objectMapper;
    private final CredentialProfileRegistry credentialProfileRegistry;

    public ParsedCredential parse(String vcJson) {
        try {
            JsonNode vcNode = objectMapper.readTree(vcJson);
            String credentialType = resolveCredentialType(vcNode);
            CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(credentialType);
            if (profile == null) {
                throw new InvalidCredentialFormatException(
                        "No profile found for credential type: " + credentialType);
            }
            return new ParsedCredential(vcNode, profile, credentialType);
        } catch (InvalidCredentialFormatException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidCredentialFormatException("Failed to parse credential: " + e.getMessage());
        }
    }

    public List<Power> extractPowers(JsonNode vcNode, CredentialProfile profile) {
        CredentialProfile.PolicyExtraction extraction = profile.policyExtraction();
        if (extraction == null || extraction.powersPath() == null) {
            return Collections.emptyList();
        }
        JsonNode powersNode = navigatePath(vcNode, extraction.powersPath());
        if (powersNode.isMissingNode() || powersNode.isNull()) {
            return Collections.emptyList();
        }
        return objectMapper.convertValue(powersNode, new TypeReference<>() {});
    }

    public String extractOrganizationId(JsonNode vcNode, CredentialProfile profile) {
        CredentialProfile.PolicyExtraction extraction = profile.policyExtraction();
        if (extraction == null || extraction.mandatorPath() == null) {
            return null;
        }
        JsonNode mandatorNode = navigatePath(vcNode, extraction.mandatorPath());
        if (mandatorNode.isMissingNode() || mandatorNode.isNull()) {
            return null;
        }
        JsonNode orgIdNode = mandatorNode.path(extraction.orgIdField());
        return orgIdNode.isMissingNode() || orgIdNode.isNull() ? null : orgIdNode.asText();
    }

    public JsonNode extractMandator(JsonNode vcNode, CredentialProfile profile) {
        CredentialProfile.PolicyExtraction extraction = profile.policyExtraction();
        if (extraction == null || extraction.mandatorPath() == null) {
            return objectMapper.missingNode();
        }
        return navigatePath(vcNode, extraction.mandatorPath());
    }

    private JsonNode navigatePath(JsonNode root, String dotPath) {
        if (root == null || dotPath == null) {
            return objectMapper.missingNode();
        }
        String[] parts = dotPath.split("\\.");
        JsonNode current = root;
        for (String part : parts) {
            current = current.path(part);
            if (current.isMissingNode()) {
                return current;
            }
        }
        return current;
    }

    private String resolveCredentialType(JsonNode vcNode) {
        JsonNode typeNode = vcNode.get("type");
        if (typeNode == null || !typeNode.isArray()) {
            throw new InvalidCredentialFormatException("Credential has no 'type' array");
        }
        for (JsonNode t : typeNode) {
            String type = t.asText();
            if (!"VerifiableCredential".equals(type)) {
                return type;
            }
        }
        if (!typeNode.isEmpty()) {
            return typeNode.get(0).asText();
        }
        throw new InvalidCredentialFormatException("Credential 'type' array is empty");
    }

    public record ParsedCredential(JsonNode node, CredentialProfile profile, String credentialType) {}
}
