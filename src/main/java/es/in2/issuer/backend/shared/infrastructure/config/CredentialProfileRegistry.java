package es.in2.issuer.backend.shared.infrastructure.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
@Component
public class CredentialProfileRegistry {

    private final Map<String, CredentialProfile> byConfigurationId;
    private final Map<String, CredentialProfile> byCredentialType;
    private final Map<String, JsonNode> rawProfilesByConfigurationId;

    public CredentialProfileRegistry(
            ObjectMapper objectMapper,
            ResourcePatternResolver resourcePatternResolver,
            @Value("${credential.profiles.path:classpath:credentials/profiles}") String profilesBasePath) {
        String profilesPattern = profilesBasePath + "/*.json";
        Map<String, CredentialProfile> configIdMap = new LinkedHashMap<>();
        Map<String, CredentialProfile> typeMap = new LinkedHashMap<>();
        Map<String, JsonNode> rawMap = new LinkedHashMap<>();

        try {
            Resource[] resources = resourcePatternResolver.getResources(profilesPattern);
            for (Resource resource : resources) {
                loadProfile(objectMapper, resource, configIdMap, typeMap, rawMap);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load credential profiles from " + profilesPattern, e);
        }

        if (configIdMap.isEmpty()) {
            log.warn("No credential profiles found at {}", profilesPattern);
        } else {
            log.info("Loaded {} credential profile(s): {}", configIdMap.size(), configIdMap.keySet());
        }

        this.byConfigurationId = Collections.unmodifiableMap(configIdMap);
        this.byCredentialType = Collections.unmodifiableMap(typeMap);
        this.rawProfilesByConfigurationId = Collections.unmodifiableMap(rawMap);
    }

    private void loadProfile(ObjectMapper objectMapper, Resource resource,
                             Map<String, CredentialProfile> configIdMap,
                             Map<String, CredentialProfile> typeMap,
                             Map<String, JsonNode> rawMap) {
        String filename = resource.getFilename();
        try (InputStream is = resource.getInputStream()) {
            JsonNode rawJson = objectMapper.readTree(is);
            CredentialProfile profile = objectMapper.treeToValue(rawJson, CredentialProfile.class);

            String configId = profile.credentialConfigurationId();
            if (configId == null || configId.isBlank()) {
                throw new IllegalStateException(
                        "Profile in " + filename + " has no credential_configuration_id");
            }

            if (configIdMap.containsKey(configId)) {
                throw new IllegalStateException(
                        "Duplicate credential_configuration_id '" + configId + "' in " + filename);
            }

            String credentialType = profile.credentialType();
            if (typeMap.containsKey(credentialType)) {
                log.warn("Multiple profiles share credential type '{}' (skipping typeMap entry for '{}'). " +
                        "Use getByConfigurationId() for unambiguous lookup.", credentialType, configId);
            } else {
                typeMap.put(credentialType, profile);
            }

            configIdMap.put(configId, profile);
            rawMap.put(configId, rawJson);

            log.info("Loaded credential profile '{}' (type: {}) from {}", configId, credentialType, filename);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to parse credential profile from " + filename, e);
        }
    }

    public CredentialProfile getByConfigurationId(String credentialConfigurationId) {
        return byConfigurationId.get(credentialConfigurationId);
    }

    public CredentialProfile getByCredentialType(String credentialType) {
        return byCredentialType.get(credentialType);
    }

    public Map<String, CredentialProfile> getAllProfiles() {
        return byConfigurationId;
    }

    public JsonNode getRawProfile(String credentialConfigurationId) {
        return rawProfilesByConfigurationId.get(credentialConfigurationId);
    }
}
