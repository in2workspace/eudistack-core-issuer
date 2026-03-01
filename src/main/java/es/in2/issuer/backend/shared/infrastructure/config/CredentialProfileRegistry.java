package es.in2.issuer.backend.shared.infrastructure.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialType;
import lombok.extern.slf4j.Slf4j;
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

    private static final String PROFILES_PATTERN = "classpath:credentials/profiles/*.json";

    private final Map<String, CredentialProfile> byConfigurationId;
    private final Map<String, CredentialProfile> byCredentialType;
    private final Map<String, CredentialProfile> byEnumName;

    public CredentialProfileRegistry(ObjectMapper objectMapper, ResourcePatternResolver resourcePatternResolver) {
        Map<String, CredentialProfile> configIdMap = new LinkedHashMap<>();
        Map<String, CredentialProfile> typeMap = new LinkedHashMap<>();
        Map<String, CredentialProfile> enumNameMap = new LinkedHashMap<>();

        try {
            Resource[] resources = resourcePatternResolver.getResources(PROFILES_PATTERN);
            for (Resource resource : resources) {
                loadProfile(objectMapper, resource, configIdMap, typeMap, enumNameMap);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load credential profiles from " + PROFILES_PATTERN, e);
        }

        if (configIdMap.isEmpty()) {
            log.warn("No credential profiles found at {}", PROFILES_PATTERN);
        } else {
            log.info("Loaded {} credential profile(s): {}", configIdMap.size(), configIdMap.keySet());
        }

        this.byConfigurationId = Collections.unmodifiableMap(configIdMap);
        this.byCredentialType = Collections.unmodifiableMap(typeMap);
        this.byEnumName = Collections.unmodifiableMap(enumNameMap);
    }

    private void loadProfile(ObjectMapper objectMapper, Resource resource,
                             Map<String, CredentialProfile> configIdMap,
                             Map<String, CredentialProfile> typeMap,
                             Map<String, CredentialProfile> enumNameMap) {
        String filename = resource.getFilename();
        try (InputStream is = resource.getInputStream()) {
            CredentialProfile profile = objectMapper.readValue(is, CredentialProfile.class);

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
                throw new IllegalStateException(
                        "Duplicate credential type '" + credentialType + "' in " + filename);
            }

            configIdMap.put(configId, profile);
            typeMap.put(credentialType, profile);

            // Also index by CredentialType enum name (e.g., "LEAR_CREDENTIAL_EMPLOYEE")
            for (CredentialType ct : CredentialType.values()) {
                if (ct.getTypeId().equals(configId)) {
                    enumNameMap.put(ct.name(), profile);
                    break;
                }
            }

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

    /**
     * Lookup by CredentialType enum name (e.g., "LEAR_CREDENTIAL_EMPLOYEE").
     * Used by CredentialSignerWorkflowImpl which stores the enum name in the database.
     */
    public CredentialProfile getByEnumName(String enumName) {
        return byEnumName.get(enumName);
    }

    public Map<String, CredentialProfile> getAllProfiles() {
        return byConfigurationId;
    }
}
