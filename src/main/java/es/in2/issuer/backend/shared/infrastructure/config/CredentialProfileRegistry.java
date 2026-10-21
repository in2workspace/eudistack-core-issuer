package es.in2.issuer.backend.shared.infrastructure.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.issuer.backend.shared.domain.model.catalog.ClaimPath;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfileBindingInvariant;
import es.in2.issuer.backend.shared.domain.model.enums.BindingType;
import es.in2.issuer.backend.shared.domain.spi.CredentialProfileCatalog;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Slf4j
@Component
public class CredentialProfileRegistry implements CredentialProfileCatalog {

    private static final String SYNTHETIC_SCHEMA_URI_BASE = "https://registry.eudistack.net/schemas/";

    private final Map<String, CredentialProfile> byConfigurationId;
    private final Map<String, CredentialProfile> byCredentialType;
    private final Map<String, JsonNode> rawProfilesByConfigurationId;
    private final Map<String, List<ClaimPath>> attributePathsByConfigurationId;
    private final Map<String, String> configurationIdBySchemaUri;

    public CredentialProfileRegistry(
            ObjectMapper objectMapper,
            ResourcePatternResolver resourcePatternResolver,
            @Value("${credential.profiles.path:classpath:credentials/profiles}") String profilesBasePath) {
        String profilesPattern = profilesBasePath + "/**/*.json";
        Map<String, CredentialProfile> configIdMap = new LinkedHashMap<>();
        Map<String, CredentialProfile> typeMap = new LinkedHashMap<>();
        Map<String, JsonNode> rawMap = new LinkedHashMap<>();
        Map<String, List<ClaimPath>> pathsMap = new LinkedHashMap<>();
        Map<String, String> schemaUriMap = new LinkedHashMap<>();

        try {
            Resource[] resources = resourcePatternResolver.getResources(profilesPattern);

            List<Resource> coreResources = new ArrayList<>();
            Map<String, JsonNode> profileOverrides = new LinkedHashMap<>();

            for (Resource resource : resources) {
                String filename = resource.getFilename();
                if (filename != null && filename.matches(".*\\.sample.*\\.json")) {
                    log.debug("Skipping sample credential profile file {}", filename);
                    continue;
                }
                if (filename != null && filename.endsWith(".profile.json")) {
                    JsonNode profileJson = readJsonResource(objectMapper, resource);
                    String configId = extractConfigurationId(profileJson, filename);
                    profileOverrides.put(configId, profileJson);
                    log.debug("Loaded profile overlay '{}' from {}", configId, filename);
                } else {
                    coreResources.add(resource);
                }
            }

            for (Resource resource : coreResources) {
                loadCoreWithOptionalProfile(objectMapper, resource, profileOverrides, configIdMap, typeMap, rawMap,
                        pathsMap, schemaUriMap);
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
        this.attributePathsByConfigurationId = Collections.unmodifiableMap(pathsMap);
        this.configurationIdBySchemaUri = Collections.unmodifiableMap(schemaUriMap);
    }

    private JsonNode readJsonResource(ObjectMapper objectMapper, Resource resource) {
        String filename = resource.getFilename();
        try (InputStream is = resource.getInputStream()) {
            return objectMapper.readTree(is);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to parse JSON from " + filename, e);
        }
    }

    private String extractConfigurationId(JsonNode json, String filename) {
        JsonNode idNode = json.get("credential_configuration_id");
        if (idNode == null || idNode.asText().isBlank()) {
            throw new IllegalStateException(
                    "Profile in " + filename + " has no credential_configuration_id");
        }
        return idNode.asText();
    }

    private void loadCoreWithOptionalProfile(ObjectMapper objectMapper, Resource resource,
                                             Map<String, JsonNode> profileOverrides,
                                             Map<String, CredentialProfile> configIdMap,
                                             Map<String, CredentialProfile> typeMap,
                                             Map<String, JsonNode> rawMap,
                                             Map<String, List<ClaimPath>> pathsMap,
                                             Map<String, String> schemaUriMap) {
        String filename = resource.getFilename();
        JsonNode coreJson = readJsonResource(objectMapper, resource);
        String configId = extractConfigurationId(coreJson, filename);

        JsonNode profileOverlay = profileOverrides.get(configId);
        JsonNode mergedJson;
        if (profileOverlay != null) {
            ((ObjectNode) coreJson).setAll((ObjectNode) profileOverlay);
            mergedJson = coreJson;
            log.debug("Merged profile overlay onto core '{}' from {}", configId, filename);
        } else {
            mergedJson = coreJson;
        }

        try {
            CredentialProfile profile = objectMapper.treeToValue(mergedJson, CredentialProfile.class);

            if (configIdMap.containsKey(configId)) {
                throw new IllegalStateException(
                        "Duplicate credential_configuration_id '" + configId + "' in " + filename);
            }

            // Fail-fast at the loading boundary (ADR-110): a profile whose three binding fields
            // contradict one another used to surface as a 500 on its first issuance. Now it stops
            // the service from starting, naming the profile and the offending field.
            CredentialProfileBindingInvariant.validate(profile);
            bindingTypeOf(profile);
            requireValidityDays(profile, filename);

            String credentialType = profile.credentialType();
            if (typeMap.containsKey(credentialType)) {
                log.warn("Multiple profiles share credential type '{}' (skipping typeMap entry for '{}'). " +
                        "Use getByConfigurationId() for unambiguous lookup.", credentialType, configId);
            } else {
                typeMap.put(credentialType, profile);
            }

            String schemaUri = schemaUriOf(profile);
            String previous = schemaUriMap.putIfAbsent(schemaUri, configId);
            if (previous != null) {
                throw new IllegalStateException("Credential profiles '" + previous + "' and '" + configId
                        + "' declare the same schema_uri '" + schemaUri + "'");
            }

            configIdMap.put(configId, profile);
            rawMap.put(configId, mergedJson);
            pathsMap.put(configId, SchemaAttributePaths.of(mergedJson, profile.format()));

            log.info("Loaded credential profile '{}' (type: {}) from {}", configId, credentialType, filename);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to parse credential profile from " + filename, e);
        }
    }

    /**
     * A catalog entry takes its default validity from its type file, and the contract admits no entry
     * without one ({@code default_days >= 1}): a type that does not state it stops the service from
     * starting instead of being issued with a validity nobody chose (EUD-266, D12).
     */
    @SuppressWarnings("deprecation")
    private static void requireValidityDays(CredentialProfile profile, String filename) {
        if (profile.validityDays() < 1) {
            throw new IllegalStateException("Credential profile '" + profile.credentialConfigurationId() + "' in "
                    + filename + " has no validity_days: declare it with a value of at least 1");
        }
    }

    @Override
    public CredentialProfile getByConfigurationId(String credentialConfigurationId) {
        return byConfigurationId.get(credentialConfigurationId);
    }

    @Override
    public List<ClaimPath> attributePaths(String credentialConfigurationId) {
        requireLoaded(credentialConfigurationId);
        return attributePathsByConfigurationId.get(credentialConfigurationId);
    }

    @Override
    public Optional<String> resolveSchemaUri(String schemaUri) {
        return Optional.ofNullable(configurationIdBySchemaUri.get(schemaUri));
    }

    @Override
    public String schemaUriOf(String credentialConfigurationId) {
        CredentialProfile profile = byConfigurationId.get(credentialConfigurationId);
        return profile != null ? schemaUriOf(profile) : SYNTHETIC_SCHEMA_URI_BASE + credentialConfigurationId;
    }

    @Override
    public BindingType bindingTypeOf(String credentialConfigurationId) {
        return bindingTypeOf(requireLoaded(credentialConfigurationId));
    }

    /** An explicit {@code binding_type} wins; otherwise any declared binding method or {@code cnf_required} means a key. */
    private static BindingType bindingTypeOf(CredentialProfile profile) {
        if (profile.bindingType() != null) {
            return BindingType.fromValue(profile.bindingType()).orElseThrow(() -> new IllegalStateException(
                    "Credential profile '" + profile.credentialConfigurationId() + "' declares binding_type '"
                            + profile.bindingType() + "', expected one of key, none, claim, biometric"));
        }
        Set<String> methods = profile.cryptographicBindingMethodsSupported();
        boolean declaresMethods = methods != null && !methods.isEmpty();
        return declaresMethods || profile.cnfRequired() ? BindingType.KEY : BindingType.NONE;
    }

    private CredentialProfile requireLoaded(String credentialConfigurationId) {
        CredentialProfile profile = byConfigurationId.get(credentialConfigurationId);
        if (profile == null) {
            throw new IllegalArgumentException("Unknown credential_configuration_id: " + credentialConfigurationId);
        }
        return profile;
    }

    private static String schemaUriOf(CredentialProfile profile) {
        String declared = profile.schemaUri();
        return declared != null && !declared.isBlank()
                ? declared
                : SYNTHETIC_SCHEMA_URI_BASE + profile.credentialConfigurationId();
    }

    public CredentialProfile getByCredentialType(String credentialType) {
        return byCredentialType.get(credentialType);
    }

    /**
     * Resolves a profile from an identifier that may be either a {@code credential_configuration_id}
     * or a bare W3C credential type name.
     *
     * <p>Modern profiles encode the configuration id inside {@code credential_definition.type},
     * so both indexes coincide. Legacy DOME credentials carry a human-readable type instead
     * (e.g. {@code LEARCredentialEmployee}), which only exists in the credential-type index.
     *
     * @return the matching profile, or {@code null} when neither index contains the key
     */
    public CredentialProfile resolveProfile(String credentialTypeOrConfigurationId) {
        CredentialProfile profile = byConfigurationId.get(credentialTypeOrConfigurationId);
        return profile != null ? profile : byCredentialType.get(credentialTypeOrConfigurationId);
    }

    public Map<String, CredentialProfile> getAllProfiles() {
        return byConfigurationId;
    }

    public JsonNode getRawProfile(String credentialConfigurationId) {
        return rawProfilesByConfigurationId.get(credentialConfigurationId);
    }
}
