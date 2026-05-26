package es.in2.issuer.backend.dome.infrastructure.adapter.web.dto;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;

/**
 * Response DTO for the sync-credentials endpoint
 */
public record SyncCredentialsResponse(
        List<JsonNode> credentials,
        String format
) {}