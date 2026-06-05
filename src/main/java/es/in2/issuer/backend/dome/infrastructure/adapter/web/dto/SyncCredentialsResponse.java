package es.in2.issuer.backend.dome.infrastructure.adapter.web.dto;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;

/**
 * DTO for the synchronization credentials response.
 */
public record SyncCredentialsResponse(
        List<JsonNode> credentials,
        String format
) {}