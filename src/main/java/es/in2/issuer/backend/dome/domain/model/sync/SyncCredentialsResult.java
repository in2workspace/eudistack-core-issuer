package es.in2.issuer.backend.dome.domain.model.sync;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;

public record SyncCredentialsResult (
        List<JsonNode> credentials,
        String format
) {
    public SyncCredentialsResult(List<JsonNode> credentials) {
        this(credentials, "vc-list");
    }
}
