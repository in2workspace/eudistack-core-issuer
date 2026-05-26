package es.in2.issuer.backend.dome.infrastructure.adapter.persistence;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.dome.domain.model.sync.HolderKeyThumbprint;
import es.in2.issuer.backend.dome.domain.spi.CredentialSyncPort;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;

@Repository
public class R2dbcCredentialSyncAdapter implements CredentialSyncPort {

    private final DatabaseClient databaseClient;
    private final ObjectMapper objectMapper;

    public R2dbcCredentialSyncAdapter(DatabaseClient databaseClient, ObjectMapper objectMapper) {
        this.databaseClient = databaseClient;
        this.objectMapper = objectMapper;
    }

    @Override
    public Flux<JsonNode> findByHolderKey(String tenant, HolderKeyThumbprint thumbprint) {

        String sql = "SELECT credential_data FROM dome_issuer.issuance WHERE holder_key_thumbprint = :thumbprint";

        return databaseClient.sql(sql)
                .bind("thumbprint", thumbprint.value())
                .map((row, rowMetadata) -> {
                    try {
                        String json = row.get("credential_data", String.class);
                        return objectMapper.readTree(json);
                    } catch (Exception e) {
                        throw new RuntimeException("Error parsing JSON from database", e);
                    }
                })
                .all();
    }
}