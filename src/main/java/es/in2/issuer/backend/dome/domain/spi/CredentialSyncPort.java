package es.in2.issuer.backend.dome.domain.spi;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.dome.domain.model.sync.HolderKeyThumbprint;
import reactor.core.publisher.Flux;

/**
 * Outgoing port to retrieve migrated credentials from the underlying database.
 * Defines the contract for data fetching, decoupling the domain logic from the
 * specific database implementation.
 */
public interface CredentialSyncPort {

    /**
     * Finds and streams all pre-existing credentials associated with a specific holder's key thumbprint.
     */
    Flux<JsonNode> findByHolderKey(String tenant, HolderKeyThumbprint thumbprint);
}
