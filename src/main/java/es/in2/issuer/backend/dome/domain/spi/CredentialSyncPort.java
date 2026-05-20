package es.in2.issuer.backend.dome.domain.spi;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.dome.domain.model.sync.HolderKeyThumbprint;
import reactor.core.publisher.Flux;

/**
 * Port to retrieve migrate credentials from the database.
 */
public interface CredentialSyncPort {

    /**
     * Finds credentials by the holder's key thumbprint.
     *
     * @param tenant        the tenant identifier
     * @param thumbprint    the holder's key thumbprint
     *
     * @return a Flux emitting the found credentials.
     */
    Flux<JsonNode> findByHolderKey(String tenant, HolderKeyThumbprint thumbprint);
}
