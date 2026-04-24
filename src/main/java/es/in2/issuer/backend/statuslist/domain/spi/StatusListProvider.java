package es.in2.issuer.backend.statuslist.domain.spi;


import es.in2.issuer.backend.statuslist.domain.model.StatusListEntry;
import es.in2.issuer.backend.statuslist.domain.model.StatusListFormat;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import reactor.core.publisher.Mono;

/**
 * Internal SPI to manage Status Lists.
 * Supports both W3C BitstringStatusList and Token Status List (draft-ietf-oauth-status-list).
 */
public interface StatusListProvider {

    /**
     * Allocates a new status entry for a credential issuance flow.
     * The format determines which type of status list to use:
     * - BITSTRING_VC: W3C BitstringStatusListCredential
     * - TOKEN_JWT: Token Status List (draft-ietf-oauth-status-list)
     *
     * @param publicIssuerBaseUrl public base URL of this issuer (scheme + host
     *                            + port + context-path) resolved by the caller
     *                            via {@link es.in2.issuer.backend.shared.domain.spi.UrlResolver}.
     *                            Used to compose the status list credential URL
     *                            embedded in the signed payload.
     */
    Mono<StatusListEntry> allocateEntry(StatusPurpose purpose, StatusListFormat format,
                                        String issuanceId, String token, String publicIssuerBaseUrl);

    /**
     * Returns the signed status list credential (JWT) for the given list.
     */
    Mono<String> getSignedStatusListCredential(Long listId);

    /**
     * Revokes a credential by setting the corresponding bit to 1 in the Status List.
     *
     * @param publicIssuerBaseUrl see {@link #allocateEntry}. Re-signing the list
     *                            after revocation requires the same public URL
     *                            the original list was issued against.
     */
    Mono<Void> revoke(String issuanceId, String token, String publicIssuerBaseUrl);

}
