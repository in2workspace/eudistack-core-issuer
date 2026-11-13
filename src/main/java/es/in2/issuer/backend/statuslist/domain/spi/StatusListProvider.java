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

    Mono<Void> releaseEntry(String issuanceId, String publicIssuerBaseUrl);

    /**
     * Returns the signed status list credential (JWT) for the given list.
     *
     * @param expectedFormat serialization the caller (i.e. the endpoint being hit) is going to
     *                       serve the blob as. A list is only reachable through the endpoint
     *                       matching its own stored format: asking the Token Status List endpoint
     *                       for a {@code bitstring_vc} list (or vice versa) is a
     *                       {@link es.in2.issuer.backend.statuslist.domain.exception.StatusListNotFoundException},
     *                       never a 200 carrying the wrong media type.
     */
    Mono<String> getSignedStatusListCredential(Long listId, StatusListFormat expectedFormat);

    /**
     * Revokes a credential: sets its bit to 1 in the Status List and applies {@code statusChange},
     * both in one transaction, so that the list and the issuance process cannot diverge (EUD-271).
     * Sealing the list calls the QTSP, so it happens before the transaction and nothing is written
     * if it fails. When the bit was already set (a divergence left by an older revocation), only
     * {@code statusChange} runs.
     *
     * @param token               caller access token, propagated to signing for triggers with an
     *                            authenticated caller context (operator revocation). {@code null}
     *                            for system-triggered revocations (no HTTP caller behind it): the
     *                            QTSP obtains its own credentials for those (AD-1, EUD-225).
     * @param publicIssuerBaseUrl see {@link #allocateEntry}. Re-signing the list
     *                            after revocation requires the same public URL
     *                            the original list was issued against.
     * @param statusChange        the write of the issuance process. Subscribed inside the transaction,
     *                            once per attempt when the list changed under the previous one.
     */
    Mono<Void> revoke(String issuanceId, String token, String publicIssuerBaseUrl, Mono<Void> statusChange);

}
