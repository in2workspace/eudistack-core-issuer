package es.in2.issuer.backend.statuslist.domain.service;

import reactor.core.publisher.Mono;

/**
 * Resolves the public issuer base URL a status list was originally signed against,
 * for triggers that do not carry a live {@code ServerWebExchange} (AD-2).
 * <p>
 * Re-signing a status list after revocation MUST use the same public URL the list
 * was issued against, or the {@code id}/{@code sub} embedded in the signed payload
 * stops matching the URL a verifier dereferences it from (W3C Bitstring Status List /
 * IETF Token Status List correspondence). Implementations MUST be fail-closed: if the
 * URL cannot be derived from the persisted, already-signed list, this must error rather
 * than fall back to a guessed or configured value.
 */
public interface StatusListPublicBaseUrlResolver {

    /**
     * Resolves the public issuer base URL for the status list containing the given
     * issuance's entry.
     *
     * @param issuanceId the issuance whose status list entry determines the list to resolve
     * @return the public issuer base URL (scheme + host + port + context-path) the list
     *         was signed against
     */
    Mono<String> resolve(String issuanceId);
}
