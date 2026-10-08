package es.in2.issuer.backend.oidc4vci.domain.exception;

import lombok.Getter;

/**
 * The credential offer referenced by the Wallet did exist but can no longer be retrieved,
 * because it expired or was already consumed (410 Gone). Distinct from
 * {@link CredentialOfferExpiredException}, which covers a refresh attempt on an issuance that
 * is no longer in DRAFT.
 */
@Getter
public class CredentialOfferNoLongerAvailableException extends RuntimeException {

    private final boolean consumed;

    private CredentialOfferNoLongerAvailableException(String message, boolean consumed) {
        super(message);
        this.consumed = consumed;
    }

    public static CredentialOfferNoLongerAvailableException expired() {
        return new CredentialOfferNoLongerAvailableException("The credential offer has expired.", false);
    }

    public static CredentialOfferNoLongerAvailableException alreadyUsed() {
        return new CredentialOfferNoLongerAvailableException("The credential offer has already been used.", true);
    }
}
