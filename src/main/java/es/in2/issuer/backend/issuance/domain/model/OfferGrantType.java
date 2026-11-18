package es.in2.issuer.backend.issuance.domain.model;

import es.in2.issuer.backend.issuance.domain.exception.InvalidGrantTypeException;

import java.util.Arrays;

/**
 * The OID4VCI grants an issuance request may put in its credential offer (EUD-254 contract,
 * {@code grant_type}): the authorization code, which is the default, or the pre-authorized code.
 * Any other value is rejected with {@code invalid_grant_type} -- it used to be stored as sent and
 * then treated as an authorization code by the offer service.
 */
public enum OfferGrantType {

    AUTHORIZATION_CODE("authorization_code"),
    PRE_AUTHORIZED_CODE("urn:ietf:params:oauth:grant-type:pre-authorized_code");

    /** Never echoes the value the client sent: it may be any string. */
    static final String INVALID_MESSAGE =
            "grant_type must be one of: authorization_code, urn:ietf:params:oauth:grant-type:pre-authorized_code";

    private final String value;

    OfferGrantType(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    /**
     * The grant a request asks for: {@link #AUTHORIZATION_CODE} when it sends none, the matching one
     * when it sends one of the two values exactly.
     *
     * @throws InvalidGrantTypeException for any other value, the empty string included
     */
    public static OfferGrantType fromRequest(String grantType) {
        if (grantType == null) {
            return AUTHORIZATION_CODE;
        }
        return Arrays.stream(values())
                .filter(grant -> grant.value.equals(grantType))
                .findFirst()
                .orElseThrow(() -> new InvalidGrantTypeException(INVALID_MESSAGE));
    }
}
