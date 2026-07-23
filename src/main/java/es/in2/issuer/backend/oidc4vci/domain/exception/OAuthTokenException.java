package es.in2.issuer.backend.oidc4vci.domain.exception;

import lombok.Getter;

/**
 * Exception for OAuth 2.0 Token Endpoint errors per RFC 6749 §5.2.
 */
@Getter
public class OAuthTokenException extends RuntimeException {

    public static final String INVALID_CLIENT = "invalid_client";

    private final String errorCode;

    public OAuthTokenException(String errorCode, String errorDescription) {
        super(errorDescription);
        this.errorCode = errorCode;
    }

    public static OAuthTokenException unsupportedGrantType(String grantType) {
        return new OAuthTokenException("unsupported_grant_type", "Unsupported grant type: " + grantType);
    }

    public static OAuthTokenException invalidGrant(String description) {
        return new OAuthTokenException("invalid_grant", description);
    }

    public static OAuthTokenException invalidRequest(String description) {
        return new OAuthTokenException("invalid_request", description);
    }

    /**
     * Uniform denial for client_credentials authentication failures (unknown
     * client, wrong secret, non-ACTIVE status) — same error/description for
     * every cause, per the anti-enumeration requirement (ES-03, NFR-S-EUD75-02).
     */
    public static OAuthTokenException invalidClient() {
        return new OAuthTokenException(INVALID_CLIENT, INVALID_CLIENT);
    }
}