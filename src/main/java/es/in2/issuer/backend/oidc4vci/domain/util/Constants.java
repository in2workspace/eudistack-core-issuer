package es.in2.issuer.backend.oidc4vci.domain.util;

public final class Constants {

    private Constants() {
        throw new IllegalStateException("Utility class");
    }

    public static final int TX_CODE_SIZE = 6;
    public static final String TX_INPUT_MODE = "numeric";
    // SEC-02: Reduced from 30 days to 15 minutes (ENS nivel alto / OWASP A07)
    public static final long ACCESS_TOKEN_EXPIRATION_MINUTES = 15L;

    // Authorization Code Flow
    public static final long PAR_CACHE_EXPIRY_SECONDS = 60;
    public static final long AUTHORIZATION_CODE_CACHE_EXPIRY_SECONDS = 300;
    public static final long NONCE_CACHE_EXPIRY_SECONDS = 300;
    public static final long NOTIFICATION_CACHE_EXPIRY_HOURS = 72;
    public static final String PAR_REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:";
    public static final String AUTHORIZATION_CODE_GRANT_TYPE = "authorization_code";

    // EUD-75 (US-02): M2M client_credentials grant for unattended intake
    public static final String CLIENT_CREDENTIALS_GRANT_TYPE = "client_credentials";
    // TTL kept short (least-privilege): revocation of an ApiClient only takes
    // effect on the next token request, so a short-lived token bounds exposure.
    public static final long M2M_ACCESS_TOKEN_EXPIRATION_MINUTES = 5L;
    public static final String M2M_CALLER_TYPE = "M2M";
    public static final String M2M_INTAKE_SCOPE = "intake.trigger";
}
