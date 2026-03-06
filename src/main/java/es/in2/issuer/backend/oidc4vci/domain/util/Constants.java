package es.in2.issuer.backend.oidc4vci.domain.util;

public final class Constants {

    private Constants() {
        throw new IllegalStateException("Utility class");
    }

    public static final int TX_CODE_SIZE = 6;
    public static final String TX_INPUT_MODE = "numeric";
    public static final long ACCESS_TOKEN_EXPIRATION_TIME_DAYS = 30L;

    // Authorization Code Flow
    public static final long PAR_CACHE_EXPIRY_SECONDS = 60;
    public static final long AUTHORIZATION_CODE_CACHE_EXPIRY_SECONDS = 300;
    public static final long NONCE_CACHE_EXPIRY_SECONDS = 300;
    public static final long NOTIFICATION_CACHE_EXPIRY_HOURS = 72;
    public static final String PAR_REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:";
    public static final String AUTHORIZATION_CODE_GRANT_TYPE = "authorization_code";
}
