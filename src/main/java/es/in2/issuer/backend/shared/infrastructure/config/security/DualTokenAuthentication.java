package es.in2.issuer.backend.shared.infrastructure.config.security;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.Objects;

public final class DualTokenAuthentication extends AbstractAuthenticationToken {

    private final String accessToken;
    @Nullable private final String idToken;
    @Nullable private final String requestBaseUrl;
    @Nullable private final String expectedVerifierBaseUrl;

    public DualTokenAuthentication(String accessToken, @Nullable String idToken) {
        this(accessToken, idToken, null, null);
    }

    public DualTokenAuthentication(String accessToken, @Nullable String idToken, @Nullable String requestBaseUrl) {
        this(accessToken, idToken, requestBaseUrl, null);
    }

    public DualTokenAuthentication(
            String accessToken,
            @Nullable String idToken,
            @Nullable String requestBaseUrl,
            @Nullable String expectedVerifierBaseUrl
    ) {
        super(null);
        this.accessToken = accessToken;
        this.idToken = idToken;
        this.requestBaseUrl = requestBaseUrl;
        this.expectedVerifierBaseUrl = expectedVerifierBaseUrl;
        setAuthenticated(false);
    }

    @Override
    public Object getCredentials() { return accessToken; }

    @Override
    public Object getPrincipal() {
        // At this stage, the authentication request only carries the raw tokens (access and optional ID token).
        // The user's identity ("principal") is not yet known — this instance represents a pre-authenticated state.
        // Once the tokens are validated by an AuthenticationProvider, a new Authentication object will be created
        // with the proper principal (e.g., a Jwt or UserDetails instance) and marked as authenticated.
        return "N/A";
    }

    @Nullable
    public String getIdToken() { return idToken; }

    /**
     * Public base URL of the incoming request (scheme + host + port + context path),
     * captured by the authentication converter from the {@link org.springframework.web.server.ServerWebExchange}.
     * Used by the authentication manager to validate the token's {@code iss} claim
     * without depending on APP_URL config (HAIP-aligned).
     */
    @Nullable
    public String getRequestBaseUrl() { return requestBaseUrl; }

    /**
     * Public base URL the verifier should have used to sign tokens reaching this
     * issuer under same-origin routing (scheme + host + port + "/verifier"). Used
     * by the authentication manager to validate {@code iss} for verifier-emitted
     * tokens (login flows) without depending on APP_VERIFIER_URL config.
     */
    @Nullable
    public String getExpectedVerifierBaseUrl() { return expectedVerifierBaseUrl; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DualTokenAuthentication that)) return false;
        if (!super.equals(o)) return false;
        return Objects.equals(this.accessToken, that.accessToken)
                && Objects.equals(this.idToken, that.idToken)
                && Objects.equals(this.requestBaseUrl, that.requestBaseUrl)
                && Objects.equals(this.expectedVerifierBaseUrl, that.expectedVerifierBaseUrl);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), accessToken, idToken, requestBaseUrl, expectedVerifierBaseUrl);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[authenticated=" + isAuthenticated() + "]";
    }
}

