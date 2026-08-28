package es.in2.issuer.backend.shared.infrastructure.config.security;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.web.server.ServerWebExchange;

import java.util.Objects;

/**
 * Pre-authenticated token carrying the raw access / id tokens and a reference
 * to the live {@link ServerWebExchange}.
 *
 * <p>Spring Security's {@code AuthenticationWebFilter} runs the
 * {@code ReactiveAuthenticationManager} in a reactive branch where neither
 * the Reactor context populated by upstream filters nor the
 * {@code ServerWebExchangeContextFilter} attribute are visible. The
 * {@link ServerAuthenticationConverter} is the only place guaranteed to
 * receive the exchange, so the converter stuffs it in here for the manager
 * to consume. The manager then delegates URL construction to
 * {@link es.in2.issuer.backend.shared.domain.spi.UrlResolver}.
 */
public final class DualTokenAuthentication extends AbstractAuthenticationToken {

    private final String accessToken;
    @Nullable private final String idToken;
    @Nullable private final ServerWebExchange requestExchange;

    public DualTokenAuthentication(String accessToken, @Nullable String idToken) {
        this(accessToken, idToken, null);
    }

    public DualTokenAuthentication(String accessToken,
                                   @Nullable String idToken,
                                   @Nullable ServerWebExchange requestExchange) {
        super(null);
        this.accessToken = accessToken;
        this.idToken = idToken;
        this.requestExchange = requestExchange;
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
     * Live exchange of the request that produced this auth token, or null
     * when the token was built outside the request path (e.g. unit tests).
     */
    @Nullable
    public ServerWebExchange getRequestExchange() { return requestExchange; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DualTokenAuthentication that)) return false;
        if (!super.equals(o)) return false;
        return Objects.equals(this.accessToken, that.accessToken)
                && Objects.equals(this.idToken, that.idToken)
                && Objects.equals(this.requestExchange, that.requestExchange);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), accessToken, idToken, requestExchange);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[authenticated=" + isAuthenticated() + "]";
    }
}
