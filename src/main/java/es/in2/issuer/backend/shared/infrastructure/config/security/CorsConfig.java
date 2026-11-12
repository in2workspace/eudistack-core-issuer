package es.in2.issuer.backend.shared.infrastructure.config.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * CORS configuration for the Issuer.
 *
 * <p>External wallets call OID4VCI endpoints from a different origin (e.g. DOME where
 * issuer and wallet have separate domains). The authorize endpoint returns a 302 redirect,
 * and Chrome requires Access-Control-Allow-Origin on that redirect response for XHR to
 * follow it and read response.url (which carries the auth code).
 *
 * <p>The {@link CorsWebFilter} bean runs at HIGHEST_PRECEDENCE, outside and before any
 * {@link org.springframework.security.web.server.SecurityWebFilterChain}. This guarantees
 * CORS headers are set regardless of which security chain handles the request and regardless
 * of how reverse proxies interpret the spring.webflux.base-path context path.
 *
 * <p><b>Two policies (SonarCloud S5122).</b> The paths external wallets call
 * ({@code /.well-known/**}, {@code /oid4vci/**}, {@code /oauth/**}, {@code /credential-offer/**},
 * {@code /w3c/**}, {@code /token/**}) are public by design and accept any origin, without credentials.
 * {@code /api/**} (backoffice, issuances, me, intake) is not an OID4VCI path, so it only accepts the
 * origins listed in {@code cors-origins.yaml} ({@link CorsOriginsLoader}, {@code app.cors.origins-path}).
 * With an empty list no cross-origin caller is allowed; same-origin callers (the Portal de administración
 * through the reverse proxy) and server-to-server callers (intake) are not subject to CORS.
 */
@Configuration
public class CorsConfig {

    private final CorsOriginsLoader corsOriginsLoader;

    public CorsConfig(CorsOriginsLoader corsOriginsLoader) {
        this.corsOriginsLoader = corsOriginsLoader;
    }

    @Bean
    public UrlBasedCorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration publicConfig = new CorsConfiguration();
        publicConfig.setAllowedOriginPatterns(List.of("*"));
        publicConfig.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
        publicConfig.setAllowedHeaders(List.of(
                "Content-Type", "Authorization", "DPoP",
                "OAuth-Client-Attestation", "OAuth-Client-Attestation-PoP"));
        publicConfig.setAllowCredentials(false);
        publicConfig.setMaxAge(1800L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/.well-known/**", publicConfig);
        source.registerCorsConfiguration("/oid4vci/**", publicConfig);
        source.registerCorsConfiguration("/oauth/**", publicConfig);
        source.registerCorsConfiguration("/credential-offer/**", publicConfig);
        source.registerCorsConfiguration("/w3c/**", publicConfig);
        source.registerCorsConfiguration("/token/**", publicConfig);
        source.registerCorsConfiguration("/api/**", apiConfig());

        return source;
    }

    // /api/** is not public: only the configured origins may call it cross-origin.
    private CorsConfiguration apiConfig() {
        CorsConfiguration apiConfig = new CorsConfiguration();
        apiConfig.setAllowedOrigins(corsOriginsLoader.loadOrigins());
        apiConfig.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        // If-Match: the catalog entries use optimistic concurrency (EUD-266). The response headers are
        // exposed so a cross-origin front can read the new ETag, the Location of a created entry and the
        // deprecation notice of the legacy catalog alias.
        apiConfig.setAllowedHeaders(List.of("Content-Type", "Authorization", "If-Match"));
        apiConfig.setExposedHeaders(List.of("ETag", "Location", "Deprecation", "Link"));
        apiConfig.setAllowCredentials(false);
        apiConfig.setMaxAge(1800L);
        return apiConfig;
    }

    // Standalone filter — runs before all SecurityWebFilterChains so CORS headers are
    // always present on OID4VCI responses (including 302 redirects from /oid4vci/v1/authorize)
    // regardless of security matcher path resolution with spring.webflux.base-path.
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public CorsWebFilter corsWebFilter() {
        return new CorsWebFilter(corsConfigurationSource());
    }
}
