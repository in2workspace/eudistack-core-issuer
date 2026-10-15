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
 * <p><b>Why a wildcard origin is acceptable here (SonarCloud S5122, reviewed and accepted).</b>
 * A single configuration is registered for every path, with {@code allowCredentials=false} and
 * without {@code Access-Control-Allow-Credentials}. The browser therefore never attaches cookies
 * or other ambient credentials to a cross-origin request, so a foreign page gains nothing it could
 * not already do by calling the endpoint directly. Every protected endpoint authenticates with a
 * {@code Bearer} access token (or {@code client_credentials} on intake), which a browser does not
 * send on its own: an attacker page would first need to hold a valid token.
 *
 * <p>{@code /api/**} (backoffice, issuances, me, intake) is covered by the same wildcard on purpose.
 * It is not a public OID4VCI path, but the Portal de administración reaches it same-origin through the
 * reverse proxy ({@code /issuer/api/v1/...}) and intake is server-to-server, so CORS does not apply to
 * either today. Restricting it to an allowlist ({@link CorsOriginsLoader}, {@code app.cors.origins-path})
 * was deliberately left out: it relies on same-origin detection behind CloudFront/ALB
 * ({@code Host}/{@code X-Forwarded-Host}) that cannot be verified outside STG, and a mistake would
 * answer the portal's own POST/PUT with 403. Revisit with the allowlist once it can be tested in STG.
 */
@Configuration
public class CorsConfig {

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
        // Bearer-authenticated, no credentials: see the class Javadoc for why this stays a wildcard.
        source.registerCorsConfiguration("/api/**", publicConfig);

        return source;
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
