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
