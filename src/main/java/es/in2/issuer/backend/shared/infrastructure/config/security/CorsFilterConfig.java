package es.in2.issuer.backend.shared.infrastructure.config.security;

import lombok.RequiredArgsConstructor;
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
@RequiredArgsConstructor
public class CorsFilterConfig {

    private final CorsOriginsLoader corsOriginsLoader;

    @Bean
    public UrlBasedCorsConfigurationSource corsConfigurationSource() {
        // 1. Restricted configuration for authenticated or administrative endpoints.
        // These rely on a predefined list of allowed origins (e.g. the Issuer's own UI).
        CorsConfiguration restrictedConfig = new CorsConfiguration();
        restrictedConfig.setAllowedOrigins(corsOriginsLoader.loadOrigins());
        restrictedConfig.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        restrictedConfig.setAllowedHeaders(List.of(
                "Content-Type", "Authorization", "DPoP",
                "OAuth-Client-Attestation", "OAuth-Client-Attestation-PoP",
                "Api-Version"));
        restrictedConfig.setAllowCredentials(false);
        restrictedConfig.setMaxAge(1800L);

        // 2. Open configuration for public-facing endpoints.
        // SD-01: Public endpoints (metadata, OID4VCI flows, status lists) MUST allow
        // any origin to facilitate interoperability with any external wallet or verifier.
        CorsConfiguration openConfig = new CorsConfiguration();
        openConfig.setAllowedOrigins(List.of("*"));
        openConfig.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
        openConfig.setAllowedHeaders(List.of(
                "Content-Type", "Authorization", "DPoP",
                "OAuth-Client-Attestation", "OAuth-Client-Attestation-PoP",
                "Api-Version"));
        openConfig.setAllowCredentials(false);
        openConfig.setMaxAge(1800L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        // Public resource prefixes (Open CORS)
        source.registerCorsConfiguration("/.well-known/**", openConfig);
        source.registerCorsConfiguration("/oid4vci/**", openConfig);
        source.registerCorsConfiguration("/oauth/**", openConfig);
        source.registerCorsConfiguration("/credential-offer/**", openConfig);
        source.registerCorsConfiguration("/w3c/**", openConfig);
        source.registerCorsConfiguration("/token/**", openConfig);
        source.registerCorsConfiguration("/health", openConfig);
        source.registerCorsConfiguration("/prometheus", openConfig);
        source.registerCorsConfiguration("/springdoc/**", openConfig);
        source.registerCorsConfiguration("/issuance/v1/credentials/status/**", openConfig);

        // Specific public endpoints within restricted prefixes
        source.registerCorsConfiguration("/api/v1/bootstrap", openConfig);

        // Management and Internal APIs (Restricted CORS)
        source.registerCorsConfiguration("/api/**", restrictedConfig);
        source.registerCorsConfiguration("/admin/**", restrictedConfig);

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
