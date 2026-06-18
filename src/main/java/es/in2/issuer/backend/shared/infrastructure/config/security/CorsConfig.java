package es.in2.issuer.backend.shared.infrastructure.config.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import java.util.List;

/**
 * CORS configuration for the Issuer.
 *
 * <p>External wallets always call from a different origin (cross-domain deployments
 * like DOME where issuer and wallet have separate domains). All OID4VCI endpoints
 * must return Access-Control-Allow-Origin on every response in the redirect chain,
 * including 302 responses from the authorize endpoint.
 *
 * <p>A single /** pattern is used instead of per-path entries to ensure coverage
 * regardless of the server context path (spring.webflux.base-path). Path-specific
 * entries are matched after the base-path is stripped by the reactive
 * UrlBasedCorsConfigurationSource, but proxy-level stripping is not guaranteed,
 * so wildcard coverage is the only reliable approach.
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
        source.registerCorsConfiguration("/**", publicConfig);

        return source;
    }
}
