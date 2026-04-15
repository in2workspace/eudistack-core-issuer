package es.in2.issuer.backend.shared.infrastructure.config.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import java.util.List;

/**
 * CORS configuration for the Issuer.
 *
 * <p>With Atlassian-style routing, our own frontends are same-origin
 * with the APIs — no CORS needed between them.
 *
 * <p>External wallets (different origins) need CORS to call OID4VCI
 * endpoints (credential, nonce, well-known). These are configured
 * with wildcard origin to support any wallet.
 */
@Configuration
public class CorsConfig {

    @Bean
    public UrlBasedCorsConfigurationSource corsConfigurationSource() {
        // Public OID4VCI endpoints — allow any origin (wallets)
        CorsConfiguration publicConfig = new CorsConfiguration();
        publicConfig.setAllowedOriginPatterns(List.of("*"));
        publicConfig.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
        publicConfig.setAllowedHeaders(List.of(
                "Content-Type", "Authorization", "DPoP",
                "OAuth-Client-Attestation", "OAuth-Client-Attestation-PoP"));
        publicConfig.setAllowCredentials(false);
        publicConfig.setMaxAge(1800L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // OID4VCI endpoints called by external wallets
        source.registerCorsConfiguration("/.well-known/**", publicConfig);
        source.registerCorsConfiguration("/oid4vci/**", publicConfig);
        source.registerCorsConfiguration("/oauth/**", publicConfig);
        source.registerCorsConfiguration("/credential-offer/**", publicConfig);
        // API endpoints (backoffice, issuances) — same origin in Atlassian-style
        // If external clients need access, add specific origins via cors-origins.yaml
        source.registerCorsConfiguration("/api/**", publicConfig);

        return source;
    }
}
