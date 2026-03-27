package es.in2.issuer.backend.shared.infrastructure.config.security;

import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import lombok.RequiredArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Configuration
@RequiredArgsConstructor
public class CorsConfig {

    private final AppConfig appConfig;
    private final CorsOriginsLoader corsOriginsLoader;

    @Bean
    public UrlBasedCorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        List<String> origins = new ArrayList<>();
        origins.add(appConfig.getIssuerFrontendUrl());
        origins.add(appConfig.getWalletFrontendUrl());
        origins.addAll(corsOriginsLoader.loadOrigins());

        config.setAllowedOrigins(origins);
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(false);
        config.setMaxAge(1800L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
