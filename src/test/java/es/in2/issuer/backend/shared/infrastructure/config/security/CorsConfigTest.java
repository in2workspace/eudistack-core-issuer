package es.in2.issuer.backend.shared.infrastructure.config.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CorsConfigTest {

    private final CorsConfig corsConfig = new CorsConfig();

    @Test
    void corsConfigurationSource_shouldAllowAnyOrigin() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();

        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/any/path").build()
        );
        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertNotNull(config);
        assertNotNull(config.getAllowedOriginPatterns());
        assertTrue(config.getAllowedOriginPatterns().contains("*"));
    }

    @Test
    void corsConfigurationSource_shouldAllowStandardMethods() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();

        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/any/path").build()
        );
        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertNotNull(config);
        assertNotNull(config.getAllowedMethods());
        assertTrue(config.getAllowedMethods().containsAll(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS")));
    }

    @Test
    void corsConfigurationSource_shouldNotAllowCredentials() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();

        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/any/path").build()
        );
        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertNotNull(config);
        assertFalse(Boolean.TRUE.equals(config.getAllowCredentials()));
    }
}
