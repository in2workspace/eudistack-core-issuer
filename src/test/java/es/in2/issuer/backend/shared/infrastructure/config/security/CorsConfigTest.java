package es.in2.issuer.backend.shared.infrastructure.config.security;

import es.in2.issuer.backend.shared.infrastructure.config.properties.AppProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
class CorsConfigTest {

    @Mock
    private AppProperties appProperties;

    @InjectMocks
    private CorsConfig corsConfig;

    @BeforeEach
    void setUp() {
        lenient().when(appProperties.issuerFrontendUrl()).thenReturn("https://mock-issuer");
    }


    @Test
    void corsConfigurationSource_shouldAllowSpecificOrigins() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();

        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/any/path").build()
        );
        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertNotNull(config);
        java.util.List<String> origins = config.getAllowedOrigins() != null
                ? config.getAllowedOrigins()
                : config.getAllowedOriginPatterns();

        java.util.Objects.requireNonNull(origins);

        assertTrue(origins.contains("https://mock-issuer"));
        assertFalse(origins.contains("*"));
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
