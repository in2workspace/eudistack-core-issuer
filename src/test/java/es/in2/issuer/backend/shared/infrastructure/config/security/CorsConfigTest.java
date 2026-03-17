package es.in2.issuer.backend.shared.infrastructure.config.security;

import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CorsConfigTest {

    @Mock
    private AppConfig appConfig;

    @InjectMocks
    private CorsConfig corsConfig;

    @Test
    void corsConfigurationSource_shouldAllowSpecificOrigins() {
        when(appConfig.getIssuerFrontendUrl()).thenReturn("https://mock-issuer");
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();

        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/any/path").build()
        );
        CorsConfiguration config = source.getCorsConfiguration(exchange);

        List<String> origins = config.getAllowedOrigins();

        assertThat(origins).contains("https://mock-issuer");
    }

    @Test
    void corsConfigurationSource_shouldAllowStandardMethods() {
        when(appConfig.getIssuerFrontendUrl()).thenReturn("https://mock-issuer");
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();

        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/any/path").build()
        );
        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedMethods())
                .isNotNull()
                .containsAll(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    }

    @Test
    void corsConfigurationSource_shouldNotAllowCredentials() {
        when(appConfig.getIssuerFrontendUrl()).thenReturn("https://mock-issuer");
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();

        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/any/path").build()
        );
        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowCredentials()).isNotEqualTo(Boolean.TRUE);
    }
}
