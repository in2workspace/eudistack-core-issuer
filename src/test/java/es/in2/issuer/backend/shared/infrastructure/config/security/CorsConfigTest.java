package es.in2.issuer.backend.shared.infrastructure.config.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CorsConfigTest {

    private final CorsConfig corsConfig = new CorsConfig();

    @Test
    void CorsConfigurationSource_WellKnownPath_AllowsAnyOriginForExternalWallets() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/.well-known/openid-credential-issuer").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedOriginPatterns()).contains("*");
    }

    @Test
    void CorsConfigurationSource_Oid4vciPath_AllowsAnyOriginForExternalWallets() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/oid4vci/credential").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedOriginPatterns()).contains("*");
    }

    @Test
    void CorsConfigurationSource_ApiPath_AllowsStandardHttpMethods() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/issuances").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedMethods())
                .containsAll(List.of("GET", "POST", "OPTIONS"));
    }

    @Test
    void CorsConfigurationSource_ApiPath_DoesNotAllowCredentials() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/issuances").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowCredentials()).isNotEqualTo(Boolean.TRUE);
    }

    @Test
    void CorsConfigurationSource_ApiPath_AllowsDpopAndAttestationHeaders() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/oauth/token").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedHeaders())
                .contains("Content-Type", "Authorization", "DPoP",
                        "OAuth-Client-Attestation", "OAuth-Client-Attestation-PoP");
    }
}
