package es.in2.issuer.backend.shared.infrastructure.config.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CorsConfigTest {

    private static final String ALLOWED_ORIGIN = "https://portal.example.org";

    private final CorsOriginsLoader corsOriginsLoader = mock(CorsOriginsLoader.class);
    private CorsConfig corsConfig;

    @BeforeEach
    void setUp() {
        when(corsOriginsLoader.loadOrigins()).thenReturn(List.of(ALLOWED_ORIGIN));
        corsConfig = new CorsConfig(corsOriginsLoader);
    }

    @Test
    void corsWebFilter_IsRegisteredAsStandaloneBean() {
        CorsWebFilter filter = corsConfig.corsWebFilter();
        assertThat(filter).isNotNull();
    }

    // Public OID4VCI paths called by external wallets. The authorize endpoint returns a 302 redirect and
    // Chrome requires Access-Control-Allow-Origin on that response for cross-origin XHR to follow it.
    @ParameterizedTest
    @ValueSource(strings = {
            "/.well-known/openid-credential-issuer",
            "/oid4vci/credential",
            "/oid4vci/v1/authorize",
            "/oauth/token",
            "/credential-offer/abc",
            "/w3c/v1/credentials/status/1",
            "/token/v1/credentials/status/1"})
    void CorsConfigurationSource_PublicWalletPaths_AllowAnyOriginWithoutCredentials(String path) {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get(path).build());

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedOriginPatterns()).contains("*");
        assertThat(config.getAllowCredentials()).isNotEqualTo(Boolean.TRUE);
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

    @Test
    void CorsConfigurationSource_ApiPath_OnlyAllowsConfiguredOrigins() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/issuances").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedOrigins()).containsExactly(ALLOWED_ORIGIN);
        assertThat(config.getAllowedOriginPatterns()).isNullOrEmpty();
        assertThat(config.checkOrigin(ALLOWED_ORIGIN)).isEqualTo(ALLOWED_ORIGIN);
        assertThat(config.checkOrigin("https://evil.example.com")).isNull();
    }

    @Test
    void CorsConfigurationSource_ApiPathWithoutConfiguredOrigins_RejectsEveryCrossOrigin() {
        when(corsOriginsLoader.loadOrigins()).thenReturn(List.of());
        UrlBasedCorsConfigurationSource source = new CorsConfig(corsOriginsLoader).corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/me").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.checkOrigin("https://portal.example.org")).isNull();
    }

    @Test
    void CorsConfigurationSource_ApiPath_AllowsWriteMethodsForConfiguredOrigins() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/backoffice/credential-catalog").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedMethods()).contains("PUT", "DELETE");
    }

}
