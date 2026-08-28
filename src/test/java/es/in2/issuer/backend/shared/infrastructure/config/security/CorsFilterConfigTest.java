package es.in2.issuer.backend.shared.infrastructure.config.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CorsFilterConfigTest {

    private CorsOriginsLoader corsOriginsLoader;
    private CorsFilterConfig corsConfig;
    private static final List<String> ALLOWED_ORIGINS = List.of(
            "https://wallet.example.com",
            "https://another.com",
            "https://*.stg.eudistack.net");

    @BeforeEach
    void setUp() {
        corsOriginsLoader = mock(CorsOriginsLoader.class);
        corsConfig = new CorsFilterConfig(corsOriginsLoader);
        when(corsOriginsLoader.loadOrigins()).thenReturn(ALLOWED_ORIGINS);
    }

    @Test
    void corsWebFilter_IsRegisteredAsStandaloneBean() {
        CorsWebFilter filter = corsConfig.corsWebFilter();
        assertThat(filter).isNotNull();
    }

    @Test
    void CorsConfigurationSource_WellKnownPath_AllowsAllOrigins() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/.well-known/openid-credential-issuer").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedOrigins()).containsExactly("*");
    }

    @Test
    void CorsConfigurationSource_Oid4vciPath_AllowsAllOrigins() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/oid4vci/v1/authorize").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedOrigins()).containsExactly("*");
    }

    // The authorize endpoint returns a 302 redirect. Chrome requires Access-Control-Allow-Origin
    // on that response for cross-origin XHR to follow the redirect and read response.url.
    @Test
    void CorsConfigurationSource_AuthorizePath_AllowsAllOrigins() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/oid4vci/v1/authorize").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedOrigins()).containsExactly("*");
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
                .containsAll(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
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
    void CorsConfigurationSource_ApiPath_AllowsRequiredHeaders() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/issuances").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedHeaders())
                .contains("Content-Type", "Authorization", "DPoP",
                        "OAuth-Client-Attestation", "OAuth-Client-Attestation-PoP",
                        "Api-Version", "X-ID-Token", "X-Idempotency-Key", "X-Tenant",
                        "X-Bootstrap-Token");
    }

    @Test
    void CorsConfigurationSource_RestrictedApiPath_StillAllowsOnlyConfiguredOrigins() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/issuances").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedOriginPatterns()).containsExactlyElementsOf(ALLOWED_ORIGINS);
    }

    @Test
    void CorsConfigurationSource_RestrictedApiPath_ExposesLocationHeader() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/v1/issuances").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getExposedHeaders()).contains("Location");
    }

    @Test
    void CorsConfigurationSource_AdminPath_AllowsRestrictedOrigins() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/admin/v1/credential-catalog").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedOriginPatterns()).containsExactlyElementsOf(ALLOWED_ORIGINS);
    }

    @Test
    void CorsConfigurationSource_BootstrapPath_AllowsAllOriginsAsItIsPublic() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/bootstrap").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedOrigins()).containsExactly("*");
    }

    @Test
    void CorsConfigurationSource_BootstrapPath_AllowsRequiredHeaders() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/v1/bootstrap").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedHeaders()).contains("X-Bootstrap-Token", "Api-Version");
        assertThat(config.getExposedHeaders()).contains("Location");
    }

    @Test
    void CorsConfigurationSource_StatusListPath_AllowsAllOrigins() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/w3c/v1/credentials/status/123").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedOrigins()).containsExactly("*");
    }

    @Test
    void CorsConfigurationSource_TokenStatusListPath_AllowsAllOrigins() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/token/v1/credentials/status/456").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedOrigins()).containsExactly("*");
    }

    @Test
    void CorsConfigurationSource_IssuanceStatusPath_AllowsAllOrigins() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/issuance/v1/credentials/status/789").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedOrigins()).containsExactly("*");
    }

    @Test
    void CorsConfigurationSource_OauthTokenPath_AllowsAllOrigins() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/oauth/token").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedOrigins()).containsExactly("*");
    }

    @Test
    void CorsConfigurationSource_HealthPath_AllowsAllOrigins() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/health").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedOrigins()).containsExactly("*");
    }

    @Test
    void CorsConfigurationSource_PrometheusPath_AllowsAllOrigins() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/prometheus").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedOrigins()).containsExactly("*");
    }

    @Test
    void CorsConfigurationSource_SpringdocPath_AllowsAllOrigins() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/springdoc/swagger-ui.html").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedOrigins()).containsExactly("*");
    }

    @Test
    void CorsConfigurationSource_CredentialOfferRefreshPath_AllowsAllOrigins() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/credential-offer/refresh/123").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedOrigins()).containsExactly("*");
    }
}