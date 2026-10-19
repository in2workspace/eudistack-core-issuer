package es.in2.issuer.backend.shared.infrastructure.config.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import reactor.core.publisher.Mono;

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

    // EUD-266: a front on another origin sends If-Match to change a catalog entry and reads its ETag and
    // Location, and the deprecation notice of the legacy alias (RFC 9745).
    @Test
    void corsWebFilter_preflightOfACatalogEntryChange_allowsIfMatchFromAConfiguredOrigin() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.options("http://localhost/api/v1/attestation-catalog/doctorid.sd.1")
                        .header(HttpHeaders.ORIGIN, ALLOWED_ORIGIN)
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "PUT")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "authorization, content-type, if-match")
                        .build());

        corsConfig.corsWebFilter().filter(exchange, ex -> Mono.empty()).block();

        assertThat(exchange.getResponse().getStatusCode()).isNull();
        assertThat(exchange.getResponse().getHeaders().getAccessControlAllowOrigin()).isEqualTo(ALLOWED_ORIGIN);
        assertThat(exchange.getResponse().getHeaders().getAccessControlAllowHeaders())
                .anyMatch("If-Match"::equalsIgnoreCase);
        assertThat(exchange.getResponse().getHeaders().getAccessControlAllowMethods()).contains(HttpMethod.PUT);
    }

    @Test
    void corsWebFilter_preflightFromAnOriginThatIsNotConfigured_isRejected() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.options("http://localhost/api/v1/attestation-catalog/doctorid.sd.1")
                        .header(HttpHeaders.ORIGIN, "https://evil.example.com")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "PUT")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "if-match")
                        .build());

        corsConfig.corsWebFilter().filter(exchange, ex -> Mono.empty()).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void corsWebFilter_catalogResponse_exposesTheHeadersTheFrontNeeds() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("http://localhost/api/v1/attestation-catalog/doctorid.sd.1")
                        .header(HttpHeaders.ORIGIN, ALLOWED_ORIGIN)
                        .build());

        corsConfig.corsWebFilter().filter(exchange, ex -> Mono.empty()).block();

        assertThat(exchange.getResponse().getHeaders().getAccessControlExposeHeaders())
                .containsExactlyInAnyOrder("ETag", "Location", "Deprecation", "Link");
    }

}
