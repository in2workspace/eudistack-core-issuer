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

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CorsConfigTest {

    @Mock
    private AppConfig appConfig;

    @Mock
    private CorsOriginsLoader corsOriginsLoader;

    @InjectMocks
    private CorsConfig corsConfig;

    private void stubBaseOrigins() {
        when(appConfig.getIssuerFrontendUrl()).thenReturn("https://mock-issuer");
        when(appConfig.getWalletFrontendUrl()).thenReturn("https://mock-wallet");
        when(corsOriginsLoader.loadOrigins()).thenReturn(Collections.emptyList());
    }

    @Test
    void CorsConfigurationSource_FrontendUrlsConfigured_AllowsConfiguredOrigins() {
        stubBaseOrigins();

        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/any/path").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config.getAllowedOrigins()).contains("https://mock-issuer", "https://mock-wallet");
    }

    @Test
    void CorsConfigurationSource_WithYamlOrigins_MergesAllOrigins() {
        when(appConfig.getIssuerFrontendUrl()).thenReturn("https://mock-issuer");
        when(appConfig.getWalletFrontendUrl()).thenReturn("https://mock-wallet");
        when(corsOriginsLoader.loadOrigins()).thenReturn(List.of(
                "https://issuer-core-stg.api.altia.eudistack.net",
                "https://wallet-stg.altia.eudistack.net"
        ));

        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/any/path").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config.getAllowedOrigins()).containsExactlyInAnyOrder(
                "https://mock-issuer",
                "https://mock-wallet",
                "https://issuer-core-stg.api.altia.eudistack.net",
                "https://wallet-stg.altia.eudistack.net"
        );
    }

    @Test
    void CorsConfigurationSource_FrontendUrlsConfigured_AllowsStandardHttpMethods() {
        stubBaseOrigins();

        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/any/path").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config.getAllowedMethods())
                .isNotNull()
                .containsAll(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    }

    @Test
    void CorsConfigurationSource_FrontendUrlsConfigured_DoesNotAllowCredentials() {
        stubBaseOrigins();

        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/any/path").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config.getAllowCredentials()).isNotEqualTo(Boolean.TRUE);
    }
}
