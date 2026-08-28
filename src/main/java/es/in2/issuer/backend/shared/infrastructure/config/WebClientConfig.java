package es.in2.issuer.backend.shared.infrastructure.config;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.reactive.function.client.WebClientCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import reactor.netty.resources.ConnectionProvider;

import java.time.Duration;

@Configuration
@RequiredArgsConstructor
public class WebClientConfig {
    private final AppConfig appConfig;

    private static final ConnectionProvider connectionProvider = ConnectionProvider.builder("custom")
            .maxConnections(500)
            .maxIdleTime(Duration.ofSeconds(50))
            .maxLifeTime(Duration.ofSeconds(300))
            .evictInBackground(Duration.ofSeconds(80))
            .build();

    // Applies the tuned connectionProvider (idle eviction) to the auto-configured WebClient.Builder
    // that HttpUtils and other components inject directly, so pooled connections to external
    // services (e.g. the QTSP remote-signature endpoint) don't get reused after the peer has
    // already closed them — the cause of "Connection reset by peer" on the first call after a gap.
    @Bean
    public WebClientCustomizer webClientCustomizer() {
        return builder -> builder.clientConnector(
                new ReactorClientHttpConnector(HttpClient.create(connectionProvider).followRedirect(false)));
    }

    @Bean
    public WebClient commonWebClient() {
        return WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(
                        HttpClient.create(connectionProvider).followRedirect(false))
                )
                .build();
    }

    @Bean
    public WebClient oauth2VerifierWebClient() {
        return WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(HttpClient.create(connectionProvider)
                        .baseUrl(appConfig.getVerifierInternalUrl())
                        .followRedirect(false))
                )
                .build();
    }

}
