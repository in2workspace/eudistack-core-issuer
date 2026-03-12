package es.in2.issuer.backend.shared.infrastructure.config.health;

import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.ReactiveHealthIndicator;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Health indicator that pings the verifier's well-known endpoint.
 */
@Component
@RequiredArgsConstructor
public class VerifierHealthIndicator implements ReactiveHealthIndicator {

    private final WebClient.Builder webClientBuilder;
    private final AppConfig appConfig;

    @Override
    public Mono<Health> health() {
        String verifierUrl = appConfig.getVerifierUrl();
        if (verifierUrl == null || verifierUrl.isBlank()) {
            return Mono.just(Health.unknown().withDetail("reason", "verifier-url not configured").build());
        }

        return webClientBuilder.build()
                .get()
                .uri(verifierUrl + "/.well-known/openid-configuration")
                .retrieve()
                .toBodilessEntity()
                .map(response -> Health.up()
                        .withDetail("verifierUrl", verifierUrl)
                        .build())
                .timeout(Duration.ofSeconds(5))
                .onErrorResume(e -> Mono.just(Health.down()
                        .withDetail("verifierUrl", verifierUrl)
                        .withDetail("error", e.getMessage())
                        .build()));
    }
}
