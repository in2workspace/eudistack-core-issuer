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
        String verifierUrl = appConfig.getVerifierInternalUrl();
        if (verifierUrl == null || verifierUrl.isBlank()) {
            return Mono.just(Health.unknown().withDetail("reason", "verifier-url not configured").build());
        }

        // Verifier mounts all endpoints under its own base-path (/verifier).
        // Using its /health keeps the probe semantically correct and avoids
        // leaking assumptions about which well-known documents are exposed.
        String base = stripTrailingSlash(verifierUrl);
        String probeUrl = base.endsWith("/verifier") ? base + "/health" : base + "/verifier/health";
        return webClientBuilder.build()
                .get()
                .uri(probeUrl)
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

    private static String stripTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
