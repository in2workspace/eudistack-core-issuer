package es.in2.issuer.backend.shared.infrastructure.config.health;

import es.in2.issuer.backend.signing.infrastructure.config.RuntimeSigningConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.ReactiveHealthIndicator;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Health indicator for the signing service.
 * Reports the active signing provider and whether remote signature is configured.
 */
@Component
@RequiredArgsConstructor
public class SigningServiceHealthIndicator implements ReactiveHealthIndicator {

    private final RuntimeSigningConfig runtimeSigningConfig;

    @Override
    public Mono<Health> health() {
        return Mono.fromSupplier(() -> {
            String provider = runtimeSigningConfig.getProvider();
            boolean remoteConfigured = runtimeSigningConfig.getRemoteSignature() != null;

            Health.Builder builder = Health.up()
                    .withDetail("provider", provider)
                    .withDetail("remoteConfigured", remoteConfigured);

            if ("remote".equalsIgnoreCase(provider) && !remoteConfigured) {
                builder = Health.down()
                        .withDetail("provider", provider)
                        .withDetail("reason", "Remote provider selected but no remote signature configured");
            }

            return builder.build();
        });
    }
}
