package es.in2.issuer.backend.shared.infrastructure.config.health;

import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.ReactiveHealthIndicator;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Health indicator for the signing subsystem.
 *
 * <p>Signing configuration is per-tenant ({@code tenant_signing_config}); there
 * is no global default. This health check only reports whether the signing
 * module is wired. Per-tenant QTSP reachability is exercised on actual
 * signing requests.
 */
@Component
public class SigningServiceHealthIndicator implements ReactiveHealthIndicator {

    @Override
    public Mono<Health> health() {
        return Mono.just(Health.up()
                .withDetail("mode", "per-tenant (tenant_signing_config)")
                .build());
    }
}
