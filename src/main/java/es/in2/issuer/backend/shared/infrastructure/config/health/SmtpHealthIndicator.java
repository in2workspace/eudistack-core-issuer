package es.in2.issuer.backend.shared.infrastructure.config.health;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.ReactiveHealthIndicator;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import jakarta.mail.Transport;
import jakarta.mail.Session;

/**
 * Health indicator that verifies SMTP connectivity.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SmtpHealthIndicator implements ReactiveHealthIndicator {

    private final JavaMailSender mailSender;

    @Override
    public Mono<Health> health() {
        return Mono.fromCallable(() -> {
            try {
                if (mailSender instanceof org.springframework.mail.javamail.JavaMailSenderImpl impl) {
                    Session session = impl.getSession();
                    try (Transport transport = session.getTransport("smtp")) {
                        transport.connect(impl.getHost(), impl.getPort(), impl.getUsername(), impl.getPassword());
                    }
                    return Health.up()
                            .withDetail("host", impl.getHost())
                            .withDetail("port", impl.getPort())
                            .build();
                }
                return Health.unknown().withDetail("reason", "mailSender type not supported").build();
            } catch (Exception e) {
                log.debug("SMTP health check failed: {}", e.getMessage());
                return Health.down().withDetail("error", e.getMessage()).build();
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }
}
