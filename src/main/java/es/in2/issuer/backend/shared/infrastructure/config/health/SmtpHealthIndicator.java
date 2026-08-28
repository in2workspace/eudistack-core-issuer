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
                    // Port 465 and mail.smtp.ssl.enable=true use implicit TLS, which requires
                    // the "smtps" transport. Plain "smtp" hangs the socket until timeout.
                    String protocol = useSmtps(impl, session) ? "smtps" : "smtp";
                    try (Transport transport = session.getTransport(protocol)) {
                        transport.connect(impl.getHost(), impl.getPort(), impl.getUsername(), impl.getPassword());
                    }
                    return Health.up()
                            .withDetail("host", impl.getHost())
                            .withDetail("port", impl.getPort())
                            .withDetail("protocol", protocol)
                            .build();
                }
                return Health.unknown().withDetail("reason", "mailSender type not supported").build();
            } catch (Exception e) {
                log.debug("SMTP health check failed: {}", e.getMessage());
                return Health.down().withDetail("error", e.getMessage()).build();
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }

    private static boolean useSmtps(org.springframework.mail.javamail.JavaMailSenderImpl impl, Session session) {
        if (impl.getPort() == 465) {
            return true;
        }
        String sslEnable = session.getProperty("mail.smtp.ssl.enable");
        return "true".equalsIgnoreCase(sslEnable);
    }
}
