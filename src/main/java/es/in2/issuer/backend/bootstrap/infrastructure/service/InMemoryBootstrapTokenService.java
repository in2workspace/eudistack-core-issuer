package es.in2.issuer.backend.bootstrap.infrastructure.service;

import es.in2.issuer.backend.bootstrap.domain.service.BootstrapTokenService;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
@Service
public class InMemoryBootstrapTokenService implements BootstrapTokenService {

    private final AtomicReference<String> token;

    public InMemoryBootstrapTokenService(
            @Value("${BOOTSTRAP_TOKEN:}") String configuredToken) {
        String effectiveToken = (configuredToken != null && !configuredToken.isBlank())
                ? configuredToken
                : UUID.randomUUID().toString();
        this.token = new AtomicReference<>(effectiveToken);
    }

    @PostConstruct
    void printToken() {
        // SEC-04: stdout only — never goes to log aggregator (Loki, ELK, etc.)
        System.out.println("[BOOTSTRAP] One-time token: " + token.get());
    }

    @Override
    public String getToken() {
        return token.get();
    }

    @Override
    public boolean consumeIfValid(String candidate) {
        if (candidate == null || candidate.isBlank()) {
            return false;
        }
        String current = token.get();
        if (current != null && current.equals(candidate)) {
            return token.compareAndSet(current, null);
        }
        return false;
    }
}
