package es.in2.issuer.backend.dome.infrastructure.adapter.cli;

import es.in2.issuer.backend.dome.infrastructure.config.properties.KeyMigrationProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("key-migration")
@RequiredArgsConstructor
@Slf4j
public class CliOperatorAuthFilter {

    private final KeyMigrationProperties properties;

    public void validatePlanA(String operatorId) {
        if (operatorId == null || operatorId.isBlank()) {
            throw new IllegalStateException("operatorId must not be blank");
        }
        if (!properties.planAEnabled()) {
            throw new IllegalStateException("Plan A not enabled");
        }
        log.info("pre-flight approved operatorId={}", mask(operatorId));
    }

    private String mask(String value) {
        if (value == null || value.length() <= 4) {
            return "****";
        }
        return value.substring(0, 4) + "****";
    }
}

