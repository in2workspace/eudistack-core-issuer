package es.in2.issuer.backend.dome.infrastructure.adapter.cli;

import es.in2.issuer.backend.dome.infrastructure.config.properties.KeyMigrationProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * Pre-flight validation filter for CLI migration commands.
 * Ensures that the operator identifier is present and the relevant plan is enabled
 * before any destructive or irreversible key migration step is executed.
 */
@Slf4j
@Component
@Profile("key-migration")
@RequiredArgsConstructor
public class CliOperatorAuthFilter {

    private final KeyMigrationProperties properties;

    /**
     * Validates pre-conditions for a Plan-A command.
     *
     * @param operatorId the operator identifier supplied via CLI
     * @throws IllegalStateException if operatorId is blank or Plan-A is disabled
     */
    public void validatePlanA(String operatorId) {
        if (operatorId == null || operatorId.isBlank()) {
            throw new IllegalStateException("operatorId must not be blank");
        }
        if (!properties.planAEnabled()) {
            throw new IllegalStateException("Plan A is not enabled (issuer.dome.key-migration.plan-a-enabled=false)");
        }
        log.info("pre-flight Plan-A approved operatorId={}", mask(operatorId));
    }

    /**
     * Validates pre-conditions for a Plan-B command.
     *
     * @param operatorId the operator identifier supplied via CLI
     * @throws IllegalStateException if operatorId is blank or Plan-B is disabled
     */
    public void validatePlanB(String operatorId) {
        if (operatorId == null || operatorId.isBlank()) {
            throw new IllegalStateException("operatorId must not be blank");
        }
        if (!properties.planBEnabled()) {
            throw new IllegalStateException("Plan B is not enabled (issuer.dome.key-migration.plan-b-enabled=false)");
        }
        log.info("pre-flight Plan-B approved operatorId={}", mask(operatorId));
    }

    /**
     * Masks an operator ID showing only the first 4 characters.
     * Never logs the full value for traceability without leaking sensitive identifiers.
     */
    private String mask(String operatorId) {
        int end = Math.min(4, operatorId.length());
        return operatorId.substring(0, end) + "****";
    }
}

