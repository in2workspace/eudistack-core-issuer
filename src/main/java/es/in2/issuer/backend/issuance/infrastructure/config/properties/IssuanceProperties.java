package es.in2.issuer.backend.issuance.infrastructure.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "issuance")
public record IssuanceProperties(
        @DefaultValue("30") int draftMaxAgeDays,
        @DefaultValue("0 0 2 * * *") String cleanupCron,
        @DefaultValue("60") int deliveryTimeoutMinutes,
        @DefaultValue("0 */5 * * * ?") String deliveryTimeoutCron,
        // Time limit of the email/ui delivery flow. The name predates the single delivery mode (EUD-268)
        // and is kept so deployed configuration keeps applying.
        @DefaultValue("30") int hybridWalletTimeoutSeconds
) {
}
