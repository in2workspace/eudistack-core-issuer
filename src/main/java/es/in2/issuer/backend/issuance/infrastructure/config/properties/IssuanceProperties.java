package es.in2.issuer.backend.issuance.infrastructure.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "issuance")
public record IssuanceProperties(
        @DefaultValue("30") int draftMaxAgeDays,
        @DefaultValue("0 0 2 * * *") String cleanupCron,
        @DefaultValue("60") int deliveryTimeoutMinutes,
        @DefaultValue("0 */5 * * * ?") String deliveryTimeoutCron
) {
}
