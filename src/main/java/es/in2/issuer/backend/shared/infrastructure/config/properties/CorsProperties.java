package es.in2.issuer.backend.shared.infrastructure.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "app.cors")
@Validated
public record CorsProperties(
        String originsPath
) {
}
