package es.in2.issuer.backend.shared.infrastructure.config.properties;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "spring.application")
@Validated
public record SpringApplicationProperties(
        @NotBlank String name
) {
}
