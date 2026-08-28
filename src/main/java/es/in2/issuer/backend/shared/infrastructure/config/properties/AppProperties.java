package es.in2.issuer.backend.shared.infrastructure.config.properties;

import jakarta.validation.constraints.NotBlank;
import org.hibernate.validator.constraints.URL;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Application settings.
 *
 * <p>{@code url} and {@code verifierUrl} were removed in EUDI-017: public
 * URLs are derived at runtime from the request exchange via
 * {@link es.in2.issuer.backend.shared.domain.spi.UrlResolver}. The internal
 * URLs stay because out-of-request callers (health indicator, the resolver
 * itself when rewriting a public verifier URL to its intra-VPC peer) still
 * need them, and they must carry the service base-path
 * (e.g. {@code http://verifier-core.stg.eudistack.local:8080/verifier}).
 */
@ConfigurationProperties(prefix = "app")
@Validated
public record AppProperties(
        @NotBlank @URL String internalUrl,
        @NotBlank @URL String verifierInternalUrl,
        @NotBlank String defaultLang,
        @NotBlank String sysTenant,
        ManagementToken managementToken
) {

    @Validated
    public record ManagementToken(
            @NotBlank String orgIdJsonPath,
            @NotBlank String adminPowerFunction,
            @NotBlank String adminPowerAction
    ) {
    }
}
