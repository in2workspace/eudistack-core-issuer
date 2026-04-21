package es.in2.issuer.backend.shared.infrastructure.config.properties;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.hibernate.validator.constraints.URL;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "app")
@Validated
public record AppProperties(
        @NotBlank @URL String url,
        @URL String internalUrl,
        @NotBlank @URL String issuerFrontendUrl,
        @NotNull KnowledgeBase knowledgeBase,
        @NotBlank @URL String verifierUrl,
        @URL String verifierInternalUrl,
        @NotBlank @URL String walletUrl,
        @NotBlank String defaultLang,
        @NotBlank String sysTenant,
        ManagementToken managementToken
) {

    @Validated
    public record KnowledgeBase(
            @NotBlank @URL String uploadCertificationGuideUrl,
            @NotBlank @URL String walletGuideUrl
    ) {
    }

    @Validated
    public record ManagementToken(
            @NotBlank String orgIdJsonPath,
            @NotBlank String adminPowerFunction,
            @NotBlank String adminPowerAction
    ) {
    }
}
