package es.in2.issuer.backend.shared.infrastructure.config.properties;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.boot.context.properties.bind.Name;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Branding data of the transactional emails (support and knowledge-base links, social links),
 * per tenant with fallback to {@link #defaults()}. Images are not configured: they follow the
 * fixed names {@code email/logo.png} and {@code email/header-bg.png} inside the tenant folder
 * under {@code assetsBaseUrl}.
 */
@ConfigurationProperties(prefix = "email-branding")
@Validated
public record EmailBrandingProperties(
        @NotBlank String assetsBaseUrl,
        @NotBlank @DefaultValue("eudistack") String defaultFolder,
        @Name("default") @NotNull @Valid TenantEmailBranding defaults,
        @DefaultValue Map<String, @Valid TenantEmailBranding> tenants
) {

    public static final Set<String> SOCIAL_LINK_TYPES = Set.of("github", "linkedin");

    public record TenantEmailBranding(
            String supportUrl,
            String knowledgeBaseUrl,
            @DefaultValue List<@Valid SocialLink> socialLinks
    ) {
    }

    public record SocialLink(
            @NotBlank String type,
            @NotBlank String url
    ) {
        public SocialLink {
            if (type != null && !SOCIAL_LINK_TYPES.contains(type)) {
                throw new IllegalArgumentException(
                        "Unknown email-branding social link type '" + type + "'. Allowed: " + SOCIAL_LINK_TYPES);
            }
        }
    }
}
