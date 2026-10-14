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
 * Branding data of the transactional emails, per tenant. Only the support and knowledge-base links
 * fall back to {@link #defaults()}; images and social links show only when the tenant's own block
 * enables them. Image locations are not configured: they follow the fixed names
 * {@code email/logo.png} and {@code email/header-bg.png} inside the tenant folder under
 * {@code assetsBaseUrl}.
 */
@ConfigurationProperties(prefix = "email-branding")
@Validated
public record EmailBrandingProperties(
        @NotBlank String assetsBaseUrl,
        @Name("default") @NotNull @Valid DefaultEmailBranding defaults,
        @DefaultValue Map<String, @Valid TenantEmailBranding> tenants
) {

    public static final Set<String> SOCIAL_LINK_TYPES = Set.of("github", "linkedin");

    /** Links used by tenants that do not define their own. Required: every email links to them. */
    public record DefaultEmailBranding(
            @NotBlank String supportUrl,
            @NotBlank String knowledgeBaseUrl
    ) {
    }

    /**
     * A tenant's own branding. {@code logo} / {@code headerBackground} state that the tenant folder holds
     * that image; without them (or without a block) the email shows none.
     */
    public record TenantEmailBranding(
            String supportUrl,
            String knowledgeBaseUrl,
            @DefaultValue("false") boolean logo,
            @DefaultValue("false") boolean headerBackground,
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
