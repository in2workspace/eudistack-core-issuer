package es.in2.issuer.backend.shared.domain.model.dto;

import java.util.List;

/**
 * Brand-specific items of a transactional email, already resolved to absolute URLs for a tenant.
 * {@code logoUrl} / {@code headerBackgroundUrl} are null when the tenant has no such image, and
 * {@code socialLinks} is empty when it has none: the templates then omit them.
 * Common icons (warning, social networks) are not branding: they ship with the app as inline images.
 */
public record EmailBranding(
        String logoUrl,
        String headerBackgroundUrl,
        String supportUrl,
        String knowledgeBaseUrl,
        List<SocialLink> socialLinks
) {

    public record SocialLink(String type, String url) {
    }
}
