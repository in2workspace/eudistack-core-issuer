package es.in2.issuer.backend.shared.domain.model.dto;

import java.util.List;

/**
 * Brand-specific items of a transactional email, already resolved to absolute URLs for a tenant.
 */
public record EmailBranding(
        String logoUrl,
        String headerBackgroundUrl,
        String warningIconUrl,
        String supportUrl,
        String knowledgeBaseUrl,
        List<SocialLink> socialLinks
) {

    public record SocialLink(String type, String url, String iconUrl) {
    }
}
