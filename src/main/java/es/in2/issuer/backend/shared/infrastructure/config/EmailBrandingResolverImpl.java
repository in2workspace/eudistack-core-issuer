package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.model.dto.EmailBranding;
import es.in2.issuer.backend.shared.domain.spi.EmailBrandingResolver;
import es.in2.issuer.backend.shared.infrastructure.config.properties.EmailBrandingProperties;
import es.in2.issuer.backend.shared.infrastructure.config.properties.EmailBrandingProperties.SocialLink;
import es.in2.issuer.backend.shared.infrastructure.config.properties.EmailBrandingProperties.TenantEmailBranding;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@Component
public class EmailBrandingResolverImpl implements EmailBrandingResolver {

    private static final String ICONS_PATH = "email/icons/";

    private final EmailBrandingProperties properties;

    public EmailBrandingResolverImpl(EmailBrandingProperties properties) {
        this.properties = properties;
    }

    @Override
    public Mono<EmailBranding> resolve() {
        return Mono.deferContextual(ctx -> Mono.just(resolveFor(ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, ""))));
    }

    EmailBranding resolveFor(String tenantId) {
        TenantEmailBranding defaults = properties.defaults();
        TenantEmailBranding tenant = properties.tenants().get(tenantId);

        return new EmailBranding(
                imageUrl(tenant != null ? tenant.logo() : null, tenantId, defaults.logo()),
                imageUrl(tenant != null ? tenant.headerBackground() : null, tenantId, defaults.headerBackground()),
                assetUrl(properties.defaultFolder(), ICONS_PATH + "warning.png"),
                firstNonBlank(tenant != null ? tenant.supportUrl() : null, defaults.supportUrl()),
                firstNonBlank(tenant != null ? tenant.knowledgeBaseUrl() : null, defaults.knowledgeBaseUrl()),
                socialLinks(tenant, defaults)
        );
    }

    /** A tenant-defined path resolves against the tenant folder; an inherited one against the default folder (D5). */
    private String imageUrl(String tenantPath, String tenantId, String defaultPath) {
        if (notBlank(tenantPath)) {
            return assetUrl(tenantId, tenantPath);
        }
        return notBlank(defaultPath) ? assetUrl(properties.defaultFolder(), defaultPath) : null;
    }

    private List<EmailBranding.SocialLink> socialLinks(TenantEmailBranding tenant, TenantEmailBranding defaults) {
        List<SocialLink> source = tenant != null && tenant.socialLinks() != null && !tenant.socialLinks().isEmpty()
                ? tenant.socialLinks()
                : defaults.socialLinks();
        if (source == null) {
            return List.of();
        }
        return source.stream()
                .map(link -> new EmailBranding.SocialLink(link.type(), link.url(),
                        assetUrl(properties.defaultFolder(), ICONS_PATH + link.type() + ".png")))
                .toList();
    }

    private String assetUrl(String folder, String relativePath) {
        return stripTrailingSlashes(properties.assetsBaseUrl()) + "/" + stripSlashes(folder) + "/"
                + stripLeadingSlashes(relativePath);
    }

    private static String firstNonBlank(String first, String second) {
        return notBlank(first) ? first : second;
    }

    private static boolean notBlank(String value) {
        return value != null && !value.isBlank();
    }

    private static String stripTrailingSlashes(String value) {
        return value.replaceAll("/+$", "");
    }

    private static String stripLeadingSlashes(String value) {
        return value.replaceAll("^/+", "");
    }

    private static String stripSlashes(String value) {
        return stripLeadingSlashes(stripTrailingSlashes(value));
    }
}
