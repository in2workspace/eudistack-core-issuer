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

    private static final String LOGO_PATH = "email/logo.png";
    private static final String HEADER_BACKGROUND_PATH = "email/header-bg.png";
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
        String folder = tenant != null ? tenantId : properties.defaultFolder();

        return new EmailBranding(
                assetUrl(folder, LOGO_PATH),
                assetUrl(folder, HEADER_BACKGROUND_PATH),
                assetUrl(properties.defaultFolder(), ICONS_PATH + "warning.png"),
                firstNonBlank(tenant != null ? tenant.supportUrl() : null, defaults.supportUrl()),
                firstNonBlank(tenant != null ? tenant.knowledgeBaseUrl() : null, defaults.knowledgeBaseUrl()),
                socialLinks(tenant, defaults)
        );
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
