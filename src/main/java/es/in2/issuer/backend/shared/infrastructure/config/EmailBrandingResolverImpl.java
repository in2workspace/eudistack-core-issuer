package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.model.dto.EmailBranding;
import es.in2.issuer.backend.shared.domain.spi.EmailBrandingResolver;
import es.in2.issuer.backend.shared.infrastructure.config.properties.EmailBrandingProperties;
import es.in2.issuer.backend.shared.infrastructure.config.properties.EmailBrandingProperties.DefaultEmailBranding;
import es.in2.issuer.backend.shared.infrastructure.config.properties.EmailBrandingProperties.TenantEmailBranding;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@Component
public class EmailBrandingResolverImpl implements EmailBrandingResolver {

    private static final String LOGO_PATH = "email/logo.png";
    private static final String HEADER_BACKGROUND_PATH = "email/header-bg.png";

    private final EmailBrandingProperties properties;

    public EmailBrandingResolverImpl(EmailBrandingProperties properties) {
        this.properties = properties;
    }

    @Override
    public Mono<EmailBranding> resolve() {
        return Mono.deferContextual(ctx -> Mono.just(resolveFor(ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, ""))));
    }

    EmailBranding resolveFor(String tenantId) {
        DefaultEmailBranding defaults = properties.defaults();
        TenantEmailBranding tenant = properties.tenants().get(tenantId);
        if (tenant == null) {
            return new EmailBranding(null, null, defaults.supportUrl(), defaults.knowledgeBaseUrl(), List.of());
        }
        return new EmailBranding(
                tenant.logo() ? assetUrl(tenantId, LOGO_PATH) : null,
                tenant.headerBackground() ? assetUrl(tenantId, HEADER_BACKGROUND_PATH) : null,
                firstNonBlank(tenant.supportUrl(), defaults.supportUrl()),
                firstNonBlank(tenant.knowledgeBaseUrl(), defaults.knowledgeBaseUrl()),
                tenant.socialLinks() == null ? List.of() : tenant.socialLinks().stream()
                        .map(link -> new EmailBranding.SocialLink(link.type(), link.url()))
                        .toList()
        );
    }

    private String assetUrl(String tenantId, String relativePath) {
        return StringUtils.trimTrailingCharacter(properties.assetsBaseUrl(), '/') + "/" + tenantId + "/"
                + StringUtils.trimLeadingCharacter(relativePath, '/');
    }

    private static String firstNonBlank(String first, String second) {
        return first != null && !first.isBlank() ? first : second;
    }
}
