package es.in2.issuer.backend.shared.infrastructure.adapter.email;

import es.in2.issuer.backend.shared.domain.model.dto.EmailBranding;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

import java.util.List;
import java.util.Locale;

/** Renders the real templates with the real message bundles, outside Spring, for template tests and previews. */
final class EmailTemplateTestSupport {

    static final String ASSETS = "https://assets.example.com/assets/tenants";

    /** A tenant without its own block: default links, no images, no social links. */
    static final EmailBranding DEFAULT_BRANDING = new EmailBranding(
            null,
            null,
            "https://support.eudistack.example/help",
            "https://docs.eudistack.example/",
            List.of());

    static final EmailBranding DOME_BRANDING = new EmailBranding(
            ASSETS + "/dome/email/logo.png",
            ASSETS + "/dome/email/header-bg.png",
            "https://ticketing.dome.example/",
            "https://docs.eudistack.example/",
            List.of(
                    new EmailBranding.SocialLink("github", "https://github.com/dome-example"),
                    new EmailBranding.SocialLink("linkedin", "https://www.linkedin.com/company/dome-example")));

    private EmailTemplateTestSupport() {
    }

    static SpringTemplateEngine engine() {
        ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();
        messageSource.setBasename("messages/messages");
        messageSource.setDefaultEncoding("UTF-8");
        messageSource.setFallbackToSystemLocale(false);

        ClassLoaderTemplateResolver resolver = new ClassLoaderTemplateResolver();
        resolver.setPrefix("templates/");
        resolver.setSuffix(".html");
        resolver.setTemplateMode(TemplateMode.HTML);
        resolver.setCharacterEncoding("UTF-8");
        resolver.setCacheable(false);

        SpringTemplateEngine engine = new SpringTemplateEngine();
        engine.setTemplateResolver(resolver);
        engine.setMessageSource(messageSource);
        return engine;
    }

    static Context baseContext(Locale locale, EmailBranding branding, String tenantDisplayName) {
        Context ctx = new Context(locale);
        ctx.setVariable("branding", branding);
        ctx.setVariable("tenantDisplayName", tenantDisplayName);
        return ctx;
    }

    static Context txCodeContext(Locale locale, EmailBranding branding, String txCode) {
        Context ctx = baseContext(locale, branding, "Tenant");
        ctx.setVariable("txCode", txCode);
        return ctx;
    }

    static Context offerContext(Locale locale, EmailBranding branding, String txCode) {
        Context ctx = baseContext(locale, branding, "Tenant");
        ctx.setVariable("organization", "ACME Corp");
        ctx.setVariable("qrImageCid", "cid:qr-credential-offer.png");
        ctx.setVariable("walletDeepLink", "https://wallet.example.com/callback?credential_offer_uri=abc");
        ctx.setVariable("reissueUrl", "https://issuer.example.com/credential-offer-refresh/token");
        if (txCode != null) {
            ctx.setVariable("txCode", txCode);
        }
        return ctx;
    }

    static Context statusContext(Locale locale, EmailBranding branding, boolean revoked) {
        Context ctx = baseContext(locale, branding, "Tenant");
        ctx.setVariable("credentialId", "cred-123");
        ctx.setVariable("type", "learcredential.employee.w3c.4");
        ctx.setVariable("credentialStatus", revoked ? "REVOKED" : "EXPIRED");
        ctx.setVariable("title", revoked ? "Your Credential Has Been Revoked" : "Your Credential Has Expired");
        ctx.setVariable("statusKeyPrefix", revoked ? "email.revoked" : "email.expired");
        ctx.setVariable("statusWordColor", revoked ? "#E5483B" : "#B89C14");
        ctx.setVariable("badgeBackground", revoked ? "#F8A9A9" : "#FCEFC0");
        ctx.setVariable("badgeTextColor", revoked ? "#7A1F1F" : "#8A750F");
        return ctx;
    }

    static Context failureContext(Locale locale, EmailBranding branding, String eventDescription) {
        Context ctx = baseContext(locale, branding, "Tenant");
        ctx.setVariable("eventDescription", eventDescription);
        return ctx;
    }
}
