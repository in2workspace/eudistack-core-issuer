package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.model.dto.EmailBranding;
import es.in2.issuer.backend.shared.infrastructure.config.properties.EmailBrandingProperties;
import es.in2.issuer.backend.shared.infrastructure.config.properties.EmailBrandingProperties.SocialLink;
import es.in2.issuer.backend.shared.infrastructure.config.properties.EmailBrandingProperties.TenantEmailBranding;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EmailBrandingResolverImplTest {

    private static final String BASE = "https://assets.example.com/assets/tenants";

    private static EmailBrandingResolverImpl resolver(String baseUrl) {
        TenantEmailBranding defaults = new TenantEmailBranding(
                "https://support.default", "https://kb.default", List.of());
        TenantEmailBranding dome = new TenantEmailBranding(
                "https://support.dome", null,
                List.of(new SocialLink("github", "https://github.com/dome"),
                        new SocialLink("linkedin", "https://linkedin.com/dome")));
        TenantEmailBranding linksOnly = new TenantEmailBranding(null, "https://kb.acme", List.of());
        return new EmailBrandingResolverImpl(new EmailBrandingProperties(
                baseUrl, "eudistack", defaults, Map.of("dome", dome, "acme", linksOnly)));
    }

    @Test
    void resolveFor_tenantWithBlock_usesOwnFolderForBothImages() {
        EmailBranding branding = resolver(BASE).resolveFor("dome");

        assertThat(branding.logoUrl()).isEqualTo(BASE + "/dome/email/logo.png");
        assertThat(branding.headerBackgroundUrl()).isEqualTo(BASE + "/dome/email/header-bg.png");
        assertThat(branding.supportUrl()).isEqualTo("https://support.dome");
    }

    @Test
    void resolveFor_tenantWithoutBlock_usesDefaultFolderAndDefaultLinks() {
        EmailBranding branding = resolver(BASE).resolveFor("sandbox");

        assertThat(branding.logoUrl()).isEqualTo(BASE + "/eudistack/email/logo.png");
        assertThat(branding.headerBackgroundUrl()).isEqualTo(BASE + "/eudistack/email/header-bg.png");
        assertThat(branding.supportUrl()).isEqualTo("https://support.default");
        assertThat(branding.knowledgeBaseUrl()).isEqualTo("https://kb.default");
        assertThat(branding.socialLinks()).isEmpty();
    }

    @Test
    void resolveFor_partialLinkOverride_inheritsMissingLinksFromDefault() {
        EmailBranding branding = resolver(BASE).resolveFor("dome");

        assertThat(branding.knowledgeBaseUrl()).isEqualTo("https://kb.default");

        EmailBranding acme = resolver(BASE).resolveFor("acme");

        assertThat(acme.logoUrl()).isEqualTo(BASE + "/acme/email/logo.png");
        assertThat(acme.supportUrl()).isEqualTo("https://support.default");
        assertThat(acme.knowledgeBaseUrl()).isEqualTo("https://kb.acme");
        assertThat(acme.socialLinks()).isEmpty();
    }

    @Test
    void resolveFor_socialLinks_useCommonIconsFromDefaultFolder() {
        EmailBranding branding = resolver(BASE).resolveFor("dome");

        assertThat(branding.socialLinks()).containsExactly(
                new EmailBranding.SocialLink("github", "https://github.com/dome",
                        BASE + "/eudistack/email/icons/github.png"),
                new EmailBranding.SocialLink("linkedin", "https://linkedin.com/dome",
                        BASE + "/eudistack/email/icons/linkedin.png"));
        assertThat(branding.warningIconUrl()).isEqualTo(BASE + "/eudistack/email/icons/warning.png");
    }

    @Test
    void resolveFor_slashesInBaseAndPaths_areNormalised() {
        TenantEmailBranding defaults = new TenantEmailBranding("s", "k", List.of());
        EmailBrandingResolverImpl resolver = new EmailBrandingResolverImpl(new EmailBrandingProperties(
                BASE + "//", "/eudistack/", defaults, Map.of()));

        assertThat(resolver.resolveFor("x").logoUrl()).isEqualTo(BASE + "/eudistack/email/logo.png");
    }

    @Test
    void resolve_readsTenantFromReactorContext() {
        StepVerifier.create(resolver(BASE).resolve()
                        .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "dome")))
                .assertNext(b -> assertThat(b.logoUrl()).isEqualTo(BASE + "/dome/email/logo.png"))
                .verifyComplete();
    }

    @Test
    void resolve_withoutTenantInContext_usesDefault() {
        StepVerifier.create(resolver(BASE).resolve())
                .assertNext(b -> assertThat(b.logoUrl()).isEqualTo(BASE + "/eudistack/email/logo.png"))
                .verifyComplete();
    }

    // --- Binding -----------------------------------------------------------------------------

    @Configuration
    @EnableConfigurationProperties(EmailBrandingProperties.class)
    static class PropertiesConfig {
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withInitializer(new ConfigDataApplicationContextInitializer())
            .withUserConfiguration(PropertiesConfig.class);

    @Test
    void binding_applicationYaml_bindsDefaultsAndDomeBlock() {
        runner.withPropertyValues("spring.config.location=classpath:application.yml,classpath:email-branding.yaml")
                .run(ctx -> {
                    EmailBrandingProperties props = ctx.getBean(EmailBrandingProperties.class);
                    assertThat(props.defaultFolder()).isEqualTo("eudistack");
                    assertThat(props.assetsBaseUrl()).isEqualTo("https://sandbox.stg.eudistack.net/assets/tenants");
                    assertThat(props.defaults().knowledgeBaseUrl()).isEqualTo("https://docs.eudistack.net/");
                    assertThat(props.tenants().get("dome").socialLinks()).hasSize(2);
                });
    }

    @Test
    void binding_assetsBaseUrlProperty_overridesDefault() {
        runner.withPropertyValues(
                        "spring.config.location=classpath:application.yml,classpath:email-branding.yaml",
                        "EMAIL_ASSETS_BASE_URL=https://sandbox.eudistack.net/assets/tenants")
                .run(ctx -> assertThat(ctx.getBean(EmailBrandingProperties.class).assetsBaseUrl())
                        .isEqualTo("https://sandbox.eudistack.net/assets/tenants"));
    }

    @Test
    void binding_withoutAssetsBaseUrl_failsStartup() {
        runner.withPropertyValues(
                        "spring.config.location=optional:classpath:/no-such-file.yaml",
                        "email-branding.default.support-url=https://s.example.com")
                .run(ctx -> assertThat(ctx).hasFailed());
    }

    @Test
    void binding_unknownSocialLinkType_failsStartup() {
        runner.withPropertyValues(
                        "spring.config.location=optional:classpath:/no-such-file.yaml",
                        "email-branding.assets-base-url=https://a.example.com",
                        "email-branding.default.support-url=https://s.example.com",
                        "email-branding.tenants.dome.social-links[0].type=twitter",
                        "email-branding.tenants.dome.social-links[0].url=https://x.example.com")
                .run(ctx -> assertThat(ctx).hasFailed());
    }

    @Test
    void socialLink_unknownType_isRejected() {
        assertThatThrownBy(() -> new SocialLink("facebook", "https://f.example.com"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("facebook");
    }
}
