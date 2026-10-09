package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.model.dto.EmailBranding;
import es.in2.issuer.backend.shared.infrastructure.config.properties.EmailBrandingProperties;
import es.in2.issuer.backend.shared.infrastructure.config.properties.EmailBrandingProperties.SocialLink;
import es.in2.issuer.backend.shared.infrastructure.config.properties.EmailBrandingProperties.TenantEmailBranding;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import reactor.test.StepVerifier;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EmailBrandingResolverImplTest {

    private static final String BASE = "https://assets.example.com/assets/tenants";

    private static EmailBrandingResolverImpl resolver(String baseUrl) {
        TenantEmailBranding defaults = new TenantEmailBranding(
                "email/logo.png", null, "https://support.default", "https://kb.default", List.of());
        TenantEmailBranding dome = new TenantEmailBranding(
                "email/logo.png", "email/header-bg.png", "https://support.dome", null,
                List.of(new SocialLink("github", "https://github.com/dome"),
                        new SocialLink("linkedin", "https://linkedin.com/dome")));
        TenantEmailBranding onlyLogo = new TenantEmailBranding("email/own-logo.png", null, null, null, List.of());
        return new EmailBrandingResolverImpl(new EmailBrandingProperties(
                baseUrl, "eudistack", defaults, Map.of("dome", dome, "acme", onlyLogo)));
    }

    @Test
    void resolveFor_tenantWithBlock_usesTenantFolderAndOverrides() {
        EmailBranding branding = resolver(BASE).resolveFor("dome");

        assertThat(branding.logoUrl()).isEqualTo(BASE + "/dome/email/logo.png");
        assertThat(branding.headerBackgroundUrl()).isEqualTo(BASE + "/dome/email/header-bg.png");
        assertThat(branding.supportUrl()).isEqualTo("https://support.dome");
    }

    @Test
    void resolveFor_tenantWithoutBlock_fallsBackToDefaultEntirely() {
        EmailBranding branding = resolver(BASE).resolveFor("sandbox");

        assertThat(branding.logoUrl()).isEqualTo(BASE + "/eudistack/email/logo.png");
        assertThat(branding.headerBackgroundUrl()).isNull();
        assertThat(branding.supportUrl()).isEqualTo("https://support.default");
        assertThat(branding.knowledgeBaseUrl()).isEqualTo("https://kb.default");
        assertThat(branding.socialLinks()).isEmpty();
    }

    @Test
    void resolveFor_partialOverride_inheritsMissingFieldsFromDefault() {
        EmailBranding branding = resolver(BASE).resolveFor("acme");

        assertThat(branding.logoUrl()).isEqualTo(BASE + "/acme/email/own-logo.png");
        assertThat(branding.headerBackgroundUrl()).isNull();
        assertThat(branding.supportUrl()).isEqualTo("https://support.default");
        assertThat(branding.knowledgeBaseUrl()).isEqualTo("https://kb.default");
    }

    @Test
    void resolveFor_tenantWithoutLogo_inheritedLogoResolvesAgainstDefaultFolder() {
        TenantEmailBranding defaults = new TenantEmailBranding("email/logo.png", null, "s", "k", List.of());
        TenantEmailBranding noLogo = new TenantEmailBranding(null, "email/bg.png", null, null, List.of());
        EmailBrandingResolverImpl resolver = new EmailBrandingResolverImpl(new EmailBrandingProperties(
                BASE, "eudistack", defaults, Map.of("t", noLogo)));

        EmailBranding branding = resolver.resolveFor("t");

        assertThat(branding.logoUrl()).isEqualTo(BASE + "/eudistack/email/logo.png");
        assertThat(branding.headerBackgroundUrl()).isEqualTo(BASE + "/t/email/bg.png");
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
        TenantEmailBranding defaults = new TenantEmailBranding("/email/logo.png", null, "s", "k", List.of());
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
    void binding_baseFileAlone_bindsDefaultsAndDomeBlock() {
        runner.withPropertyValues("spring.config.location=classpath:email-branding.yaml")
                .run(ctx -> {
                    EmailBrandingProperties props = ctx.getBean(EmailBrandingProperties.class);
                    assertThat(props.defaultFolder()).isEqualTo("eudistack");
                    assertThat(props.defaults().logo()).isEqualTo("email/logo.png");
                    assertThat(props.tenants().get("dome").headerBackground()).isEqualTo("email/header-bg.png");
                    assertThat(props.tenants().get("dome").socialLinks()).hasSize(2);
                });
    }

    @Test
    void binding_overrideFile_mergesMapsKeyByKeyAndReplacesLists(@TempDir Path dir) throws IOException {
        Path override = dir.resolve("override.yaml");
        Files.writeString(override, """
                email-branding:
                  assets-base-url: https://override.example.com/assets/tenants
                  tenants:
                    dome:
                      social-links:
                        - { type: github, url: "https://github.com/real" }
                """);

        runner.withPropertyValues("spring.config.location=classpath:email-branding.yaml,file:" + override)
                .run(ctx -> {
                    EmailBrandingProperties props = ctx.getBean(EmailBrandingProperties.class);
                    assertThat(props.assetsBaseUrl()).isEqualTo("https://override.example.com/assets/tenants");
                    TenantEmailBranding dome = props.tenants().get("dome");
                    assertThat(dome.supportUrl()).isEqualTo("https://ticketing.dome-marketplace.eu/");
                    assertThat(dome.socialLinks()).containsExactly(new SocialLink("github", "https://github.com/real"));
                });
    }

    @Test
    void binding_withoutAssetsBaseUrl_failsStartup() {
        runner.withPropertyValues(
                        "spring.config.location=optional:classpath:/no-such-file.yaml",
                        "email-branding.default.logo=email/logo.png")
                .run(ctx -> assertThat(ctx).hasFailed());
    }

    @Test
    void binding_unknownSocialLinkType_failsStartup() {
        runner.withPropertyValues(
                        "spring.config.location=optional:classpath:/no-such-file.yaml",
                        "email-branding.assets-base-url=https://a.example.com",
                        "email-branding.default.logo=email/logo.png",
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
