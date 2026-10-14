package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.model.dto.EmailBranding;
import es.in2.issuer.backend.shared.infrastructure.config.properties.EmailBrandingProperties;
import es.in2.issuer.backend.shared.infrastructure.config.properties.EmailBrandingProperties.DefaultEmailBranding;
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
        DefaultEmailBranding defaults = new DefaultEmailBranding("https://support.default", "https://kb.default");
        TenantEmailBranding brand = new TenantEmailBranding(
                "https://support.dome", null, true, true,
                List.of(new SocialLink("github", "https://github.com/dome"),
                        new SocialLink("linkedin", "https://linkedin.com/dome")));
        TenantEmailBranding linksOnly = new TenantEmailBranding(null, "https://kb.acme", false, false, List.of());
        TenantEmailBranding logoOnly = new TenantEmailBranding(null, null, true, false, List.of());
        TenantEmailBranding backgroundOnly = new TenantEmailBranding(null, null, false, true, List.of());
        return new EmailBrandingResolverImpl(new EmailBrandingProperties(baseUrl, defaults, Map.of(
                "brand", brand, "acme", linksOnly, "logo-only", logoOnly, "bg-only", backgroundOnly)));
    }

    @Test
    void resolveFor_tenantWithBothImages_usesOwnFolder() {
        EmailBranding branding = resolver(BASE).resolveFor("brand");

        assertThat(branding.logoUrl()).isEqualTo(BASE + "/brand/email/logo.png");
        assertThat(branding.headerBackgroundUrl()).isEqualTo(BASE + "/brand/email/header-bg.png");
        assertThat(branding.supportUrl()).isEqualTo("https://support.dome");
    }

    @Test
    void resolveFor_tenantWithoutBlock_hasDefaultLinksAndNoImagesNorSocialLinks() {
        EmailBranding branding = resolver(BASE).resolveFor("sandbox");

        assertThat(branding.logoUrl()).isNull();
        assertThat(branding.headerBackgroundUrl()).isNull();
        assertThat(branding.supportUrl()).isEqualTo("https://support.default");
        assertThat(branding.knowledgeBaseUrl()).isEqualTo("https://kb.default");
        assertThat(branding.socialLinks()).isEmpty();
    }

    @Test
    void resolveFor_tenantWithoutImageFlags_hasNoImages() {
        EmailBranding acme = resolver(BASE).resolveFor("acme");

        assertThat(acme.logoUrl()).isNull();
        assertThat(acme.headerBackgroundUrl()).isNull();
    }

    @Test
    void resolveFor_logoAndBackgroundFlags_areIndependent() {
        EmailBranding logoOnly = resolver(BASE).resolveFor("logo-only");
        EmailBranding backgroundOnly = resolver(BASE).resolveFor("bg-only");

        assertThat(logoOnly.logoUrl()).isEqualTo(BASE + "/logo-only/email/logo.png");
        assertThat(logoOnly.headerBackgroundUrl()).isNull();
        assertThat(backgroundOnly.logoUrl()).isNull();
        assertThat(backgroundOnly.headerBackgroundUrl()).isEqualTo(BASE + "/bg-only/email/header-bg.png");
    }

    @Test
    void resolveFor_partialLinkOverride_inheritsMissingLinksFromDefault() {
        EmailBranding branding = resolver(BASE).resolveFor("brand");

        assertThat(branding.knowledgeBaseUrl()).isEqualTo("https://kb.default");

        EmailBranding acme = resolver(BASE).resolveFor("acme");

        assertThat(acme.supportUrl()).isEqualTo("https://support.default");
        assertThat(acme.knowledgeBaseUrl()).isEqualTo("https://kb.acme");
        assertThat(acme.socialLinks()).isEmpty();
    }

    @Test
    void resolveFor_tenantWithSocialLinks_hasThem() {
        EmailBranding branding = resolver(BASE).resolveFor("brand");

        assertThat(branding.socialLinks()).containsExactly(
                new EmailBranding.SocialLink("github", "https://github.com/dome"),
                new EmailBranding.SocialLink("linkedin", "https://linkedin.com/dome"));
    }

    @Test
    void resolveFor_trailingSlashesInBase_areNormalised() {
        EmailBrandingResolverImpl resolver = new EmailBrandingResolverImpl(new EmailBrandingProperties(
                BASE + "//", new DefaultEmailBranding("s", "k"),
                Map.of("x", new TenantEmailBranding(null, null, true, false, List.of()))));

        assertThat(resolver.resolveFor("x").logoUrl()).isEqualTo(BASE + "/x/email/logo.png");
    }

    @Test
    void resolve_readsTenantFromReactorContext() {
        StepVerifier.create(resolver(BASE).resolve()
                        .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "brand")))
                .assertNext(b -> assertThat(b.supportUrl()).isEqualTo("https://support.dome"))
                .verifyComplete();
    }

    @Test
    void resolve_withoutTenantInContext_usesDefaultLinksAndNoImages() {
        StepVerifier.create(resolver(BASE).resolve())
                .assertNext(b -> {
                    assertThat(b.logoUrl()).isNull();
                    assertThat(b.supportUrl()).isEqualTo("https://support.default");
                })
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
                    assertThat(props.assetsBaseUrl()).isEqualTo("https://sandbox.stg.eudistack.net/assets/tenants");
                    assertThat(props.defaults().knowledgeBaseUrl()).isEqualTo("https://docs.eudistack.net/");
                    assertThat(props.tenants().get("dome").socialLinks()).hasSize(2);
                    assertThat(props.tenants().get("dome").logo()).isTrue();
                    assertThat(props.tenants().get("dome").headerBackground()).isTrue();
                });
    }

    @Test
    void binding_withoutEmailBrandingPath_importsTheBundledFile() {
        runner.withPropertyValues("spring.config.location=classpath:application.yml")
                .run(ctx -> {
                    EmailBrandingProperties props = ctx.getBean(EmailBrandingProperties.class);
                    assertThat(props.defaults().supportUrl()).isEqualTo("https://docs.eudistack.net");
                    assertThat(props.tenants().get("dome").knowledgeBaseUrl())
                            .isEqualTo("https://knowledgebase.dome-marketplace.eu/");
                });
    }

    @Test
    void binding_emailBrandingPath_replacesTheBundledFile(@TempDir Path dir) throws IOException {
        Path file = Files.writeString(dir.resolve("email-branding.yaml"), """
                email-branding:
                  default:
                    support-url: https://support.env
                    knowledge-base-url: https://kb.env
                  tenants:
                    acme:
                      logo: true
                """);

        runner.withPropertyValues(
                        "spring.config.location=classpath:application.yml",
                        "EMAIL_BRANDING_PATH=file:" + file.toAbsolutePath())
                .run(ctx -> {
                    EmailBrandingProperties props = ctx.getBean(EmailBrandingProperties.class);
                    assertThat(props.defaults().supportUrl()).isEqualTo("https://support.env");
                    assertThat(props.defaults().knowledgeBaseUrl()).isEqualTo("https://kb.env");
                    assertThat(props.tenants()).containsOnlyKeys("acme");
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
                        "email-branding.default.support-url=https://s.example.com",
                        "email-branding.default.knowledge-base-url=https://k.example.com")
                .run(ctx -> assertThat(ctx).hasFailed());
    }

    @Test
    void binding_withoutDefaultSupportUrl_failsStartup() {
        runner.withPropertyValues(
                        "spring.config.location=optional:classpath:/no-such-file.yaml",
                        "email-branding.assets-base-url=https://a.example.com",
                        "email-branding.default.knowledge-base-url=https://k.example.com")
                .run(ctx -> assertThat(ctx).hasFailed());
    }

    @Test
    void binding_withoutDefaultKnowledgeBaseUrl_failsStartup() {
        runner.withPropertyValues(
                        "spring.config.location=optional:classpath:/no-such-file.yaml",
                        "email-branding.assets-base-url=https://a.example.com",
                        "email-branding.default.support-url=https://s.example.com")
                .run(ctx -> assertThat(ctx).hasFailed());
    }

    @Test
    void binding_unknownSocialLinkType_failsStartup() {
        runner.withPropertyValues(
                        "spring.config.location=optional:classpath:/no-such-file.yaml",
                        "email-branding.assets-base-url=https://a.example.com",
                        "email-branding.default.support-url=https://s.example.com",
                        "email-branding.default.knowledge-base-url=https://k.example.com",
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
