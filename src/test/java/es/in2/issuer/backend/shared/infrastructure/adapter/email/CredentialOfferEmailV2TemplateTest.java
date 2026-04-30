package es.in2.issuer.backend.shared.infrastructure.adapter.email;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

class CredentialOfferEmailV2TemplateTest {

    private SpringTemplateEngine templateEngine;

    @BeforeEach
    void setUp() {
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

        templateEngine = new SpringTemplateEngine();
        templateEngine.setTemplateResolver(resolver);
        templateEngine.setMessageSource(messageSource);
    }

    private Context buildContext(Locale locale, String organization, String walletDeepLink, String reissueUrl) {
        Context ctx = new Context(locale);
        ctx.setVariable("organization", organization);
        ctx.setVariable("qrImageCid", "cid:qr-credential-offer.png");
        ctx.setVariable("walletDeepLink", walletDeepLink);
        ctx.setVariable("reissueUrl", reissueUrl);
        return ctx;
    }

    @Test
    void render_withEnglishLocale_containsExpectedEnglishText() {
        Context ctx = buildContext(Locale.ENGLISH, "KPMG Spain",
                "https://wallet.example.com/callback?credential_offer_uri=abc",
                "https://issuer.example.com/credential-offer/refresh/token");

        String html = templateEngine.process("credential-offer-email-v2", ctx);

        assertThat(html).contains("Spring Meeting 2026");
        assertThat(html).contains("Hello,");
        assertThat(html).contains("KPMG Spain has issued your credential");
        assertThat(html).contains("How to activate your credential");
        assertThat(html).contains("Download Wallet");
        assertThat(html).contains("Open the app on your device");
        assertThat(html).contains("Scan the QR code below");
        assertThat(html).contains("Activate the credential and add it to your Wallet");
        assertThat(html).contains("This QR code is valid for 10 minutes");
        assertThat(html).contains("On a mobile device? Open it directly in your Wallet");
        assertThat(html).contains("Not available on iPhone");
        assertThat(html).contains("Open in Wallet");
        assertThat(html).contains("QR code expired?");
        assertThat(html).contains("Request a new one");
    }

    @Test
    void render_withSpanishLocale_containsExpectedSpanishText() {
        Context ctx = buildContext(Locale.forLanguageTag("es"), "KPMG España",
                "https://wallet.example.com/callback?credential_offer_uri=abc",
                "https://issuer.example.com/credential-offer/refresh/token");

        String html = templateEngine.process("credential-offer-email-v2", ctx);

        assertThat(html).contains("Encuentro de Primavera 2026");
        assertThat(html).contains("Hola,");
        assertThat(html).contains("KPMG España ha emitido tu credencial");
        assertThat(html).contains("Cómo activar tu credencial");
        assertThat(html).contains("Descarga Wallet");
        assertThat(html).contains("Abre la aplicación en tu dispositivo");
        assertThat(html).contains("Escanea el código QR de abajo");
        assertThat(html).contains("Activa la credencial");
        assertThat(html).contains("No disponible en iPhone");
        assertThat(html).contains("¿QR expirado?");
        assertThat(html).contains("Solicitar uno nuevo");
    }

    @Test
    void render_withEmptyOrganization_rendersBodyWithoutNull() {
        Context ctx = buildContext(Locale.ENGLISH, "",
                "https://wallet.example.com/callback?credential_offer_uri=abc",
                "https://issuer.example.com/credential-offer/refresh/token");

        String html = templateEngine.process("credential-offer-email-v2", ctx);

        assertThat(html).contains("has issued your credential");
        assertThat(html).doesNotContain("null");
    }

    @Test
    void render_withSpecialCharactersInOrganization_escapesHtmlEntities() {
        Context ctx = buildContext(Locale.ENGLISH, "ACME <Corp> & Partners",
                "https://wallet.example.com/callback?credential_offer_uri=abc",
                "https://issuer.example.com/credential-offer/refresh/token");

        String html = templateEngine.process("credential-offer-email-v2", ctx);

        assertThat(html).contains("ACME &lt;Corp&gt; &amp; Partners has issued your credential");
        assertThat(html).doesNotContain("ACME <Corp> & Partners has issued");
    }

    @Test
    void render_walletDeepLinkAndReissueUrl_appearInHrefAttributes() {
        String walletDeepLink = "https://wallet.example.com/callback?credential_offer_uri=https%3A%2F%2Fexample.com";
        String reissueUrl = "https://issuer.example.com/credential-offer/refresh/mytoken";

        Context ctx = buildContext(Locale.ENGLISH, "TestOrg", walletDeepLink, reissueUrl);

        String html = templateEngine.process("credential-offer-email-v2", ctx);

        assertThat(html).contains("href=\"" + walletDeepLink + "\"");
        assertThat(html).contains("href=\"" + reissueUrl + "\"");
    }

    @Test
    void render_qrImageCid_appearsInImgSrcAttribute() {
        Context ctx = buildContext(Locale.ENGLISH, "TestOrg",
                "https://wallet.example.com/callback",
                "https://issuer.example.com/refresh/token");

        String html = templateEngine.process("credential-offer-email-v2", ctx);

        assertThat(html).contains("src=\"cid:qr-credential-offer.png\"");
    }
}
