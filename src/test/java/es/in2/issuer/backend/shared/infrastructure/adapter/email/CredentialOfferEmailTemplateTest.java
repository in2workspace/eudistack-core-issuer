package es.in2.issuer.backend.shared.infrastructure.adapter.email;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Renders the real credential offer email template (EUD-305): the button must carry the link
 * exactly as the caller decided it -- a link to the tenant's wallet, or the standard
 * {@code openid-credential-offer://} form when the tenant configures no wallet.
 */
class CredentialOfferEmailTemplateTest {

    private TemplateEngine templateEngine;

    @BeforeEach
    void setUp() {
        ClassLoaderTemplateResolver resolver = new ClassLoaderTemplateResolver();
        resolver.setPrefix("templates/");
        resolver.setSuffix(".html");
        resolver.setTemplateMode(TemplateMode.HTML);
        resolver.setCharacterEncoding("UTF-8");
        templateEngine = new SpringTemplateEngine();
        templateEngine.setTemplateResolver(resolver);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://wallet.example.com/wallet/protocol/callback?credential_offer_uri=https%3A%2F%2Fissuer.example.com%2Fissuer%2Foid4vci%2Fv1%2Fcredential-offer%2Fnonce",
            "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example.com%2Fissuer%2Foid4vci%2Fv1%2Fcredential-offer%2Fnonce"
    })
    void credentialOfferEmail_buttonCarriesTheLinkUnchanged(String credentialOfferLink) {
        Context context = new Context(Locale.ENGLISH);
        context.setVariable("organization", "ACME");
        context.setVariable("qrImageCid", "cid:qr-credential-offer.png");
        context.setVariable("credentialOfferLink", credentialOfferLink);
        context.setVariable("reissueUrl", "https://issuer.example.com/credential-offer-refresh/abc");

        String html = templateEngine.process("credential-offer-email", context);

        assertThat(html).contains("href=\"" + credentialOfferLink + "\"");
    }
}
