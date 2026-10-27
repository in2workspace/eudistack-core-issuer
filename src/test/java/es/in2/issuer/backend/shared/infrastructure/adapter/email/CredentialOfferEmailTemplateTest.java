package es.in2.issuer.backend.shared.infrastructure.adapter.email;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.thymeleaf.context.Context;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Renders the real credential offer email template (EUD-305): the button must carry
 * {@code walletLink} exactly as the email service built it -- a link to the tenant's wallet, or the
 * standard {@code openid-credential-offer://} form when the tenant configures no wallet.
 */
class CredentialOfferEmailTemplateTest {

    @ParameterizedTest
    @ValueSource(strings = {
            "https://wallet.example.com/wallet/protocol/callback?credential_offer_uri=https%3A%2F%2Fissuer.example.com%2Fissuer%2Foid4vci%2Fv1%2Fcredential-offer%2Fnonce",
            "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example.com%2Fissuer%2Foid4vci%2Fv1%2Fcredential-offer%2Fnonce"
    })
    void credentialOfferEmail_buttonCarriesTheWalletLinkUnchanged(String walletLink) {
        Context context = EmailTemplateTestSupport.offerContext(
                Locale.ENGLISH, EmailTemplateTestSupport.DEFAULT_BRANDING, null);
        context.setVariable("walletLink", walletLink);

        String html = EmailTemplateTestSupport.engine().process("credential-offer-email", context);

        assertThat(html).contains("href=\"" + walletLink + "\"");
    }
}
