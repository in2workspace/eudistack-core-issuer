package es.in2.issuer.backend.shared.infrastructure.adapter.email;

import es.in2.issuer.backend.shared.domain.model.dto.EmailBranding;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

import static es.in2.issuer.backend.shared.infrastructure.adapter.email.EmailTemplateTestSupport.*;
import static org.assertj.core.api.Assertions.assertThat;

class EmailTemplatesRenderTest {

    private static final Locale EN = Locale.ENGLISH;
    private static final Locale ES = Locale.forLanguageTag("es");

    private final SpringTemplateEngine engine = EmailTemplateTestSupport.engine();

    private record Variant(String template, Locale locale, EmailBranding branding, Context context) {
        @Override
        public String toString() {
            return template + " / " + locale.getLanguage() + " / "
                    + (branding == DOME_BRANDING ? "dome" : "default");
        }
    }

    static Stream<Arguments> allVariants() {
        Stream.Builder<Arguments> variants = Stream.builder();
        for (Locale locale : List.of(EN, ES)) {
            for (EmailBranding branding : List.of(DEFAULT_BRANDING, DOME_BRANDING)) {
                variants.add(Arguments.of(new Variant("tx-code-email", locale, branding,
                        txCodeContext(locale, branding, "4821"))));
                variants.add(Arguments.of(new Variant("credential-offer-email", locale, branding,
                        offerContext(locale, branding, "4821"))));
                variants.add(Arguments.of(new Variant("revoked-expired-credential-email", locale, branding,
                        statusContext(locale, branding, true))));
                variants.add(Arguments.of(new Variant("revoked-expired-credential-email", locale, branding,
                        statusContext(locale, branding, false))));
                variants.add(Arguments.of(new Variant("credential-failure-email", locale, branding,
                        failureContext(locale, branding, "Timeout waiting for user decision"))));
            }
        }
        return variants.build();
    }

    private String render(String template, Context context) {
        return engine.process(template, context);
    }

    // --- Common to every template and variant --------------------------------------------------

    @ParameterizedTest(name = "{0}")
    @MethodSource("allVariants")
    void render_everyVariant_hasNoUnresolvedMessagesAndUsesBlinkerAndLogoOnlyWhenConfigured(Variant v) {
        String html = render(v.template(), v.context());

        assertThat(html)
                .doesNotContain("??")
                .contains("Blinker");
        if (v.branding() == DOME_BRANDING) {
            assertThat(html).contains("src=\"" + v.branding().logoUrl() + "\"");
        } else {
            assertThat(html).doesNotContain("logo.png");
        }
        assertThat(html)
                .contains("max-width: 640px")
                .doesNotContain("#0F2B5B; padding: 20px");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("allVariants")
    void render_everyVariant_headerBackgroundAndSocialLinksFollowBranding(Variant v) {
        String html = render(v.template(), v.context());

        if (v.branding() == DOME_BRANDING) {
            assertThat(html)
                    .contains("background=\"" + v.branding().headerBackgroundUrl() + "\"")
                    .contains("background-image: url(" + v.branding().headerBackgroundUrl() + ")");
        } else {
            assertThat(html)
                    .doesNotContain("background=\"")
                    .doesNotContain("background-image");
        }
        if (v.branding() == DOME_BRANDING) {
            assertThat(html)
                    .contains("href=\"https://github.com/dome-example\"")
                    .contains("src=\"cid:icon-github.png\"")
                    .contains("href=\"https://www.linkedin.com/company/dome-example\"")
                    .contains("src=\"cid:icon-linkedin.png\"");
        } else {
            assertThat(html)
                    .doesNotContain("cid:icon-github.png")
                    .doesNotContain("cid:icon-linkedin.png");
        }
    }

    // --- Header: logo and background are independent -------------------------------------------

    private static final String LOGO = ASSETS + "/acme/email/logo.png";
    private static final String BACKGROUND = ASSETS + "/acme/email/header-bg.png";

    private String renderHeader(String logoUrl, String backgroundUrl) {
        EmailBranding branding = new EmailBranding(logoUrl, backgroundUrl, "https://s", "https://k", List.of());
        return render("tx-code-email", txCodeContext(EN, branding, "4821"));
    }

    @Test
    void header_withLogo_showsLogoAndKeepsGapToGreeting() {
        String html = renderHeader(LOGO, null);

        assertThat(html)
                .contains("src=\"" + LOGO + "\"")
                .contains("margin: 54px 0 0 0;")
                .doesNotContain("background-image")
                .doesNotContain("height=\"190\"")
                .contains("padding: 30px 24px 0 24px;");
    }

    @Test
    void header_withoutLogo_omitsLogoAndGap() {
        String html = renderHeader(null, null);

        assertThat(html)
                .doesNotContain("logo.png")
                .doesNotContain("height=\"54\"")
                .contains("margin: 0 0 0 0;");
    }

    @Test
    void header_backgroundWithoutLogo_keepsTheImageHeight() {
        String html = renderHeader(null, BACKGROUND);

        assertThat(html)
                .doesNotContain("height=\"54\"")
                .contains("background=\"" + BACKGROUND + "\"")
                .contains("height=\"190\"")
                .contains("height: 190px; background-image: url(" + BACKGROUND + ")")
                .contains("padding: 0 24px 0 24px;");
    }

    // --- tx-code --------------------------------------------------------------------------------

    @Test
    void txCode_english_showsGreetingTitleCodeBoxAndHint() {
        String html = render("tx-code-email", txCodeContext(EN, DEFAULT_BRANDING, "4821"));

        assertThat(html)
                .contains("Hello,")
                .contains("Your Activation Code")
                .contains(">4821<")
                .contains("max-width: 500px")
                .contains("border-radius: 16px")
                .contains("Please enter this activation code in your Wallet App.")
                .contains("If you did not request this code, please ignore this email.");
    }

    @Test
    void txCode_spanish_showsSpanishTitle() {
        String html = render("tx-code-email", txCodeContext(ES, DEFAULT_BRANDING, "4821"));

        assertThat(html)
                .contains("Hola,")
                .contains("Tu código de activación");
    }

    // --- credential offer -----------------------------------------------------------------------

    @Test
    void offer_footerCarriesReissueAndKnowledgeBaseLinks() {
        String html = render("credential-offer-email", offerContext(EN, DOME_BRANDING, null));

        assertThat(html)
                .contains("QR code expired?")
                .contains("href=\"https://issuer.example.com/credential-offer-refresh/token\"")
                .contains("Need help?")
                .contains("href=\"" + DOME_BRANDING.knowledgeBaseUrl() + "\"")
                .contains("ACME Corp has issued your credential")
                .contains("src=\"cid:qr-credential-offer.png\"");
    }

    @Test
    void offer_withTxCode_showsActivationCodeBlock() {
        String html = render("credential-offer-email", offerContext(EN, DEFAULT_BRANDING, "4821"));

        assertThat(html)
                .contains("Your activation code:")
                .contains(">4821<");
    }

    @Test
    void offer_withoutTxCode_hidesActivationCodeBlock() {
        String html = render("credential-offer-email", offerContext(EN, DEFAULT_BRANDING, null));

        assertThat(html).doesNotContain("Your activation code:");
    }

    @Test
    void offer_spanish_isTranslated() {
        String html = render("credential-offer-email", offerContext(ES, DEFAULT_BRANDING, null));

        assertThat(html)
                .contains("ACME Corp ha emitido tu credencial")
                .contains("¿QR expirado?")
                .contains("¿Necesitas ayuda?");
    }

    @Test
    void offer_organizationIsEscaped() {
        Context ctx = offerContext(EN, DEFAULT_BRANDING, null);
        ctx.setVariable("organization", "ACME <b>Corp</b>");

        String html = render("credential-offer-email", ctx);

        assertThat(html)
                .contains("ACME &lt;b&gt;Corp&lt;/b&gt; has issued")
                .doesNotContain("<b>Corp</b>");
    }

    // --- revoked / expired ----------------------------------------------------------------------

    @Test
    void status_revoked_usesRevokedWordBadgeAndColours() {
        String html = render("revoked-expired-credential-email", statusContext(EN, DEFAULT_BRANDING, true));

        assertThat(html)
                .contains("Your credential has been ")
                .contains("color: #E5483B;")
                .contains(">revoked<")
                .contains("Credential revoked")
                .contains("background-color: #F8A9A9")
                .contains("Details regarding the revoked credential are listed below:")
                .contains("Credential ID")
                .contains("cred-123")
                .contains("learcredential.employee.w3c.4")
                .doesNotContain("Credential expired");
    }

    @Test
    void status_expired_usesExpiredWordBadgeAndColours() {
        String html = render("revoked-expired-credential-email", statusContext(EN, DEFAULT_BRANDING, false));

        assertThat(html)
                .contains("Your credential has ")
                .contains("color: #B89C14;")
                .contains(">expired<")
                .contains("Credential expired")
                .contains("background-color: #FCEFC0")
                .doesNotContain("Credential revoked");
    }

    @Test
    void status_spanishRevoked_isTranslated() {
        String html = render("revoked-expired-credential-email", statusContext(ES, DEFAULT_BRANDING, true));

        assertThat(html)
                .contains("Tu credencial ha sido ")
                .contains(">revocada<")
                .contains("Credencial revocada");
    }

    @Test
    void status_footerSupportLinkComesFromBranding() {
        String html = render("revoked-expired-credential-email", statusContext(EN, DOME_BRANDING, true));

        assertThat(html).contains("href=\"https://ticketing.dome.example/\"");

        String defaultHtml = render("revoked-expired-credential-email", statusContext(EN, DEFAULT_BRANDING, true));
        assertThat(defaultHtml)
                .contains("href=\"https://support.eudistack.example/help\"")
                .doesNotContain("ticketing.dome-marketplace.eu");
    }

    // --- credential failure ---------------------------------------------------------------------

    @Test
    void failure_withEventDescription_showsDetailBoxWithWarningIcon() {
        String html = render("credential-failure-email", failureContext(EN, DEFAULT_BRANDING, "Timeout waiting"));

        assertThat(html)
                .contains("Error Details")
                .contains("Timeout waiting")
                .contains("src=\"cid:icon-warning.png\"")
                .contains("background-color: #FFF8EF")
                .contains("border: 1px solid #F2E18C");
    }

    @Test
    void failure_eventDescriptionWrapsLongTokens_withOutlookFallback() {
        String html = render("credential-failure-email", failureContext(EN, DEFAULT_BRANDING, "Timeout waiting"));

        assertThat(html)
                .contains("style=\"table-layout: fixed;\"")
                .contains("class=\"break-long\"")
                .contains("word-break: normal; overflow-wrap: break-word;")
                .contains(".break-long { word-break: break-word !important; }");
    }

    @Test
    void failure_withEmptyEventDescription_hidesWholeDetailBox() {
        String html = render("credential-failure-email", failureContext(EN, DEFAULT_BRANDING, ""));

        assertThat(html)
                .doesNotContain("Error Details")
                .doesNotContain("cid:icon-warning.png")
                .doesNotContain("#FFF8EF")
                .contains("You can try again by requesting a new credential offer.");
    }

    @Test
    void failure_eventDescriptionIsEscaped() {
        String html = render("credential-failure-email",
                failureContext(EN, DEFAULT_BRANDING, "<script>alert('x')</script>"));

        assertThat(html)
                .contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;")
                .doesNotContain("<script>alert");
    }

    @Test
    void failure_footerSupportLinkComesFromBranding() {
        String html = render("credential-failure-email", failureContext(EN, DOME_BRANDING, "boom"));

        assertThat(html).contains("href=\"https://ticketing.dome.example/\"");
    }

    // --- KPMG template is untouched by the shared layout ----------------------------------------

    @Test
    void kpmgTemplate_doesNotUseTheSharedLayout() {
        Context ctx = new Context(EN);
        ctx.setVariable("organization", "KPMG Spain");
        ctx.setVariable("qrImageCid", "cid:qr-credential-offer.png");
        ctx.setVariable("walletDeepLink", "https://wallet.example.com/callback");
        ctx.setVariable("reissueUrl", "https://issuer.example.com/refresh/token");

        String html = render("credential-offer-email-v2", ctx);

        assertThat(html)
                .contains("background-color: #0F2B5B")
                .doesNotContain("Blinker")
                .contains("href=\"https://docs.eudistack.net/\"");
    }
}
