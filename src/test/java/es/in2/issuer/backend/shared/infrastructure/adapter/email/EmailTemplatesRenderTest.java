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

        assertThat(html).doesNotContain("??");
        assertThat(html).contains("Blinker");
        if (v.branding() == DOME_BRANDING) {
            assertThat(html).contains("src=\"" + v.branding().logoUrl() + "\"");
        } else {
            assertThat(html).doesNotContain("logo.png");
        }
        assertThat(html).contains("max-width: 640px");
        assertThat(html).doesNotContain("#0F2B5B; padding: 20px");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("allVariants")
    void render_everyVariant_headerBackgroundAndSocialLinksFollowBranding(Variant v) {
        String html = render(v.template(), v.context());

        if (v.branding() == DOME_BRANDING) {
            assertThat(html).contains("background=\"" + v.branding().headerBackgroundUrl() + "\"");
            assertThat(html).contains("background-image: url(" + v.branding().headerBackgroundUrl() + ")");
        } else {
            assertThat(html).doesNotContain("background=\"");
            assertThat(html).doesNotContain("background-image");
        }
        if (v.branding() == DOME_BRANDING) {
            assertThat(html).contains("href=\"https://github.com/dome-example\"");
            assertThat(html).contains("src=\"cid:icon-github.png\"");
            assertThat(html).contains("href=\"https://www.linkedin.com/company/dome-example\"");
            assertThat(html).contains("src=\"cid:icon-linkedin.png\"");
        } else {
            assertThat(html).doesNotContain("cid:icon-github.png");
            assertThat(html).doesNotContain("cid:icon-linkedin.png");
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

        assertThat(html).contains("src=\"" + LOGO + "\"");
        assertThat(html).contains("margin: 54px 0 0 0;");
        assertThat(html).doesNotContain("background-image");
        assertThat(html).doesNotContain("height=\"190\"");
        assertThat(html).contains("padding: 30px 24px 0 24px;");
    }

    @Test
    void header_withoutLogo_omitsLogoAndGap() {
        String html = renderHeader(null, null);

        assertThat(html).doesNotContain("logo.png");
        assertThat(html).doesNotContain("height=\"54\"");
        assertThat(html).contains("margin: 0 0 0 0;");
    }

    @Test
    void header_backgroundWithoutLogo_keepsTheImageHeight() {
        String html = renderHeader(null, BACKGROUND);

        assertThat(html).doesNotContain("height=\"54\"");
        assertThat(html).contains("background=\"" + BACKGROUND + "\"");
        assertThat(html).contains("height=\"190\"");
        assertThat(html).contains("height: 190px; background-image: url(" + BACKGROUND + ")");
        assertThat(html).contains("padding: 0 24px 0 24px;");
    }

    // --- tx-code --------------------------------------------------------------------------------

    @Test
    void txCode_english_showsGreetingTitleCodeBoxAndHint() {
        String html = render("tx-code-email", txCodeContext(EN, DEFAULT_BRANDING, "4821"));

        assertThat(html).contains("Hello,");
        assertThat(html).contains("Your Activation Code");
        assertThat(html).contains(">4821<");
        assertThat(html).contains("max-width: 500px");
        assertThat(html).contains("border-radius: 16px");
        assertThat(html).contains("Please enter this activation code in your Wallet App.");
        assertThat(html).contains("If you did not request this code, please ignore this email.");
    }

    @Test
    void txCode_spanish_showsSpanishTitle() {
        String html = render("tx-code-email", txCodeContext(ES, DEFAULT_BRANDING, "4821"));

        assertThat(html).contains("Hola,");
        assertThat(html).contains("Tu código de activación");
    }

    // --- credential offer -----------------------------------------------------------------------

    @Test
    void offer_footerCarriesReissueAndKnowledgeBaseLinks() {
        String html = render("credential-offer-email", offerContext(EN, DOME_BRANDING, null));

        assertThat(html).contains("QR code expired?");
        assertThat(html).contains("href=\"https://issuer.example.com/credential-offer-refresh/token\"");
        assertThat(html).contains("Need help?");
        assertThat(html).contains("href=\"" + DOME_BRANDING.knowledgeBaseUrl() + "\"");
        assertThat(html).contains("ACME Corp has issued your credential");
        assertThat(html).contains("src=\"cid:qr-credential-offer.png\"");
    }

    @Test
    void offer_withTxCode_showsActivationCodeBlock() {
        String html = render("credential-offer-email", offerContext(EN, DEFAULT_BRANDING, "4821"));

        assertThat(html).contains("Your activation code:");
        assertThat(html).contains(">4821<");
    }

    @Test
    void offer_withoutTxCode_hidesActivationCodeBlock() {
        String html = render("credential-offer-email", offerContext(EN, DEFAULT_BRANDING, null));

        assertThat(html).doesNotContain("Your activation code:");
    }

    @Test
    void offer_spanish_isTranslated() {
        String html = render("credential-offer-email", offerContext(ES, DEFAULT_BRANDING, null));

        assertThat(html).contains("ACME Corp ha emitido tu credencial");
        assertThat(html).contains("¿QR expirado?");
        assertThat(html).contains("¿Necesitas ayuda?");
    }

    @Test
    void offer_organizationIsEscaped() {
        Context ctx = offerContext(EN, DEFAULT_BRANDING, null);
        ctx.setVariable("organization", "ACME <b>Corp</b>");

        String html = render("credential-offer-email", ctx);

        assertThat(html).contains("ACME &lt;b&gt;Corp&lt;/b&gt; has issued");
        assertThat(html).doesNotContain("<b>Corp</b>");
    }

    // --- revoked / expired ----------------------------------------------------------------------

    @Test
    void status_revoked_usesRevokedWordBadgeAndColours() {
        String html = render("revoked-expired-credential-email", statusContext(EN, DEFAULT_BRANDING, true));

        assertThat(html).contains("Your credential has been ");
        assertThat(html).contains("color: #E5483B;");
        assertThat(html).contains(">revoked<");
        assertThat(html).contains("Credential revoked");
        assertThat(html).contains("background-color: #F8A9A9");
        assertThat(html).contains("Details regarding the revoked credential are listed below:");
        assertThat(html).contains("Credential ID");
        assertThat(html).contains("cred-123");
        assertThat(html).contains("learcredential.employee.w3c.4");
        assertThat(html).doesNotContain("Credential expired");
    }

    @Test
    void status_expired_usesExpiredWordBadgeAndColours() {
        String html = render("revoked-expired-credential-email", statusContext(EN, DEFAULT_BRANDING, false));

        assertThat(html).contains("Your credential has ");
        assertThat(html).contains("color: #B89C14;");
        assertThat(html).contains(">expired<");
        assertThat(html).contains("Credential expired");
        assertThat(html).contains("background-color: #FCEFC0");
        assertThat(html).doesNotContain("Credential revoked");
    }

    @Test
    void status_spanishRevoked_isTranslated() {
        String html = render("revoked-expired-credential-email", statusContext(ES, DEFAULT_BRANDING, true));

        assertThat(html).contains("Tu credencial ha sido ");
        assertThat(html).contains(">revocada<");
        assertThat(html).contains("Credencial revocada");
    }

    @Test
    void status_footerSupportLinkComesFromBranding() {
        String html = render("revoked-expired-credential-email", statusContext(EN, DOME_BRANDING, true));

        assertThat(html).contains("href=\"https://ticketing.dome.example/\"");

        String defaultHtml = render("revoked-expired-credential-email", statusContext(EN, DEFAULT_BRANDING, true));
        assertThat(defaultHtml).contains("href=\"https://support.eudistack.example/help\"");
        assertThat(defaultHtml).doesNotContain("ticketing.dome-marketplace.eu");
    }

    // --- credential failure ---------------------------------------------------------------------

    @Test
    void failure_withEventDescription_showsDetailBoxWithWarningIcon() {
        String html = render("credential-failure-email", failureContext(EN, DEFAULT_BRANDING, "Timeout waiting"));

        assertThat(html).contains("Error Details");
        assertThat(html).contains("Timeout waiting");
        assertThat(html).contains("src=\"cid:icon-warning.png\"");
        assertThat(html).contains("background-color: #FFF8EF");
        assertThat(html).contains("border: 1px solid #F2E18C");
    }

    @Test
    void failure_withEmptyEventDescription_hidesWholeDetailBox() {
        String html = render("credential-failure-email", failureContext(EN, DEFAULT_BRANDING, ""));

        assertThat(html).doesNotContain("Error Details");
        assertThat(html).doesNotContain("cid:icon-warning.png");
        assertThat(html).doesNotContain("#FFF8EF");
        assertThat(html).contains("You can try again by requesting a new credential offer.");
    }

    @Test
    void failure_eventDescriptionIsEscaped() {
        String html = render("credential-failure-email",
                failureContext(EN, DEFAULT_BRANDING, "<script>alert('x')</script>"));

        assertThat(html).contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;");
        assertThat(html).doesNotContain("<script>alert");
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

        assertThat(html).contains("background-color: #0F2B5B");
        assertThat(html).doesNotContain("Blinker");
        assertThat(html).contains("href=\"https://docs.eudistack.net/\"");
    }
}
