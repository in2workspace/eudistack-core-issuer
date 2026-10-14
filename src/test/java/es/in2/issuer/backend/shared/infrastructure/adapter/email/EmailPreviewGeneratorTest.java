package es.in2.issuer.backend.shared.infrastructure.adapter.email;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.qrcode.QRCodeWriter;
import es.in2.issuer.backend.shared.domain.model.dto.EmailBranding;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.core.io.ClassPathResource;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

import static es.in2.issuer.backend.shared.infrastructure.adapter.email.EmailTemplateTestSupport.*;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Writes every rendered email variant to {@code build/email-previews/*.html} for manual review in a
 * browser. Disabled by default; run with {@code ./gradlew test --tests '*EmailPreviewGeneratorTest' -Demail.previews=true}.
 * <p>
 * The DOME variants load the real logo and header background from {@code -Demail.previews.assets}
 * (default: the DEV environment's tenant assets). Inline images ({@code cid:} icons and the offer QR),
 * which a browser cannot resolve, are embedded as {@code data:} URIs.
 */
@EnabledIfSystemProperty(named = "email.previews", matches = "true")
class EmailPreviewGeneratorTest {

    private static final Path OUTPUT_DIR = Path.of("build", "email-previews");
    private static final String DEFAULT_ASSETS = "https://sandbox.dev.eudistack.net/assets/tenants";
    private static final Pattern CID = Pattern.compile("cid:([\\w.-]+\\.png)");

    @Test
    void generatePreviews() throws IOException {
        SpringTemplateEngine engine = EmailTemplateTestSupport.engine();
        Files.createDirectories(OUTPUT_DIR);

        String assets = System.getProperty("email.previews.assets", DEFAULT_ASSETS).replaceAll("/+$", "");
        Map<String, EmailBranding> brandings = new LinkedHashMap<>();
        brandings.put("default", DEFAULT_BRANDING);
        brandings.put("dome", new EmailBranding(
                assets + "/dome/email/logo.png",
                assets + "/dome/email/header-bg.png",
                DOME_BRANDING.supportUrl(),
                DOME_BRANDING.knowledgeBaseUrl(),
                DOME_BRANDING.socialLinks()));

        int written = 0;
        for (String lang : new String[]{"en", "es"}) {
            Locale locale = Locale.forLanguageTag(lang);
            for (Map.Entry<String, EmailBranding> brand : brandings.entrySet()) {
                EmailBranding b = brand.getValue();
                written += write(engine, brand.getKey(), lang, "tx-code", "tx-code-email", txCodeContext(locale, b, "4821"));
                written += write(engine, brand.getKey(), lang, "offer", "credential-offer-email", offerContext(locale, b, null));
                written += write(engine, brand.getKey(), lang, "offer-with-code", "credential-offer-email", offerContext(locale, b, "4821"));
                written += write(engine, brand.getKey(), lang, "revoked", "revoked-expired-credential-email", statusContext(locale, b, true));
                written += write(engine, brand.getKey(), lang, "expired", "revoked-expired-credential-email", statusContext(locale, b, false));
                written += write(engine, brand.getKey(), lang, "failure", "credential-failure-email",
                        failureContext(locale, b, "Timeout waiting for user decision"));
                written += write(engine, brand.getKey(), lang, "failure-no-details", "credential-failure-email", failureContext(locale, b, ""));
            }
        }
        assertThat(written).isEqualTo(28);
    }

    private int write(SpringTemplateEngine engine, String brand, String lang, String name, String template,
                      Context context) throws IOException {
        String html = CID.matcher(engine.process(template, context))
                .replaceAll(match -> "data:image/png;base64," + Base64.getEncoder().encodeToString(inlineImage(match.group(1))));
        Files.writeString(OUTPUT_DIR.resolve(name + "-" + brand + "-" + lang + ".html"), html, StandardCharsets.UTF_8);
        return 1;
    }

    /** Bytes of the image EmailServiceImpl attaches under this content id. */
    private static byte[] inlineImage(String contentId) {
        if (contentId.equals("qr-credential-offer.png")) {
            return qrCode("https://wallet.example.com/callback?credential_offer_uri=abc");
        }
        String path = "email/icons/" + contentId.replaceFirst("^icon-", "");
        try (InputStream in = new ClassPathResource(path).getInputStream()) {
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException("Missing email image: " + path, e);
        }
    }

    private static byte[] qrCode(String content) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(
                    new QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, 300, 300), "PNG", out);
            return out.toByteArray();
        } catch (WriterException | IOException e) {
            throw new IllegalStateException("Failed to generate QR code", e);
        }
    }
}
