package es.in2.issuer.backend.shared.infrastructure.adapter.email;

import es.in2.issuer.backend.shared.domain.model.dto.EmailBranding;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import static es.in2.issuer.backend.shared.infrastructure.adapter.email.EmailTemplateTestSupport.*;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Writes every rendered email variant to {@code build/email-previews/*.html} for manual review in a
 * browser. Disabled by default; run with {@code ./gradlew test --tests '*EmailPreviewGeneratorTest' -Demail.previews=true}.
 */
@EnabledIfSystemProperty(named = "email.previews", matches = "true")
class EmailPreviewGeneratorTest {

    private static final Path OUTPUT_DIR = Path.of("build", "email-previews");

    @Test
    void generatePreviews() throws IOException {
        SpringTemplateEngine engine = EmailTemplateTestSupport.engine();
        Files.createDirectories(OUTPUT_DIR);

        Map<String, EmailBranding> brandings = new LinkedHashMap<>();
        brandings.put("default", DEFAULT_BRANDING);
        brandings.put("dome", DOME_BRANDING);

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
        String html = engine.process(template, context);
        Files.writeString(OUTPUT_DIR.resolve(name + "-" + brand + "-" + lang + ".html"), html, StandardCharsets.UTF_8);
        return 1;
    }
}
