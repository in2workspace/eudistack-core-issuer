package es.in2.issuer.backend.shared.infrastructure.adapter.email;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.model.dto.EmailBranding;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.domain.service.TranslationService;
import es.in2.issuer.backend.shared.domain.spi.EmailBrandingResolver;
import jakarta.mail.internet.MimeMessage;
import io.micrometer.observation.annotation.Observed;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.springframework.util.MimeTypeUtils;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Slf4j
@Service
public class EmailServiceImpl implements EmailService {

    private static final String MAIL_FROM_KEY = "issuer.mail_from";
    private static final String DEFAULT_LANG_KEY = "issuer.default_lang";

    private static final String CREDENTIAL_OFFER_SUBJECT_KEY = "email.credential-offer.subject";
    private static final String TX_CODE_SUBJECT_KEY = "email.tx-code.subject";
    private static final String CREDENTIAL_FAILURE_SUBJECT_KEY = "email.credential-failure.subject";
    private static final String DEFAULT_STATUS_SUBJECT_KEY = "email.default-status.subject";

    private static final String ICONS_PATH = "email/icons/";
    private static final Map<String, byte[]> ICONS = new ConcurrentHashMap<>();

    /** Presentation of a revoked / expired notification. Colours are approximations pending UI confirmation. */
    private record StatusStyle(String keyPrefix, String wordColor, String badgeBackground, String badgeText) {
        static final StatusStyle REVOKED = new StatusStyle("email.revoked", "#E5483B", "#F8A9A9", "#7A1F1F");
        static final StatusStyle EXPIRED = new StatusStyle("email.expired", "#B89C14", "#FCEFC0", "#8A750F");
    }

    /** Per-send values resolved once; branding is empty for the unbranded KPMG path. */
    private record SendSetup(String mailFrom, String locale, Optional<EmailBranding> branding,
                             String tenantDisplayName, Optional<String> environmentLabel) {
    }

    /** Fills the template context; inline PNGs are registered by content id and attached after the body. */
    @FunctionalInterface
    private interface ContentBuilder {
        void apply(Context context, Map<String, byte[]> inlinePngs, SendSetup setup);
    }

    private final JavaMailSender javaMailSender;
    private final TemplateEngine templateEngine;
    private final TenantConfigService tenantConfigService;
    private final TranslationService translationService;
    private final EmailBrandingResolver emailBrandingResolver;
    private final TenantRegistryService tenantRegistryService;

    public EmailServiceImpl(
            JavaMailSender javaMailSender,
            TemplateEngine templateEngine,
            TenantConfigService tenantConfigService,
            TranslationService translationService,
            EmailBrandingResolver emailBrandingResolver,
            TenantRegistryService tenantRegistryService
    ) {
        this.javaMailSender = javaMailSender;
        this.templateEngine = templateEngine;
        this.tenantConfigService = tenantConfigService;
        this.translationService = translationService;
        this.emailBrandingResolver = emailBrandingResolver;
        this.tenantRegistryService = tenantRegistryService;
    }

    @Override
    public Mono<Void> sendTxCodeNotification(String to, String txCode) {
        return send("tx-code-email", to, true,
                setup -> translationService.translateWithLocale(TX_CODE_SUBJECT_KEY, setup.locale(), setup.tenantDisplayName()),
                (context, inlinePngs, setup) -> context.setVariable("txCode", txCode))
                .onErrorMap(ex -> {
                    log.error("Failed to send tx code notification", ex);
                    return new EmailCommunicationException("Error when sending tx code notification");
                });
    }

    @Observed(name = "issuance.send-email", contextualName = "issuance-send-email")
    @Override
    public Mono<Void> sendCredentialOfferEmail(String to, String walletDeepLink, String reissueUrl,
                                               String organization, String txCode) {
        return tenantConfigService.getStringOrThrow("issuer.wallet_url")
                .flatMap(walletUrl -> send("credential-offer-email", to, true,
                        this::offerSubject,
                        (context, inlinePngs, setup) -> {
                            fillOfferContext(context, inlinePngs, walletDeepLink, reissueUrl, organization, walletUrl);
                            if (txCode != null) {
                                context.setVariable("txCode", txCode);
                            }
                        }));
    }

    @Observed(name = "issuance.send-email", contextualName = "issuance-send-email")
    @Override
    public Mono<Void> sendBrandedCredentialOfferEmail(String to, String subject, String walletDeepLink,
                                                      String reissueUrl, String organization) {
        // KPMG path: own template and subject, no branding variables.
        return tenantConfigService.getStringOrThrow("issuer.wallet_url")
                .flatMap(walletUrl -> send("credential-offer-email-v2", to, false,
                        setup -> translationService.translateWithLocale(subject, setup.locale()),
                        (context, inlinePngs, setup) ->
                                fillOfferContext(context, inlinePngs, walletDeepLink, reissueUrl, organization, walletUrl)));
    }

    @Override
    public Mono<Void> sendCredentialStatusChangeNotification(String to, String credentialId, String type, String status) {
        StatusStyle style = switch (status) {
            case "REVOKED" -> StatusStyle.REVOKED;
            case "EXPIRED" -> StatusStyle.EXPIRED;
            default -> null;
        };
        return send("revoked-expired-credential-email", to, true,
                setup -> style == null
                        ? translationService.translateWithLocale(DEFAULT_STATUS_SUBJECT_KEY, setup.locale())
                        : translationService.translateWithLocale(style.keyPrefix() + ".title", setup.locale()),
                (context, inlinePngs, setup) -> {
                    context.setVariable("credentialId", credentialId);
                    context.setVariable("type", type);
                    context.setVariable("credentialStatus", status);
                    if (style != null) {
                        context.setVariable("title",
                                translationService.translateWithLocale(style.keyPrefix() + ".title", setup.locale()));
                        context.setVariable("statusKeyPrefix", style.keyPrefix());
                        context.setVariable("statusWordColor", style.wordColor());
                        context.setVariable("badgeBackground", style.badgeBackground());
                        context.setVariable("badgeTextColor", style.badgeText());
                    }
                })
                .onErrorMap(e -> new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE));
    }

    @Override
    public Mono<Void> sendCredentialFailureNotification(String to, String eventDescription) {
        return send("credential-failure-email", to, true,
                setup -> translationService.translateWithLocale(CREDENTIAL_FAILURE_SUBJECT_KEY, setup.locale()),
                (context, inlinePngs, setup) -> {
                    boolean hasDetails = eventDescription != null && !eventDescription.isEmpty();
                    context.setVariable("eventDescription", hasDetails ? eventDescription : "");
                    if (hasDetails) {
                        addIcon(inlinePngs, "warning");
                    }
                })
                .onErrorMap(e -> new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE));
    }

    /**
     * Common pipeline: resolves mail_from, locale and (when {@code branded}) branding and tenant display
     * name, builds the MIME message on {@code boundedElastic} and sends it. Error mapping is left to callers.
     */
    private Mono<Void> send(String template, String to, boolean branded,
                            Function<SendSetup, String> subject, ContentBuilder content) {
        return resolveSetup(branded)
                .flatMap(setup -> Mono.fromCallable(() -> {
                    MimeMessage mimeMessage = javaMailSender.createMimeMessage();
                    MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);
                    helper.setFrom(setup.mailFrom());
                    helper.setTo(to);
                    helper.setSubject(subject.apply(setup));

                    Context context = createLocalizedContext(setup.locale());
                    setup.branding().ifPresent(branding -> {
                        context.setVariable("branding", branding);
                        context.setVariable("tenantDisplayName", setup.tenantDisplayName());
                    });
                    Map<String, byte[]> inlinePngs = new LinkedHashMap<>();
                    setup.branding().ifPresent(branding -> {
                        branding.socialLinks().forEach(link -> addIcon(inlinePngs, link.type()));
                    });
                    content.apply(context, inlinePngs, setup);

                    // Inline parts must follow setText: otherwise the image becomes the first part of
                    // multipart/related and clients (Outlook, Gmail) show it as the body and the HTML as an attachment.
                    helper.setText(templateEngine.process(template, context), true);
                    for (Map.Entry<String, byte[]> inline : inlinePngs.entrySet()) {
                        helper.addInline(inline.getKey(), new ByteArrayResource(inline.getValue()), MimeTypeUtils.IMAGE_PNG_VALUE);
                    }
                    javaMailSender.send(mimeMessage);
                    return null;
                }).subscribeOn(Schedulers.boundedElastic()))
                .then();
    }

    private Mono<SendSetup> resolveSetup(boolean branded) {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "");
            Optional<String> label = Optional.ofNullable(ctx.<String>getOrDefault(ENVIRONMENT_LABEL_CONTEXT_KEY, null))
                    .filter(value -> !value.isBlank());
            Mono<Optional<EmailBranding>> branding = branded
                    ? emailBrandingResolver.resolve().map(Optional::of)
                    : Mono.just(Optional.empty());
            Mono<String> displayName = branded && !tenant.isBlank()
                    ? tenantRegistryService.getDisplayName(tenant)
                    : Mono.just(tenant);
            return Mono.zip(
                    tenantConfigService.getStringOrThrow(MAIL_FROM_KEY),
                    tenantConfigService.getStringOrDefault(DEFAULT_LANG_KEY, ""),
                    branding,
                    displayName
            ).map(tuple -> new SendSetup(
                    tuple.getT1(),
                    translationService.getLocaleOrDefault(tuple.getT2()),
                    tuple.getT3(),
                    tuple.getT4(),
                    label));
        });
    }

    /** Offer subject: the environment label (non-canonical hosts only) followed by the tenant-named sentence. */
    private String offerSubject(SendSetup setup) {
        String prefix = setup.environmentLabel().map(label -> "[" + label + "] ").orElse("");
        return prefix + translationService.translateWithLocale(
                CREDENTIAL_OFFER_SUBJECT_KEY, setup.locale(), setup.tenantDisplayName());
    }

    private void fillOfferContext(Context context, Map<String, byte[]> inlinePngs, String walletDeepLink,
                                  String reissueUrl, String organization, String walletUrl) {
        byte[] qrImageBytes = generateQrCodeImage(walletDeepLink, 300, 300);

        context.setVariable("organization", organization);
        context.setVariable("qrImageCid", "cid:qr-credential-offer.png");
        context.setVariable("walletDeepLink", walletDeepLink);
        context.setVariable("walletInstallUrl", walletUrl.endsWith("/") ? walletUrl : walletUrl + "/");
        context.setVariable("reissueUrl", reissueUrl);
        inlinePngs.put("qr-credential-offer.png", qrImageBytes);
    }

    /** Common icon shipped in {@code email/icons/}, referenced by the templates as {@code cid:icon-<name>.png}. */
    private void addIcon(Map<String, byte[]> inlinePngs, String name) {
        inlinePngs.put("icon-" + name + ".png", ICONS.computeIfAbsent(name, EmailServiceImpl::readIcon));
    }

    private static byte[] readIcon(String name) {
        return readClasspath(ICONS_PATH + name + ".png");
    }

    private static byte[] readClasspath(String path) {
        try (InputStream in = new ClassPathResource(path).getInputStream()) {
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException("Missing email image: " + path, e);
        }
    }

    private byte[] generateQrCodeImage(String content, int width, int height) {
        try {
            QRCodeWriter qrCodeWriter = new QRCodeWriter();
            Map<EncodeHintType, Object> hints = Map.of(
                    EncodeHintType.CHARACTER_SET, UTF_8,
                    EncodeHintType.MARGIN, 1
            );
            BitMatrix bitMatrix = qrCodeWriter.encode(content, BarcodeFormat.QR_CODE, width, height, hints);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);
            return outputStream.toByteArray();
        } catch (Exception e) {
            throw new EmailCommunicationException("Failed to generate QR code image");
        }
    }

    private Context createLocalizedContext(String locale) {
        Context context = new Context();
        context.setLocale(Locale.forLanguageTag(locale));
        return context;
    }

}
