package es.in2.issuer.backend.shared.infrastructure.adapter.email;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.shared.domain.service.TranslationService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeUtility;
import io.micrometer.observation.annotation.Observed;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.InputStreamSource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.springframework.util.MimeTypeUtils;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Slf4j
@Service
public class EmailServiceImpl implements EmailService {

    private static final String MAIL_FROM_KEY = "issuer.mail_from";
    private static final String DEFAULT_LANG_KEY = "issuer.default_lang";

    private final JavaMailSender javaMailSender;
    private final TemplateEngine templateEngine;
    private final TenantConfigService tenantConfigService;
    private final TranslationService translationService;

    public EmailServiceImpl(
            JavaMailSender javaMailSender,
            TemplateEngine templateEngine,
            TenantConfigService tenantConfigService,
            TranslationService translationService
    ) {
        this.javaMailSender = javaMailSender;
        this.templateEngine = templateEngine;
        this.tenantConfigService = tenantConfigService;
        this.translationService = translationService;
    }

    @Override
    public Mono<Void> sendTxCodeNotification(String to, String subject, String txCode) {
        return Mono.zip(
                tenantConfigService.getStringOrThrow(MAIL_FROM_KEY),
                tenantConfigService.getStringOrDefault(DEFAULT_LANG_KEY, "")
        ).flatMap(tuple -> {
            String mailFrom = tuple.getT1();
            String locale = translationService.getLocaleOrDefault(tuple.getT2());
            return Mono.fromCallable(() -> {
                MimeMessage mimeMessage = javaMailSender.createMimeMessage();
                MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);
                helper.setFrom(mailFrom);
                helper.setTo(to);

                String translated = translationService.translateWithLocale(subject, locale);
                String encodedSubject = MimeUtility.encodeText(translated, StandardCharsets.UTF_8.name(), "B");

                helper.setSubject(encodedSubject);

                Context context = createLocalizedContext(locale);
                context.setVariable("txCode", txCode);
                String htmlContent = templateEngine.process("tx-code-email", context);
                helper.setText(htmlContent, true);

                javaMailSender.send(mimeMessage);
                return null;
            }).subscribeOn(Schedulers.boundedElastic());
        })
                .then()
                .onErrorMap(ex -> {
                    log.error("Failed to send tx code notification", ex);
                    return new EmailCommunicationException("Error when sending tx code notification");
                });
    }

    @Observed(name = "issuance.send-email", contextualName = "issuance-send-email")
    @Override
    public Mono<Void> sendCredentialOfferEmail(String to, String subject, String walletDeepLink,
                                               String reissueUrl, String organization, String txCode) {
        return doSendCredentialOfferEmail("credential-offer-email", to, subject,
                walletDeepLink, reissueUrl, organization, txCode);
    }

    @Observed(name = "issuance.send-email", contextualName = "issuance-send-email")
    @Override
    public Mono<Void> sendBrandedCredentialOfferEmail(String to, String subject, String walletDeepLink,
                                                      String reissueUrl, String organization) {
        return doSendCredentialOfferEmail("credential-offer-email-v2", to, subject,
                walletDeepLink, reissueUrl, organization, null);
    }

    private Mono<Void> doSendCredentialOfferEmail(String template, String to, String subject,
                                                   String walletDeepLink, String reissueUrl,
                                                   String organization, String txCode) {
        return Mono.zip(
                tenantConfigService.getStringOrThrow(MAIL_FROM_KEY),
                tenantConfigService.getStringOrThrow("issuer.wallet_url"),
                tenantConfigService.getStringOrDefault(DEFAULT_LANG_KEY, "")
        ).flatMap(tuple -> {
            String mailFrom = tuple.getT1();
            String walletUrl = tuple.getT2();
            String locale = translationService.getLocaleOrDefault(tuple.getT3());
            return Mono.fromCallable(() -> {
                MimeMessage mimeMessage = javaMailSender.createMimeMessage();
                MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);
                helper.setFrom(mailFrom);
                helper.setTo(to);
                helper.setSubject(translationService.translateWithLocale(subject, locale));

                byte[] qrImageBytes = generateQrCodeImage(walletDeepLink, 300, 300);

                Context context = createLocalizedContext(locale);
                context.setVariable("organization", organization);
                context.setVariable("qrImageCid", "cid:qr-credential-offer.png");
                context.setVariable("walletDeepLink", walletDeepLink);
                context.setVariable("walletInstallUrl", walletUrl.endsWith("/") ? walletUrl : walletUrl + "/");
                context.setVariable("reissueUrl", reissueUrl);
                if (txCode != null) {
                    context.setVariable("txCode", txCode);
                }

                String htmlContent = templateEngine.process(template, context);
                helper.setText(htmlContent, true);

                InputStreamSource qrImageSource = new ByteArrayResource(qrImageBytes);
                helper.addInline("qr-credential-offer.png", qrImageSource, MimeTypeUtils.IMAGE_PNG_VALUE);

                javaMailSender.send(mimeMessage);
                return null;
            }).subscribeOn(Schedulers.boundedElastic());
        }).then();
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

    @Override
    public Mono<Void> sendCredentialStatusChangeNotification(String to, String credentialId, String type, String status) {
        return sendCredentialRevokedOrExpiredNotificationEmail(to, credentialId, type, status)
                .onErrorMap(e -> new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE));
    }

    @Override
    public Mono<Void> sendCredentialFailureNotification(String to, String eventDescription) {
        return Mono.zip(
                tenantConfigService.getStringOrThrow(MAIL_FROM_KEY),
                tenantConfigService.getStringOrDefault(DEFAULT_LANG_KEY, "")
        ).flatMap(tuple -> {
            String mailFrom = tuple.getT1();
            String locale = translationService.getLocaleOrDefault(tuple.getT2());
            return Mono.fromCallable(() -> {
                MimeMessage mimeMessage = javaMailSender.createMimeMessage();
                MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);
                helper.setFrom(mailFrom);
                helper.setTo(to);
                helper.setSubject(translationService.translateWithLocale("email.credential-failure.subject", locale));
                Context context = createLocalizedContext(locale);
                context.setVariable("eventDescription", eventDescription != null ? eventDescription : "");
                helper.setText(templateEngine.process("credential-failure-email", context), true);
                javaMailSender.send(mimeMessage);
                return null;
            }).subscribeOn(Schedulers.boundedElastic());
        })
                .then()
                .onErrorMap(e -> new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE));
    }

    private Mono<Void> sendCredentialRevokedOrExpiredNotificationEmail(String to, String credentialId, String type, String credentialStatus){
        return Mono.zip(
                tenantConfigService.getStringOrThrow(MAIL_FROM_KEY),
                tenantConfigService.getStringOrDefault(DEFAULT_LANG_KEY, "")
        ).flatMap(tuple -> {
            String mailFrom = tuple.getT1();
            String locale = translationService.getLocaleOrDefault(tuple.getT2());
            return Mono.fromCallable(() -> {
                try {
                    MimeMessage mimeMessage = javaMailSender.createMimeMessage();
                    MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);

                    helper.setFrom(mailFrom);
                    helper.setTo(to);

                    Context context = buildStatusChangeEmailContext(credentialId, type, credentialStatus, locale);

                    switch (credentialStatus) {
                        case "REVOKED" -> {
                            helper.setSubject(translationService.translateWithLocale("email.revoked.subject", locale));
                            context.setVariable("title", translationService.translateWithLocale("email.revoked.title", locale));
                        }
                        case "EXPIRED" -> {
                            helper.setSubject(translationService.translateWithLocale("email.expired.subject", locale));
                            context.setVariable("title", translationService.translateWithLocale("email.expired.title", locale));
                        }
                        default -> helper.setSubject(translationService.translateWithLocale("email.default-status.subject", locale));

                    }
                    String htmlContent = templateEngine.process("revoked-expired-credential-email", context);
                    helper.setText(htmlContent, true);

                    javaMailSender.send(mimeMessage);
                } catch (MessagingException e) {
                    throw new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE);
                }

                return null;
            }).subscribeOn(Schedulers.boundedElastic());
        })
                .then();
    }

    private Context buildStatusChangeEmailContext(String credentialId, String type, String credentialStatus, String locale) {
        Context context = createLocalizedContext(locale);
        context.setVariable("credentialId", credentialId);
        context.setVariable("type", type);
        context.setVariable("credentialStatus", credentialStatus);
        return context;
    }

    private Context createLocalizedContext(String locale) {
        Context context = new Context();
        context.setLocale(Locale.forLanguageTag(locale));
        return context;
    }

}
