package es.in2.issuer.backend.shared.infrastructure.adapter.email;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.TranslationService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeUtility;
import io.micrometer.observation.annotation.Observed;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.InputStreamSource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.springframework.util.MimeTypeUtils;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import reactor.core.publisher.Mono;
import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.Constants.MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE;
import static es.in2.issuer.backend.shared.domain.util.Constants.UTF_8;

@Slf4j
@Service
public class EmailServiceImpl implements EmailService {
    private final JavaMailSender javaMailSender;
    private final TemplateEngine templateEngine;
    private final String mailFrom;
    private final TranslationService translationService;

    public EmailServiceImpl(
            JavaMailSender javaMailSender,
            TemplateEngine templateEngine,
            @Value("${app.mail-from}") String mailFrom,
            TranslationService translationService
    ) {
        this.javaMailSender = javaMailSender;
        this.templateEngine = templateEngine;
        this.mailFrom = mailFrom;
        this.translationService = translationService;
    }

    @Override
    public Mono<Void> sendTxCodeNotification(String to, String subject, String txCode) {
        return Mono.fromCallable(() -> {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);
            helper.setFrom(mailFrom);
            helper.setTo(to);

            String translated = translationService.translate(subject);
            String encodedSubject = MimeUtility.encodeText(translated, StandardCharsets.UTF_8.name(), "B");

            helper.setSubject(encodedSubject);

            Context context = createLocalizedContext();
            context.setVariable("txCode", txCode);
            String htmlContent = templateEngine.process("tx-code-email", context);
            helper.setText(htmlContent, true);

            javaMailSender.send(mimeMessage);
            return null;
        })
                .then()
                .onErrorMap(ex -> new EmailCommunicationException("Error when sending tx code notification"));
    }

    @Observed(name = "issuance.send-email", contextualName = "issuance-send-email")
    @Override
    public Mono<Void> sendCredentialOfferEmail(String to, String subject, String credentialOfferUri,
                                                String reissueUrl, String walletUrl, String organization, String txCode) {
        return Mono.fromCallable(() -> {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);
            helper.setFrom(mailFrom);
            helper.setTo(to);
            helper.setSubject(translationService.translate(subject));

            // Generate QR code image from the credential offer URI
            byte[] qrImageBytes = generateQrCodeImage(credentialOfferUri, 300, 300);

            // Build wallet deep link: extract the HTTPS URL from the openid-credential-offer:// URI
            String walletDeepLink = buildWalletDeepLink(credentialOfferUri, walletUrl);

            Context context = createLocalizedContext();
            context.setVariable("organization", organization);
            context.setVariable("qrImageCid", "cid:qr-credential-offer.png");
            context.setVariable("walletDeepLink", walletDeepLink);
            context.setVariable("reissueUrl", reissueUrl);
            if (txCode != null) {
                context.setVariable("txCode", txCode);
            }

            String htmlContent = templateEngine.process("credential-offer-email", context);
            helper.setText(htmlContent, true);

            InputStreamSource qrImageSource = new ByteArrayResource(qrImageBytes);
            helper.addInline("qr-credential-offer.png", qrImageSource, MimeTypeUtils.IMAGE_PNG_VALUE);

            javaMailSender.send(mimeMessage);
            return null;
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

    private String buildWalletDeepLink(String credentialOfferUri, String walletUrl) {
        // credentialOfferUri format: openid-credential-offer://?credential_offer_uri=https%3A%2F%2F...
        // Extract the HTTPS URL from the query parameter
        String prefix = "openid-credential-offer://?credential_offer_uri=";
        String httpsUrl = credentialOfferUri.startsWith(prefix)
                ? credentialOfferUri.substring(prefix.length())
                : URLEncoder.encode(credentialOfferUri, StandardCharsets.UTF_8);
        return walletUrl + "/protocol/callback?credential_offer_uri=" + httpsUrl;
    }

    @Override
    public Mono<Void> sendCredentialStatusChangeNotification(String to, String credentialId, String type, String status) {
        return sendCredentialRevokedOrExpiredNotificationEmail(to, credentialId, type, status)
                .onErrorMap(e -> new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE));
    }

    @Override
    public Mono<Void> sendCredentialFailureNotification(String to, String eventDescription) {
        return Mono.fromCallable(() -> {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);
            helper.setFrom(mailFrom);
            helper.setTo(to);
            helper.setSubject(translationService.translate("email.credential-failure.subject"));
            Context context = createLocalizedContext();
            context.setVariable("eventDescription", eventDescription != null ? eventDescription : "");
            helper.setText(templateEngine.process("credential-failure-email", context), true);
            javaMailSender.send(mimeMessage);
            return null;
        }).then()
                .onErrorMap(e -> new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE));
    }

    private Mono<Void> sendCredentialRevokedOrExpiredNotificationEmail(String to, String credentialId, String type, String credentialStatus){
        return Mono.fromCallable(() -> {
            try {
                MimeMessage mimeMessage = javaMailSender.createMimeMessage();
                MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);

                helper.setFrom(mailFrom);
                helper.setTo(to);

                Context context = buildStatusChangeEmailContext(credentialId, type, credentialStatus);

                switch (credentialStatus) {
                    case "REVOKED" -> {
                        helper.setSubject(translationService.translate("email.revoked.subject"));
                        context.setVariable("title", translationService.translate("email.revoked.title"));
                    }
                    case "EXPIRED" -> {
                        helper.setSubject(translationService.translate("email.expired.subject"));
                        context.setVariable("title", translationService.translate("email.expired.title"));
                    }
                    default -> helper.setSubject(translationService.translate("email.default-status.subject"));

                }
                String htmlContent = templateEngine.process("revoked-expired-credential-email", context);
                helper.setText(htmlContent, true);

                javaMailSender.send(mimeMessage);
            } catch (MessagingException e) {
                throw new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE);
            }

            return null;
        }).then();
    }

    private Context buildStatusChangeEmailContext(String credentialId, String type, String credentialStatus) {
        Context context = createLocalizedContext();
        context.setVariable("credentialId", credentialId);
        context.setVariable("type", type);
        context.setVariable("credentialStatus", credentialStatus);
        return context;
    }

    private Context createLocalizedContext() {
        Context context = new Context();
        context.setLocale(Locale.forLanguageTag(translationService.getLocale()));
        return context;
    }

}
