package es.in2.issuer.backend.shared.infrastructure.adapter.email;

import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEventType;
import es.in2.issuer.backend.shared.domain.model.audit.AuditResult;
import es.in2.issuer.backend.shared.domain.model.dto.EmailBranding;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.domain.service.TranslationService;
import es.in2.issuer.backend.shared.domain.spi.EmailBrandingResolver;
import es.in2.issuer.backend.shared.domain.spi.RecordingAuditTrail;
import es.in2.issuer.backend.shared.infrastructure.audit.ExternalSystemAccessRecorder;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.ConnectException;
import java.util.ArrayList;
import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Constants.ENVIRONMENT_LABEL_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EmailServiceImplTest {

    @Mock private JavaMailSender javaMailSender;
    @Mock private TemplateEngine templateEngine;
    @Mock private TenantConfigService tenantConfigService;
    @Mock private TranslationService translationService;
    @Mock private EmailBrandingResolver emailBrandingResolver;
    @Mock private TenantRegistryService tenantRegistryService;

    private static final EmailBranding BRANDING = new EmailBranding(
            "https://assets.example.com/dome/email/logo.png",
            "https://assets.example.com/dome/email/header-bg.png",
            "https://support.example.com", "https://kb.example.com", List.of());

    private final RecordingAuditTrail auditTrail = new RecordingAuditTrail();

    private EmailServiceImpl emailService;

    @BeforeEach
    void setUpLenient() {
        emailService = new EmailServiceImpl(
                javaMailSender, templateEngine, tenantConfigService, translationService,
                emailBrandingResolver, tenantRegistryService, new ExternalSystemAccessRecorder(auditTrail)
        );
        lenient().when(tenantConfigService.getStringOrThrow("issuer.mail_from"))
                .thenReturn(Mono.just("noreply@example.com"));
        lenient().when(tenantConfigService.getStringOrDefault("issuer.default_lang", ""))
                .thenReturn(Mono.just("en"));
        lenient().when(emailBrandingResolver.resolve()).thenReturn(Mono.just(BRANDING));
        lenient().when(tenantRegistryService.getDisplayName("dome")).thenReturn(Mono.just("DOME Marketplace"));
        lenient().when(translationService.getLocaleOrDefault(anyString())).thenReturn("en");
        lenient().when(translationService.translateWithLocale(anyString(), anyString()))
                .thenAnswer(inv -> inv.getArgument(0));
        lenient().when(translationService.translateWithLocale(anyString(), anyString(), any()))
                .thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    void testSendTxCodeNotification() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("tx-code-email"), any(Context.class))).thenReturn("htmlContent");

        StepVerifier.create(emailService.sendTxCodeNotification("to@example.com", "1234"))
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);
    }

    @Test
    void sendTxCodeNotification_mailSent_stagesAMailProviderAccessWithTheTemplateAsOperation() {
        // Arrange
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("tx-code-email"), any(Context.class))).thenReturn("htmlContent");

        // Act
        Mono<Void> sent = emailService.sendTxCodeNotification("to@example.com", "1234");

        // Assert
        StepVerifier.create(sent).verifyComplete();
        assertEquals(1, auditTrail.stagedInNewTransaction().size());
        AuditEntry entry = auditTrail.stagedInNewTransaction().getFirst();
        assertEquals(AuditEventType.EXTERNAL_SYSTEM_ACCESS, entry.type());
        assertEquals(AuditResult.SUCCESS, entry.result());
        assertEquals("MailProvider", entry.details().get("system_type"));
        assertEquals("tx-code-email", entry.details().get("operation"));
    }

    @Test
    void sendTxCodeNotification_mailServerUnreachable_stagesAFailureAndStillFailsTheSend() {
        // Arrange
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("tx-code-email"), any(Context.class))).thenReturn("htmlContent");
        doThrow(new MailSendException("failed", new ConnectException("refused"))).when(javaMailSender).send(mimeMessage);

        // Act
        Mono<Void> sent = emailService.sendTxCodeNotification("to@example.com", "1234");

        // Assert
        StepVerifier.create(sent).expectError(EmailCommunicationException.class).verify();
        AuditEntry entry = auditTrail.stagedInNewTransaction().getFirst();
        assertEquals(AuditResult.FAILURE, entry.result());
        assertEquals("Unreachable", entry.reason());
    }

    @Test
    void sendTxCodeNotification_messageCannotBeBuilt_stagesNoAccessBecauseNothingWasSent() {
        // Arrange
        when(javaMailSender.createMimeMessage()).thenThrow(new IllegalStateException("no session"));

        // Act
        Mono<Void> sent = emailService.sendTxCodeNotification("to@example.com", "1234");

        // Assert
        StepVerifier.create(sent).expectError(EmailCommunicationException.class).verify();
        assertTrue(auditTrail.all().isEmpty());
    }

    @Test
    void sendTxCodeNotification_usesPerTenantLanguageForContextLocale() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(tenantConfigService.getStringOrDefault("issuer.default_lang", ""))
                .thenReturn(Mono.just("es"));
        when(translationService.getLocaleOrDefault("es")).thenReturn("es");
        when(templateEngine.process(eq("tx-code-email"), any(Context.class))).thenReturn("htmlContent");

        StepVerifier.create(emailService.sendTxCodeNotification("to@example.com", "1234"))
                .verifyComplete();

        ArgumentCaptor<Context> ctxCaptor = ArgumentCaptor.forClass(Context.class);
        verify(templateEngine).process(eq("tx-code-email"), ctxCaptor.capture());
        assertEquals("es", ctxCaptor.getValue().getLocale().getLanguage());
    }

    @Test
    void sendTxCodeNotification_onMailError_throwsEmailCommunicationException() {
        // Arrange
        when(javaMailSender.createMimeMessage()).thenThrow(new RuntimeException("SMTP down"));

        // Act & Assert
        StepVerifier.create(emailService.sendTxCodeNotification("to@example.com", "1234"))
                .expectError(EmailCommunicationException.class)
                .verify();
    }

    @Test
    void sendCredentialOfferEmail_withTxCode_sendsEmailAndIncludesTxCodeInContext() {
        // Arrange
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("credential-offer-email"), any(Context.class))).thenReturn("htmlContent");

        // Act
        StepVerifier.create(emailService.sendCredentialOfferEmail(
                "to@example.com",
                "https://wallet.example.com/protocol/callback?credential_offer_uri=https%3A%2F%2Fexample.com",
                "https://example.com/reissue",
                "ACME Corp", "TX123"
        )).verifyComplete();

        // Assert
        verify(javaMailSender).send(mimeMessage);
        ArgumentCaptor<Context> ctxCaptor = ArgumentCaptor.forClass(Context.class);
        verify(templateEngine).process(eq("credential-offer-email"), ctxCaptor.capture());
        Context ctx = ctxCaptor.getValue();
        assertEquals("ACME Corp", ctx.getVariable("organization"));
        assertEquals("cid:qr-credential-offer.png", ctx.getVariable("qrImageCid"));
        assertEquals("TX123", ctx.getVariable("txCode"));
    }

    @Test
    void sendCredentialOfferEmail_withoutTxCode_doesNotIncludeTxCodeInContext() {
        // Arrange
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("credential-offer-email"), any(Context.class))).thenReturn("htmlContent");

        // Act & Assert
        StepVerifier.create(emailService.sendCredentialOfferEmail(
                "to@example.com",
                "https://wallet.example.com/protocol/callback?credential_offer_uri=https%3A%2F%2Fexample.com",
                "https://example.com/reissue",
                "ACME Corp", null
        )).verifyComplete();

        ArgumentCaptor<Context> ctxCaptor = ArgumentCaptor.forClass(Context.class);
        verify(templateEngine).process(eq("credential-offer-email"), ctxCaptor.capture());
        assertNull(ctxCaptor.getValue().getVariable("txCode"));
    }

    /**
     * EUD-305: the link is decided by the caller (wallet link or standard form); the email service
     * renders it as given and no longer requires {@code issuer.wallet_url}.
     */
    @Test
    void sendCredentialOfferEmail_withStandardOfferUri_rendersItAsGivenWithoutReadingWalletUrl() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("credential-offer-email"), any(Context.class))).thenReturn("htmlContent");
        String standardOfferUri = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example.com%2Fcredential-offer%2Fnonce";

        StepVerifier.create(emailService.sendCredentialOfferEmail(
                "to@example.com", standardOfferUri,
                "https://example.com/reissue", "ACME Corp", null
        )).verifyComplete();

        verify(javaMailSender).send(mimeMessage);
        ArgumentCaptor<Context> ctxCaptor = ArgumentCaptor.forClass(Context.class);
        verify(templateEngine).process(eq("credential-offer-email"), ctxCaptor.capture());
        assertEquals(standardOfferUri, ctxCaptor.getValue().getVariable("credentialOfferLink"));
        assertNull(ctxCaptor.getValue().getVariable("walletInstallUrl"));
        verify(tenantConfigService, never()).getStringOrThrow("issuer.wallet_url");
        verify(tenantConfigService, never()).getString("issuer.wallet_url");
    }

    @Test
    void sendCredentialOfferEmail_onMailError_propagatesException() {
        // Arrange
        when(javaMailSender.createMimeMessage()).thenThrow(new RuntimeException("SMTP down"));
        // Act & Assert
        StepVerifier.create(emailService.sendCredentialOfferEmail(
                "to@example.com",
                "https://wallet.example.com/protocol/callback?credential_offer_uri=https%3A%2F%2Fexample.com",
                "https://example.com/reissue",
                "ACME Corp", "TX123"
        )).expectError(RuntimeException.class)
                .verify();
    }

    @Test
    void sendCredentialStatusChangeNotification_withExpiredStatus_sendsEmailAndSetsTemplateVariables() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("revoked-expired-credential-email"), any(Context.class)))
                .thenReturn("htmlContent");

        StepVerifier.create(emailService.sendCredentialStatusChangeNotification(
                "to@example.com", "cred-123", "learcredential.employee.w3c.4", "EXPIRED"
        )).verifyComplete();

        verify(javaMailSender).send(mimeMessage);

        ArgumentCaptor<Context> ctxCaptor = ArgumentCaptor.forClass(Context.class);
        verify(templateEngine).process(eq("revoked-expired-credential-email"), ctxCaptor.capture());
        Context ctx = ctxCaptor.getValue();

        assertEquals("email.expired.title", ctx.getVariable("title"));
        assertEquals("cred-123", ctx.getVariable("credentialId"));
        assertEquals("learcredential.employee.w3c.4", ctx.getVariable("type"));
        assertEquals("EXPIRED", ctx.getVariable("credentialStatus"));
    }

    @Test
    void sendCredentialStatusChangeNotification_withRevokedStatus_sendsEmailAndSetsTemplateVariables() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("revoked-expired-credential-email"), any(Context.class)))
                .thenReturn("htmlContent");

        StepVerifier.create(emailService.sendCredentialStatusChangeNotification(
                "to@example.com", "cred-999", "learcredential.employee.w3c.4", "REVOKED"
        )).verifyComplete();

        verify(javaMailSender).send(mimeMessage);

        ArgumentCaptor<Context> ctxCaptor = ArgumentCaptor.forClass(Context.class);
        verify(templateEngine).process(eq("revoked-expired-credential-email"), ctxCaptor.capture());
        Context ctx = ctxCaptor.getValue();

        assertEquals("email.revoked.title", ctx.getVariable("title"));
        assertEquals("cred-999", ctx.getVariable("credentialId"));
        assertEquals("learcredential.employee.w3c.4", ctx.getVariable("type"));
        assertEquals("REVOKED", ctx.getVariable("credentialStatus"));
    }

    @Test
    void sendCredentialStatusChangeNotification_onMailError_mapsToEmailCommunicationException() {
        when(javaMailSender.createMimeMessage()).thenThrow(new RuntimeException("Mail server error"));

        StepVerifier.create(emailService.sendCredentialStatusChangeNotification(
                "to@example.com", "cred-123", "learcredential.employee.w3c.4", "REVOKED"
        )).expectError(EmailCommunicationException.class)
                .verify();
    }

    @Test
    void sendCredentialFailureNotification_withEventDescription_sendsEmailAndSetsTemplateVariable() {
        // Arrange
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("credential-failure-email"), any(Context.class))).thenReturn("htmlContent");

        // Act & Assert
        StepVerifier.create(emailService.sendCredentialFailureNotification(
                "to@example.com", "Timeout waiting for user decision"
        )).verifyComplete();

        verify(javaMailSender).send(mimeMessage);
        ArgumentCaptor<Context> ctxCaptor = ArgumentCaptor.forClass(Context.class);
        verify(templateEngine).process(eq("credential-failure-email"), ctxCaptor.capture());
        assertEquals("Timeout waiting for user decision", ctxCaptor.getValue().getVariable("eventDescription"));
    }

    @Test
    void sendCredentialFailureNotification_withNullEventDescription_sendsEmailWithEmptyString() {
        // Arrange
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("credential-failure-email"), any(Context.class))).thenReturn("htmlContent");

        // Act & Assert
        StepVerifier.create(emailService.sendCredentialFailureNotification("to@example.com", null))
                .verifyComplete();

        ArgumentCaptor<Context> ctxCaptor = ArgumentCaptor.forClass(Context.class);
        verify(templateEngine).process(eq("credential-failure-email"), ctxCaptor.capture());
        assertEquals("", ctxCaptor.getValue().getVariable("eventDescription"));
    }

    @Test
    void sendCredentialFailureNotification_onMailError_throwsEmailCommunicationException() {
        // Arrange
        when(javaMailSender.createMimeMessage()).thenThrow(new RuntimeException("SMTP down"));

        // Act & Assert
        StepVerifier.create(emailService.sendCredentialFailureNotification("to@example.com", "some error"))
                .expectError(EmailCommunicationException.class)
                .verify();
    }

    @Test
    void sendBrandedCredentialOfferEmail_sendsEmailWithCorrectTemplateAndVariables() {
        // Arrange
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("credential-offer-email-v2"), any(Context.class))).thenReturn("<html>v2</html>");

        String credentialOfferLink = "https://wallet.example.com/protocol/callback?credential_offer_uri=https%3A%2F%2Fissuer.example.com%2Fcredential-offer%2Fnonce";
        String reissueUrl = "https://issuer.example.com/credential-offer/refresh/abc";

        // Act
        StepVerifier.create(emailService.sendBrandedCredentialOfferEmail(
                "user@kpmg.com",
                "email.activation.subject",
                credentialOfferLink,
                reissueUrl,
                "KPMG Spain"
        )).verifyComplete();

        // Assert
        verify(javaMailSender).send(mimeMessage);
        ArgumentCaptor<Context> ctxCaptor = ArgumentCaptor.forClass(Context.class);
        verify(templateEngine).process(eq("credential-offer-email-v2"), ctxCaptor.capture());
        Context ctx = ctxCaptor.getValue();
        assertEquals("KPMG Spain", ctx.getVariable("organization"));
        assertEquals("cid:qr-credential-offer.png", ctx.getVariable("qrImageCid"));
        assertEquals(reissueUrl, ctx.getVariable("reissueUrl"));
        assertEquals(credentialOfferLink, ctx.getVariable("credentialOfferLink"));
    }

    @Test
    void sendBrandedCredentialOfferEmail_onMailError_propagatesException() {
        // Arrange
        when(javaMailSender.createMimeMessage()).thenThrow(new RuntimeException("SMTP down"));

        // Act & Assert
        StepVerifier.create(emailService.sendBrandedCredentialOfferEmail(
                "user@kpmg.com",
                "email.activation.subject",
                "https://wallet.example.com/protocol/callback?credential_offer_uri=https%3A%2F%2Fissuer.example.com%2Fcredential-offer%2Fnonce",
                "https://issuer.example.com/credential-offer/refresh/abc",
                "KPMG Spain"
        )).expectError(RuntimeException.class)
                .verify();
    }

    // --- Subjects, branding and the KPMG path (email-ui-refactor) -----------------------------------

    private static final String OFFER_DEEP_LINK =
            "https://wallet.example.com/protocol/callback?credential_offer_uri=https%3A%2F%2Fexample.com";

    private MimeMessage stubMimeMessage(String template) {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq(template), any(Context.class))).thenReturn("htmlContent");
        return mimeMessage;
    }

    private void stubOfferSubject(String expectedDisplayName, String rendered) {
        when(translationService.translateWithLocale("email.credential-offer.subject", "en", expectedDisplayName))
                .thenReturn(rendered);
    }

    @Test
    void sendCredentialOfferEmail_withEnvironmentLabel_prefixesSubjectWithLabelAndUsesDisplayName() throws Exception {
        MimeMessage mimeMessage = stubMimeMessage("credential-offer-email");
        stubOfferSubject("DOME Marketplace", "Your DOME Marketplace credential is ready");

        StepVerifier.create(emailService.sendCredentialOfferEmail(
                        "to@example.com", OFFER_DEEP_LINK, "https://example.com/reissue", "ACME Corp", null)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "dome")
                        .put(ENVIRONMENT_LABEL_CONTEXT_KEY, "SBX")))
                .verifyComplete();

        verify(mimeMessage).setSubject("[SBX] Your DOME Marketplace credential is ready", "UTF-8");
    }

    @Test
    void sendCredentialOfferEmail_withoutEnvironmentLabel_subjectHasNoPrefix() throws Exception {
        MimeMessage mimeMessage = stubMimeMessage("credential-offer-email");
        stubOfferSubject("DOME Marketplace", "Your DOME Marketplace credential is ready");

        StepVerifier.create(emailService.sendCredentialOfferEmail(
                        "to@example.com", OFFER_DEEP_LINK, "https://example.com/reissue", "ACME Corp", null)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "dome")))
                .verifyComplete();

        verify(mimeMessage).setSubject("Your DOME Marketplace credential is ready", "UTF-8");
    }

    @Test
    void sendCredentialOfferEmail_lineBreaksInSubjectValues_areReplacedBySpaces() throws Exception {
        MimeMessage mimeMessage = stubMimeMessage("credential-offer-email");
        stubOfferSubject("DOME Marketplace", "Your DOME\r\nBcc: x@example.com credential is ready");

        StepVerifier.create(emailService.sendCredentialOfferEmail(
                        "to@example.com", OFFER_DEEP_LINK, "https://example.com/reissue", "ACME Corp", null)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "dome")
                        .put(ENVIRONMENT_LABEL_CONTEXT_KEY, "S\nBX")))
                .verifyComplete();

        verify(mimeMessage).setSubject("[S BX] Your DOME Bcc: x@example.com credential is ready", "UTF-8");
    }

    @Test
    void sendCredentialOfferEmail_schedulerStyleCallWithoutRequestHost_hasNoLabelButResolvesBranding() throws Exception {
        MimeMessage mimeMessage = stubMimeMessage("credential-offer-email");
        stubOfferSubject("DOME Marketplace", "Your DOME Marketplace credential is ready");

        StepVerifier.create(emailService.sendCredentialOfferEmail(
                        "to@example.com", OFFER_DEEP_LINK, "https://example.com/reissue", "ACME Corp", null)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "dome")))
                .verifyComplete();

        verify(mimeMessage).setSubject("Your DOME Marketplace credential is ready", "UTF-8");
        ArgumentCaptor<Context> ctxCaptor = ArgumentCaptor.forClass(Context.class);
        verify(templateEngine).process(eq("credential-offer-email"), ctxCaptor.capture());
        assertEquals(BRANDING, ctxCaptor.getValue().getVariable("branding"));
        assertEquals("DOME Marketplace", ctxCaptor.getValue().getVariable("tenantDisplayName"));
    }

    @Test
    void sendTxCodeNotification_usesTenantNamedSubjectAndBranding() throws Exception {
        MimeMessage mimeMessage = stubMimeMessage("tx-code-email");
        when(translationService.translateWithLocale("email.tx-code.subject", "en", "DOME Marketplace"))
                .thenReturn("Your DOME Marketplace activation code");

        StepVerifier.create(emailService.sendTxCodeNotification("to@example.com", "1234")
                        .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "dome")))
                .verifyComplete();

        verify(mimeMessage).setSubject("Your DOME Marketplace activation code", "UTF-8");
        ArgumentCaptor<Context> ctxCaptor = ArgumentCaptor.forClass(Context.class);
        verify(templateEngine).process(eq("tx-code-email"), ctxCaptor.capture());
        assertEquals(BRANDING, ctxCaptor.getValue().getVariable("branding"));
    }

    @Test
    void sendCredentialStatusChangeNotification_revoked_usesTitleAsSubjectAndRevokedStyle() throws Exception {
        MimeMessage mimeMessage = stubMimeMessage("revoked-expired-credential-email");

        StepVerifier.create(emailService.sendCredentialStatusChangeNotification(
                "to@example.com", "cred-1", "type", "REVOKED")).verifyComplete();

        verify(mimeMessage).setSubject("email.revoked.title", "UTF-8");
        ArgumentCaptor<Context> ctxCaptor = ArgumentCaptor.forClass(Context.class);
        verify(templateEngine).process(eq("revoked-expired-credential-email"), ctxCaptor.capture());
        assertEquals("email.revoked", ctxCaptor.getValue().getVariable("statusKeyPrefix"));
        assertEquals("#E5483B", ctxCaptor.getValue().getVariable("statusWordColor"));
        assertEquals("#F8A9A9", ctxCaptor.getValue().getVariable("badgeBackground"));
    }

    @Test
    void sendCredentialStatusChangeNotification_expired_usesTitleAsSubjectAndExpiredStyle() throws Exception {
        MimeMessage mimeMessage = stubMimeMessage("revoked-expired-credential-email");

        StepVerifier.create(emailService.sendCredentialStatusChangeNotification(
                "to@example.com", "cred-1", "type", "EXPIRED")).verifyComplete();

        verify(mimeMessage).setSubject("email.expired.title", "UTF-8");
        ArgumentCaptor<Context> ctxCaptor = ArgumentCaptor.forClass(Context.class);
        verify(templateEngine).process(eq("revoked-expired-credential-email"), ctxCaptor.capture());
        assertEquals("email.expired", ctxCaptor.getValue().getVariable("statusKeyPrefix"));
        assertEquals("#B89C14", ctxCaptor.getValue().getVariable("statusWordColor"));
    }

    @Test
    void sendCredentialStatusChangeNotification_unknownStatus_keepsDefaultSubject() throws Exception {
        MimeMessage mimeMessage = stubMimeMessage("revoked-expired-credential-email");

        StepVerifier.create(emailService.sendCredentialStatusChangeNotification(
                "to@example.com", "cred-1", "type", "SUSPENDED")).verifyComplete();

        verify(mimeMessage).setSubject("email.default-status.subject", "UTF-8");
    }

    @Test
    void sendCredentialFailureNotification_keepsFailureSubject() throws Exception {
        MimeMessage mimeMessage = stubMimeMessage("credential-failure-email");

        StepVerifier.create(emailService.sendCredentialFailureNotification("to@example.com", "boom"))
                .verifyComplete();

        verify(mimeMessage).setSubject("email.credential-failure.subject", "UTF-8");
    }

    @Test
    void sendBrandedCredentialOfferEmail_kpmgPath_keepsActivationSubjectAndSkipsBranding() throws Exception {
        MimeMessage mimeMessage = stubMimeMessage("credential-offer-email-v2");

        StepVerifier.create(emailService.sendBrandedCredentialOfferEmail(
                        "user@kpmg.com", "email.activation.subject", OFFER_DEEP_LINK,
                        "https://example.com/reissue", "KPMG Spain")
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "kpmg")
                        .put(ENVIRONMENT_LABEL_CONTEXT_KEY, "SBX")))
                .verifyComplete();

        verify(mimeMessage).setSubject("email.activation.subject", "UTF-8");
        ArgumentCaptor<Context> ctxCaptor = ArgumentCaptor.forClass(Context.class);
        verify(templateEngine).process(eq("credential-offer-email-v2"), ctxCaptor.capture());
        Context ctx = ctxCaptor.getValue();
        assertNull(ctx.getVariable("branding"));
        assertNull(ctx.getVariable("tenantDisplayName"));
        assertEquals(OFFER_DEEP_LINK, ctx.getVariable("credentialOfferLink"));
        assertNull(ctx.getVariable("walletInstallUrl"));
        verifyNoInteractions(emailBrandingResolver, tenantRegistryService);
    }

    /** Regression: the QR part must follow the HTML body, or clients show the image as body and the HTML as an attachment. */
    @Test
    void sendCredentialOfferEmail_htmlBodyIsFirstRelatedPartAndQrFollows() throws Exception {
        assertHtmlBodyPrecedesQr(emailService.sendCredentialOfferEmail(
                "to@example.com", OFFER_DEEP_LINK, "https://example.com/reissue", "ACME Corp", null),
                "credential-offer-email");
    }

    @Test
    void sendBrandedCredentialOfferEmail_htmlBodyIsFirstRelatedPartAndQrFollows() throws Exception {
        assertHtmlBodyPrecedesQr(emailService.sendBrandedCredentialOfferEmail(
                "user@kpmg.com", "email.activation.subject", OFFER_DEEP_LINK,
                "https://example.com/reissue", "KPMG Spain"),
                "credential-offer-email-v2");
    }

    @Test
    void sendCredentialFailureNotification_withDetailsAndSocialLinks_attachesBundledIconsInline() throws Exception {
        when(emailBrandingResolver.resolve()).thenReturn(Mono.just(new EmailBranding(
                BRANDING.logoUrl(), BRANDING.headerBackgroundUrl(), BRANDING.supportUrl(), BRANDING.knowledgeBaseUrl(),
                List.of(new EmailBranding.SocialLink("github", "https://github.com/dome"),
                        new EmailBranding.SocialLink("linkedin", "https://linkedin.com/dome")))));

        assertEquals(List.of("<icon-github.png>", "<icon-linkedin.png>", "<icon-warning.png>"),
                inlineContentIds(emailService.sendCredentialFailureNotification("to@example.com", "Timeout")));
    }

    @Test
    void sendCredentialFailureNotification_withoutDetailsOrSocialLinks_attachesNoIcons() throws Exception {
        assertEquals(List.of(),
                inlineContentIds(emailService.sendCredentialFailureNotification("to@example.com", "")));
    }

    /** Content ids of the inline parts that follow the HTML body in multipart/related. */
    private List<String> inlineContentIds(Mono<Void> send) throws Exception {
        MimeMessage mimeMessage = new MimeMessage((Session) null);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("credential-failure-email"), any(Context.class))).thenReturn("<p>body</p>");

        StepVerifier.create(send).verifyComplete();
        mimeMessage.saveChanges();

        MimeMultipart related = (MimeMultipart) ((MimeMultipart) mimeMessage.getContent()).getBodyPart(0).getContent();
        assertTrue(related.getBodyPart(0).isMimeType("text/html"));
        List<String> ids = new ArrayList<>();
        for (int i = 1; i < related.getCount(); i++) {
            assertTrue(related.getBodyPart(i).isMimeType("image/png"));
            ids.add(((MimeBodyPart) related.getBodyPart(i)).getContentID());
        }
        return ids;
    }

    private void assertHtmlBodyPrecedesQr(Mono<Void> send, String template) throws Exception {
        MimeMessage mimeMessage = new MimeMessage((Session) null);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq(template), any(Context.class))).thenReturn("<p>body</p>");

        StepVerifier.create(send).verifyComplete();
        mimeMessage.saveChanges();

        MimeMultipart mixed = (MimeMultipart) mimeMessage.getContent();
        MimeMultipart related = (MimeMultipart) mixed.getBodyPart(0).getContent();
        assertEquals(2, related.getCount());
        assertTrue(related.getBodyPart(0).isMimeType("text/html"));
        assertEquals("<qr-credential-offer.png>", ((MimeBodyPart) related.getBodyPart(1)).getContentID());
        assertTrue(related.getBodyPart(1).isMimeType("image/png"));
    }
}
