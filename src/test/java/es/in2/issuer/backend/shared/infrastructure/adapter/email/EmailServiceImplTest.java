package es.in2.issuer.backend.shared.infrastructure.adapter.email;

import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.service.TranslationService;
import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.javamail.JavaMailSender;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EmailServiceImplTest {

    @Mock private JavaMailSender javaMailSender;
    @Mock private TemplateEngine templateEngine;
    @Mock private TranslationService translationService;

    private EmailServiceImpl emailService;

    @BeforeEach
    void setUpLenient() {
        emailService = new EmailServiceImpl(
                javaMailSender, templateEngine, "noreply@example.com",
                translationService
        );
        lenient().when(translationService.getLocale()).thenReturn("en");
        lenient().when(translationService.translate(any(String.class)))
                .thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    void testSendTxCodeNotification() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("pin-email-en"), any(Context.class))).thenReturn("htmlContent");

        StepVerifier.create(emailService.sendTxCodeNotification("to@example.com", "subject.key", "1234"))
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);
    }

    @Test
    void testSendCredentialActivationEmail() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("activate-credential-email-en"), any(Context.class))).thenReturn("htmlContent");

        StepVerifier.create(
                emailService.sendCredentialActivationEmail("to@example.com", "subject.key", "link", "knowledgebaseUrl", "organization")
        ).verifyComplete();

        verify(javaMailSender).send(mimeMessage);
    }

    @Test
    void testSendPendingCredentialNotification() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("credential-pending-notification-en"), any(Context.class))).thenReturn("htmlContent");

        StepVerifier.create(emailService.sendPendingCredentialNotification("to@example.com", "subject.key"))
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);
    }

    @Test
    void testSendPendingSignatureCredentialNotification() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("credential-pending-signature-notification-en"), any(Context.class))).thenReturn("htmlContent");

        StepVerifier.create(emailService.sendPendingSignatureCredentialNotification("to@example.com", "subject.key", "\"John\"", "domain"))
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);
    }

    @Test
    void testSendCredentialSignedNotification() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("credential-signed-notification-en"), any(Context.class))).thenReturn("htmlContent");

        StepVerifier.create(emailService.sendCredentialSignedNotification("to@example.com", "subject.key", "additionalInfo"))
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);
    }

    @Test
    void sendResponseUriFailed_sendsEmailSuccessfully() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("response-uri-failed-en"), any(Context.class))).thenReturn("htmlContent");

        StepVerifier.create(emailService.sendResponseUriFailed("to@example.com", "productId", "guideUrl"))
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);
    }

    @Test
    void sendResponseUriFailed_handlesException() {
        when(javaMailSender.createMimeMessage()).thenThrow(new RuntimeException("Mail server error"));

        StepVerifier.create(emailService.sendResponseUriFailed("to@example.com", "productId", "guideUrl"))
                .expectError(RuntimeException.class)
                .verify();
    }

    @Test
    void sendResponseUriAcceptedWithHtml_sendsEmailSuccessfully() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);

        StepVerifier.create(emailService.sendResponseUriAcceptedWithHtml("to@example.com", "productId", "htmlContent"))
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);
    }

    @Test
    void sendResponseUriAcceptedWithHtml_handlesException() {
        when(javaMailSender.createMimeMessage()).thenThrow(new RuntimeException("Mail server error"));

        StepVerifier.create(emailService.sendResponseUriAcceptedWithHtml("to@example.com", "productId", "htmlContent"))
                .expectError(RuntimeException.class)
                .verify();
    }

    @Test
    void sendCredentialStatusChangeNotification_withExpiredStatus_sendsEmailAndSetsTemplateVariables() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("revoked-expired-credential-email-en"), any(Context.class)))
                .thenReturn("htmlContent");

        StepVerifier.create(emailService.sendCredentialStatusChangeNotification(
                "to@example.com", "ACME Corp", "cred-123", "learcredential.employee.w3c.4", "EXPIRED"
        )).verifyComplete();

        verify(javaMailSender).send(mimeMessage);

        ArgumentCaptor<Context> ctxCaptor = ArgumentCaptor.forClass(Context.class);
        verify(templateEngine).process(eq("revoked-expired-credential-email-en"), ctxCaptor.capture());
        Context ctx = ctxCaptor.getValue();

        assertEquals("email.expired.title", ctx.getVariable("title"));
        assertEquals("ACME Corp", ctx.getVariable("organization"));
        assertEquals("cred-123", ctx.getVariable("credentialId"));
        assertEquals("learcredential.employee.w3c.4", ctx.getVariable("type"));
        assertEquals("EXPIRED", ctx.getVariable("credentialStatus"));
    }

    @Test
    void sendCredentialStatusChangeNotification_withRevokedStatus_sendsEmailAndSetsTemplateVariables() {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("revoked-expired-credential-email-en"), any(Context.class)))
                .thenReturn("htmlContent");

        StepVerifier.create(emailService.sendCredentialStatusChangeNotification(
                "to@example.com", "Umbrella Inc", "cred-999", "learcredential.employee.w3c.4", "REVOKED"
        )).verifyComplete();

        verify(javaMailSender).send(mimeMessage);

        ArgumentCaptor<Context> ctxCaptor = ArgumentCaptor.forClass(Context.class);
        verify(templateEngine).process(eq("revoked-expired-credential-email-en"), ctxCaptor.capture());
        Context ctx = ctxCaptor.getValue();

        assertEquals("email.revoked.title", ctx.getVariable("title"));
        assertEquals("Umbrella Inc", ctx.getVariable("organization"));
        assertEquals("cred-999", ctx.getVariable("credentialId"));
        assertEquals("learcredential.employee.w3c.4", ctx.getVariable("type"));
        assertEquals("REVOKED", ctx.getVariable("credentialStatus"));
    }

    @Test
    void sendCredentialStatusChangeNotification_onMailError_mapsToEmailCommunicationException() {
        when(javaMailSender.createMimeMessage()).thenThrow(new RuntimeException("Mail server error"));

        StepVerifier.create(emailService.sendCredentialStatusChangeNotification(
                "to@example.com", "ACME Corp", "cred-123", "learcredential.employee.w3c.4", "REVOKED"
        )).expectError(EmailCommunicationException.class)
                .verify();
    }
}
