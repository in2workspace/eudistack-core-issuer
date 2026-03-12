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
        when(templateEngine.process(eq("tx-code-email"), any(Context.class))).thenReturn("htmlContent");

        StepVerifier.create(emailService.sendTxCodeNotification("to@example.com", "subject.key", "1234"))
                .verifyComplete();

        verify(javaMailSender).send(mimeMessage);
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
}
