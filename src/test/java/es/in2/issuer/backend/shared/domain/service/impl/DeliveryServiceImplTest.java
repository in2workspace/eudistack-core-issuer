package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferEmailNotificationInfo;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DeliveryServiceImplTest {

    @Mock
    private EmailService emailService;

    @Mock
    private AppConfig appConfig;

    @InjectMocks
    private DeliveryServiceImpl deliveryService;

    @Test
    void shouldReturnCredentialOfferUriForUiDelivery() {
        String credentialOfferUri = "openid-credential-offer://example.com";
        CredentialOfferEmailNotificationInfo emailInfo = new CredentialOfferEmailNotificationInfo("test@example.com", "Org");

        StepVerifier.create(deliveryService.deliver("ui", credentialOfferUri, "refresh-token", emailInfo))
                .assertNext(response -> assertEquals(credentialOfferUri, response.credentialOfferUri()))
                .verifyComplete();

        verifyNoInteractions(emailService);
    }

    @Test
    void shouldSendEmailForEmailDelivery() {
        String credentialOfferUri = "openid-credential-offer://example.com";
        CredentialOfferEmailNotificationInfo emailInfo = new CredentialOfferEmailNotificationInfo("test@example.com", "Org");

        when(appConfig.getIssuerBackendUrl()).thenReturn("https://issuer.example.com");
        when(appConfig.getWalletFrontendUrl()).thenReturn("https://wallet.example.com");
        when(emailService.sendCredentialOfferEmail(anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        StepVerifier.create(deliveryService.deliver("email", credentialOfferUri, "refresh-token", emailInfo))
                .assertNext(response -> assertNull(response.credentialOfferUri()))
                .verifyComplete();

        verify(emailService).sendCredentialOfferEmail(
                eq("test@example.com"),
                anyString(),
                eq(credentialOfferUri),
                anyString(),
                eq("https://wallet.example.com"),
                eq("Org")
        );
    }
}
