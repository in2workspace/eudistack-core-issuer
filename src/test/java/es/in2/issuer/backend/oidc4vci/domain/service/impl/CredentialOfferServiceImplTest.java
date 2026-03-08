package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.oidc4vci.domain.service.PreAuthorizedCodeService;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferEmailNotificationInfo;
import es.in2.issuer.backend.shared.domain.model.dto.PreAuthorizedCodeResponse;
import es.in2.issuer.backend.shared.domain.model.dto.TxCode;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialOfferServiceImplTest {

    @Mock
    private IssuerProperties appConfig;
    @Mock
    private PreAuthorizedCodeService preAuthorizedCodeService;
    @Mock
    private TransientStore<String> issuerStateCacheStore;
    @Mock
    private CredentialOfferCacheRepository credentialOfferCacheRepository;
    @Mock
    private EmailService emailService;
    @Mock
    private IssuanceService issuanceService;

    @InjectMocks
    private CredentialOfferServiceImpl credentialOfferService;

    @Test
    void createAndDeliverCredentialOffer_withPreAuthorizedCodeAndUiDelivery_shouldReturnUri() {
        String issuanceId = "test-issuance-id";
        String configId = "learcredential.employee.w3c.4";

        when(appConfig.getIssuerBackendUrl()).thenReturn("https://example.com");
        when(preAuthorizedCodeService.issuePreAuthorizedCode(anyString(), any()))
                .thenReturn(Mono.just(PreAuthorizedCodeResponse.builder()
                        .preAuthorizedCode("pre-auth-code-123")
                        .txCode(TxCode.builder().length(6).inputMode("numeric").build())
                        .pin("1234")
                        .build()));
        when(credentialOfferCacheRepository.saveCredentialOffer(any()))
                .thenReturn(Mono.just("cache-nonce"));

        StepVerifier.create(credentialOfferService.createAndDeliverCredentialOffer(
                        issuanceId, configId, "pre-authorized_code", "test@example.com", "ui", "refresh-token"))
                .assertNext(result -> {
                    assertThat(result.credentialOfferUri()).startsWith("openid-credential-offer://");
                    assertThat(result.credentialOfferUri()).contains("credential_offer_uri=");
                })
                .verifyComplete();
    }

    @Test
    void createAndDeliverCredentialOffer_withAuthorizationCodeAndUiDelivery_shouldReturnUri() {
        String issuanceId = "test-issuance-id";
        String configId = "learcredential.employee.w3c.4";

        when(appConfig.getIssuerBackendUrl()).thenReturn("https://example.com");
        when(issuerStateCacheStore.add(anyString(), eq(issuanceId)))
                .thenReturn(Mono.just("cached"));
        when(credentialOfferCacheRepository.saveCredentialOffer(any()))
                .thenReturn(Mono.just("cache-nonce"));

        StepVerifier.create(credentialOfferService.createAndDeliverCredentialOffer(
                        issuanceId, configId, "authorization_code", "test@example.com", "ui", "refresh-token"))
                .assertNext(result -> {
                    assertThat(result.credentialOfferUri()).startsWith("openid-credential-offer://");
                    assertThat(result.credentialOfferUri()).contains("credential_offer_uri=");
                })
                .verifyComplete();
    }

    @Test
    void createAndDeliverCredentialOffer_withAuthorizationCodeAndEmailDelivery_shouldReturnUriWithoutSendingEmail() {
        String issuanceId = "test-issuance-id";
        String configId = "learcredential.employee.w3c.4";

        when(appConfig.getIssuerBackendUrl()).thenReturn("https://example.com");
        when(issuerStateCacheStore.add(anyString(), eq(issuanceId)))
                .thenReturn(Mono.just("cached"));
        when(credentialOfferCacheRepository.saveCredentialOffer(any()))
                .thenReturn(Mono.just("cache-nonce"));

        StepVerifier.create(credentialOfferService.createAndDeliverCredentialOffer(
                        issuanceId, configId, "authorization_code", "test@example.com", "email", "refresh-token"))
                .assertNext(result -> {
                    assertThat(result.credentialOfferUri()).startsWith("openid-credential-offer://");
                    assertThat(result.credentialOfferUri()).contains("credential_offer_uri=");
                })
                .verifyComplete();
    }

    @Test
    void createAndDeliverCredentialOffer_withPreAuthorizedCodeAndEmailDelivery_shouldSendEmail() {
        String issuanceId = "test-issuance-id";
        String configId = "learcredential.employee.w3c.4";

        when(appConfig.getIssuerBackendUrl()).thenReturn("https://example.com");
        when(appConfig.getWalletFrontendUrl()).thenReturn("https://wallet.example.com");
        when(preAuthorizedCodeService.issuePreAuthorizedCode(anyString(), any()))
                .thenReturn(Mono.just(PreAuthorizedCodeResponse.builder()
                        .preAuthorizedCode("pre-auth-code-123")
                        .txCode(TxCode.builder().length(6).inputMode("numeric").build())
                        .pin("1234")
                        .build()));
        when(credentialOfferCacheRepository.saveCredentialOffer(any()))
                .thenReturn(Mono.just("cache-nonce"));
        when(issuanceService.findCredentialOfferEmailInfoByIssuanceId(issuanceId))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo("test@example.com", "TestOrg")));
        when(emailService.sendCredentialOfferEmail(
                anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), any()))
                .thenReturn(Mono.empty());

        StepVerifier.create(credentialOfferService.createAndDeliverCredentialOffer(
                        issuanceId, configId, "pre-authorized_code", "test@example.com", "email", "refresh-token"))
                .assertNext(result -> assertThat(result.credentialOfferUri()).isNull())
                .verifyComplete();
    }
}
