package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.oidc4vci.domain.service.PreAuthorizedCodeService;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferEmailNotificationInfo;
import es.in2.issuer.backend.shared.domain.model.dto.PreAuthorizedCodeResponse;
import es.in2.issuer.backend.shared.domain.model.dto.TxCode;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.OID4VCI_CREDENTIAL_OFFER_PATH;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialOfferServiceImplTest {

    private static final String ISSUER_BASE_URL = "https://example.com";
    private static final String NONCE = "cache-nonce";
    private static final String WALLET_URL_KEY = "issuer.wallet_url";
    /** The https offer URL, encoded once, as it travels after {@code credential_offer_uri=}. */
    private static final String ENCODED_OFFER_URL = URLEncoder.encode(
            ISSUER_BASE_URL + OID4VCI_CREDENTIAL_OFFER_PATH + "/" + NONCE, StandardCharsets.UTF_8);
    private static final String STANDARD_OFFER_URI =
            "openid-credential-offer://?credential_offer_uri=" + ENCODED_OFFER_URL;

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
    @Mock
    private TenantConfigService tenantConfigService;

    @InjectMocks
    private CredentialOfferServiceImpl credentialOfferService;

    // ── ui: the standard OID4VCI form, unconverted (EUD-305) ─────────────────

    @Test
    void createAndDeliverCredentialOffer_withPreAuthorizedCodeAndUiDelivery_returnsStandardOfferUri() {
        stubPreAuthorizedCodeGrant();
        stubOfferCache();

        StepVerifier.create(credentialOfferService.createAndDeliverCredentialOffer(
                        "test-issuance-id", "learcredential.employee.w3c.4",
                        "urn:ietf:params:oauth:grant-type:pre-authorized_code", "test@example.com", "ui",
                        "refresh-token", ISSUER_BASE_URL))
                .assertNext(result -> assertThat(result.credentialOfferUri()).isEqualTo(STANDARD_OFFER_URI))
                .verifyComplete();

        verifyNoInteractions(emailService, tenantConfigService);
    }

    @Test
    void createAndDeliverCredentialOffer_withAuthorizationCodeAndUiDelivery_returnsStandardOfferUri() {
        when(issuerStateCacheStore.add(anyString(), eq("test-issuance-id")))
                .thenReturn(Mono.just("cached"));
        stubOfferCache();

        StepVerifier.create(credentialOfferService.createAndDeliverCredentialOffer(
                        "test-issuance-id", "learcredential.employee.w3c.4", "authorization_code",
                        "test@example.com", "ui", "refresh-token", ISSUER_BASE_URL))
                .assertNext(result -> assertThat(result.credentialOfferUri()).isEqualTo(STANDARD_OFFER_URI))
                .verifyComplete();
    }

    @Test
    void createAndDeliverCredentialOffer_uiIgnoresTheTenantWalletUrl() {
        stubPreAuthorizedCodeGrant();
        stubOfferCache();
        stubEmailInfo("test-issuance-id");
        stubFrontendUrl();
        when(tenantConfigService.getString(WALLET_URL_KEY))
                .thenReturn(Mono.just("https://wallet.example.com/wallet"));
        when(emailService.sendCredentialOfferEmail(anyString(), anyString(), anyString(), anyString(), isNull()))
                .thenReturn(Mono.empty());

        StepVerifier.create(credentialOfferService.createAndDeliverCredentialOffer(
                        "test-issuance-id", "learcredential.employee.w3c.4",
                        "urn:ietf:params:oauth:grant-type:pre-authorized_code", "test@example.com", "email,ui",
                        "refresh-token", ISSUER_BASE_URL))
                .assertNext(result -> assertThat(result.credentialOfferUri()).isEqualTo(STANDARD_OFFER_URI))
                .verifyComplete();

        verify(emailService).sendCredentialOfferEmail(eq("test@example.com"),
                eq("https://wallet.example.com/wallet/protocol/callback?credential_offer_uri=" + ENCODED_OFFER_URL),
                anyString(), eq("TestOrg"), isNull());
    }

    // ── email: link to the tenant's wallet, or the standard form ─────────────

    @Test
    void createAndDeliverCredentialOffer_emailWithTenantWalletUrl_linksToTheWalletCallback() {
        stubPreAuthorizedCodeGrant();
        stubOfferCache();
        stubEmailInfo("test-issuance-id");
        stubFrontendUrl();
        when(tenantConfigService.getString(WALLET_URL_KEY))
                .thenReturn(Mono.just("https://wallet.example.com/wallet"));
        when(emailService.sendCredentialOfferEmail(anyString(), anyString(), anyString(), anyString(), isNull()))
                .thenReturn(Mono.empty());

        StepVerifier.create(credentialOfferService.createAndDeliverCredentialOffer(
                        "test-issuance-id", "learcredential.employee.w3c.4",
                        "urn:ietf:params:oauth:grant-type:pre-authorized_code", "test@example.com", "email",
                        "refresh-token", ISSUER_BASE_URL))
                .assertNext(result -> {
                    assertThat(result.credentialOfferUri()).isNull();
                    assertThat(result.emailError()).isNull();
                })
                .verifyComplete();

        verify(emailService).sendCredentialOfferEmail(eq("test@example.com"),
                eq("https://wallet.example.com/wallet/protocol/callback?credential_offer_uri=" + ENCODED_OFFER_URL),
                eq("https://frontend.example.com/issuer/credential-offer-refresh/refresh-token"),
                eq("TestOrg"), isNull());
    }

    @Test
    void createAndDeliverCredentialOffer_emailWithTrailingSlashWalletUrl_doesNotDoubleTheSlash() {
        stubPreAuthorizedCodeGrant();
        stubOfferCache();
        stubEmailInfo("test-issuance-id");
        stubFrontendUrl();
        when(tenantConfigService.getString(WALLET_URL_KEY))
                .thenReturn(Mono.just("https://wallet.example.com/wallet/"));
        when(emailService.sendCredentialOfferEmail(anyString(), anyString(), anyString(), anyString(), isNull()))
                .thenReturn(Mono.empty());

        StepVerifier.create(credentialOfferService.createAndDeliverCredentialOffer(
                        "test-issuance-id", "learcredential.employee.w3c.4",
                        "urn:ietf:params:oauth:grant-type:pre-authorized_code", "test@example.com", "email",
                        "refresh-token", ISSUER_BASE_URL))
                .expectNextCount(1)
                .verifyComplete();

        verify(emailService).sendCredentialOfferEmail(anyString(),
                eq("https://wallet.example.com/wallet/protocol/callback?credential_offer_uri=" + ENCODED_OFFER_URL),
                anyString(), anyString(), isNull());
    }

    @Test
    void createAndDeliverCredentialOffer_emailWithoutTenantWalletUrl_sendsTheStandardOfferUri() {
        stubPreAuthorizedCodeGrant();
        stubOfferCache();
        stubEmailInfo("test-issuance-id");
        stubFrontendUrl();
        when(tenantConfigService.getString(WALLET_URL_KEY)).thenReturn(Mono.empty());
        when(emailService.sendCredentialOfferEmail(anyString(), anyString(), anyString(), anyString(), isNull()))
                .thenReturn(Mono.empty());

        StepVerifier.create(credentialOfferService.createAndDeliverCredentialOffer(
                        "test-issuance-id", "learcredential.employee.w3c.4",
                        "urn:ietf:params:oauth:grant-type:pre-authorized_code", "test@example.com", "email",
                        "refresh-token", ISSUER_BASE_URL))
                .assertNext(result -> {
                    assertThat(result.credentialOfferUri()).isNull();
                    assertThat(result.emailError()).isNull();
                })
                .verifyComplete();

        verify(emailService).sendCredentialOfferEmail(eq("test@example.com"),
                eq(STANDARD_OFFER_URI), anyString(), eq("TestOrg"), isNull());
    }

    @Test
    void createAndDeliverCredentialOffer_emailWithBlankTenantWalletUrl_sendsTheStandardOfferUri() {
        when(issuerStateCacheStore.add(anyString(), eq("test-issuance-id")))
                .thenReturn(Mono.just("cached"));
        stubOfferCache();
        stubEmailInfo("test-issuance-id");
        stubFrontendUrl();
        when(tenantConfigService.getString(WALLET_URL_KEY)).thenReturn(Mono.just("  "));
        when(emailService.sendCredentialOfferEmail(anyString(), anyString(), anyString(), anyString(), isNull()))
                .thenReturn(Mono.empty());

        StepVerifier.create(credentialOfferService.createAndDeliverCredentialOffer(
                        "test-issuance-id", "learcredential.employee.w3c.4", "authorization_code",
                        "test@example.com", "email", "refresh-token", ISSUER_BASE_URL))
                .assertNext(result -> assertThat(result.credentialOfferUri()).isNull())
                .verifyComplete();

        verify(emailService).sendCredentialOfferEmail(eq("test@example.com"),
                eq(STANDARD_OFFER_URI), anyString(), eq("TestOrg"), isNull());
    }

    /**
     * Code-review F3b. The onErrorMap that turns any email-leg failure into the safe
     * EmailCommunicationException constant used to wrap only the send step; a failure in the
     * repository lookup that precedes it (findCredentialOfferEmailInfoByIssuanceId) reached
     * describeEmailFailure raw. An R2DBC failure names table/column/schema, and the schema name is
     * the tenant.
     */
    @Test
    void createAndDeliverCredentialOffer_whenEmailInfoLookupFails_reportsTheSafeConstantNotTheRawMessage() {
        String issuanceId = "test-issuance-id";

        when(issuerStateCacheStore.add(anyString(), eq(issuanceId)))
                .thenReturn(Mono.just("cached"));
        stubOfferCache();
        when(issuanceService.findCredentialOfferEmailInfoByIssuanceId(issuanceId))
                .thenReturn(Mono.error(new RuntimeException(
                        "relation \"tenant_acme.issuance\" violates foreign key constraint")));

        StepVerifier.create(credentialOfferService.createAndDeliverCredentialOffer(
                        issuanceId, "learcredential.employee.w3c.4", "authorization_code", "test@example.com",
                        "email", "refresh-token", ISSUER_BASE_URL))
                .assertNext(result -> {
                    assertThat(result.emailError()).isEqualTo("Error during communication with the mail server");
                    assertThat(result.emailError()).doesNotContain("tenant_acme");
                })
                .verifyComplete();

        verifyNoInteractions(emailService);
    }

    @Test
    void createAndDeliverCredentialOffer_withKpmgTenantAndEmailDelivery_callsSendBrandedEmail() {
        when(tenantConfigService.getStringOrThrow("issuer.frontend_url"))
                .thenReturn(Mono.just("https://kpmg.eudistack.net/issuer"));
        when(tenantConfigService.getString(WALLET_URL_KEY))
                .thenReturn(Mono.just("https://kpmg.eudistack.net/wallet"));
        stubPreAuthorizedCodeGrant();
        when(credentialOfferCacheRepository.saveCredentialOffer(any()))
                .thenReturn(Mono.just("nonce"));
        when(issuanceService.findCredentialOfferEmailInfoByIssuanceId("issuance-kpmg"))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo("user@kpmg.com", "KPMG")));
        when(emailService.sendBrandedCredentialOfferEmail(anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        StepVerifier.create(credentialOfferService.createAndDeliverCredentialOffer(
                        "issuance-kpmg", "learcredential.employee.sd.1",
                        "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                        "user@kpmg.com", "email", "refresh-token", "https://kpmg.eudistack.net/issuer")
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "kpmg")))
                .assertNext(result -> assertThat(result.credentialOfferUri()).isNull())
                .verifyComplete();

        verify(emailService).sendBrandedCredentialOfferEmail(
                eq("user@kpmg.com"), anyString(),
                argThat(url -> url.startsWith("https://kpmg.eudistack.net/wallet/protocol/callback?credential_offer_uri=")),
                anyString(), eq("KPMG"));
        verify(emailService, never()).sendCredentialOfferEmail(any(), any(), any(), any(), any());
    }

    @Test
    void createAndDeliverCredentialOffer_withNonKpmgTenantAndEmailDelivery_callsSendLegacyEmail() {
        when(tenantConfigService.getStringOrThrow("issuer.frontend_url"))
                .thenReturn(Mono.just("https://sandbox.eudistack.net/issuer"));
        when(tenantConfigService.getString(WALLET_URL_KEY))
                .thenReturn(Mono.just("https://sandbox.eudistack.net/wallet"));
        stubPreAuthorizedCodeGrant();
        when(credentialOfferCacheRepository.saveCredentialOffer(any()))
                .thenReturn(Mono.just("nonce"));
        when(issuanceService.findCredentialOfferEmailInfoByIssuanceId("issuance-sandbox"))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo("user@sandbox.com", "Sandbox Org")));
        when(emailService.sendCredentialOfferEmail(any(), any(), any(), any(), isNull()))
                .thenReturn(Mono.empty());

        StepVerifier.create(credentialOfferService.createAndDeliverCredentialOffer(
                        "issuance-sandbox", "learcredential.employee.sd.1",
                        "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                        "user@sandbox.com", "email", "refresh-token", "https://sandbox.eudistack.net/issuer")
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "sandbox")))
                .assertNext(result -> assertThat(result.credentialOfferUri()).isNull())
                .verifyComplete();

        verify(emailService).sendCredentialOfferEmail(
                eq("user@sandbox.com"),
                argThat(url -> url.startsWith("https://sandbox.eudistack.net/wallet/protocol/callback?credential_offer_uri=")),
                any(), eq("Sandbox Org"), isNull());
        verify(emailService, never()).sendBrandedCredentialOfferEmail(anyString(), anyString(), anyString(), anyString(), anyString());
    }

    private void stubPreAuthorizedCodeGrant() {
        when(preAuthorizedCodeService.issuePreAuthorizedCode(anyString(), any()))
                .thenReturn(Mono.just(PreAuthorizedCodeResponse.builder()
                        .preAuthorizedCode("pre-auth-code-123")
                        .txCode(TxCode.builder().length(6).inputMode("numeric").build())
                        .txCodeValue("1234")
                        .build()));
    }

    private void stubOfferCache() {
        when(credentialOfferCacheRepository.saveCredentialOffer(any()))
                .thenReturn(Mono.just(NONCE));
    }

    private void stubEmailInfo(String issuanceId) {
        when(issuanceService.findCredentialOfferEmailInfoByIssuanceId(issuanceId))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo("test@example.com", "TestOrg")));
    }

    private void stubFrontendUrl() {
        when(tenantConfigService.getStringOrThrow("issuer.frontend_url"))
                .thenReturn(Mono.just("https://frontend.example.com/issuer"));
    }
}
