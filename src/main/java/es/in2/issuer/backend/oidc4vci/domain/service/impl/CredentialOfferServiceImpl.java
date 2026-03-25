package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.oidc4vci.domain.service.CredentialOfferService;
import es.in2.issuer.backend.oidc4vci.domain.service.PreAuthorizedCodeService;
import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.TX_CODE_SIZE;
import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.TX_INPUT_MODE;
import static es.in2.issuer.backend.shared.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.OID4VCI_CREDENTIAL_OFFER_PATH;
import static es.in2.issuer.backend.shared.domain.util.Utils.generateCustomNonce;
import static es.in2.issuer.backend.shared.infrastructure.util.HttpUtils.ensureUrlHasProtocol;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialOfferServiceImpl implements CredentialOfferService {

    private static final String GRANT_TYPE_PRE_AUTHORIZED_CODE = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

    private final IssuerProperties appConfig;
    private final PreAuthorizedCodeService preAuthorizedCodeService;
    private final TransientStore<String> issuerStateCacheStore;
    private final CredentialOfferCacheRepository credentialOfferCacheRepository;
    private final EmailService emailService;
    private final IssuanceService issuanceService;

    @Override
    @Observed(name = "oidc4vci.create-and-deliver-credential-offer", contextualName = "create-and-deliver-credential-offer")
    public Mono<CredentialOfferResult> createAndDeliverCredentialOffer(
            String issuanceId, String credentialConfigurationId, String grantType,
            String email, String delivery, String credentialOfferRefreshToken) {

        return Mono.deferContextual(ctx -> {
            String baseUrl = ctx.getOrDefault(ISSUER_BASE_URL_CONTEXT_KEY, appConfig.getIssuerBackendUrl());

            return generateGrant(issuanceId, grantType)
                    .flatMap(grantResult -> {
                        CredentialOffer offer = CredentialOffer.builder()
                                .credentialIssuer(baseUrl)
                                .credentialConfigurationIds(List.of(credentialConfigurationId))
                                .grants(grantResult.grants)
                                .build();

                        CredentialOfferData data = CredentialOfferData.builder()
                                .credentialOffer(offer)
                                .credentialEmail(email)
                                .txCode(grantResult.txCode)
                                .build();

                        return credentialOfferCacheRepository.saveCredentialOffer(issuanceId, data);
                    })
                    .flatMap(nonce -> buildCredentialOfferUri(baseUrl, nonce)
                            .flatMap(uri -> deliverOffer(baseUrl, uri, issuanceId, credentialOfferRefreshToken, delivery)));
        });
    }

    private Mono<CredentialOfferResult> deliverOffer(String baseUrl, String credentialOfferUri, String issuanceId,
                                                      String credentialOfferRefreshToken, String delivery) {
        if (DELIVERY_UI.equals(delivery)) {
            log.info("Delivering credential offer via URI for issuance: {}", issuanceId);
            return Mono.just(CredentialOfferResult.builder()
                    .credentialOfferUri(credentialOfferUri)
                    .build());
        }

        log.info("Delivering credential offer via email for issuance: {}", issuanceId);
        return issuanceService.findCredentialOfferEmailInfoByIssuanceId(issuanceId)
                .flatMap(emailInfo -> {
                    String refreshUrl = buildRefreshUrl(baseUrl, credentialOfferRefreshToken);
                    return emailService.sendCredentialOfferEmail(
                                    emailInfo.email(),
                                    CREDENTIAL_ACTIVATION_EMAIL_SUBJECT,
                                    credentialOfferUri,
                                    refreshUrl,
                                    appConfig.getWalletFrontendUrl(),
                                    emailInfo.organization(),
                                    null
                            )
                            .doOnSuccess(_ -> log.info("Credential offer email sent for issuanceId={}", issuanceId))
                            .onErrorMap(_ -> new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE))
                            .thenReturn(CredentialOfferResult.builder().build());
                });
    }

    private String buildRefreshUrl(String baseUrl, String credentialOfferRefreshToken) {
        return UriComponentsBuilder
                .fromUriString(baseUrl)
                .path("/credential-offer/refresh/" + credentialOfferRefreshToken)
                .build()
                .toUriString();
    }

    private record GrantResult(CredentialOfferGrants grants, String txCode) {}

    private Mono<GrantResult> generateGrant(String issuanceId, String grantType) {
        if (GRANT_TYPE_PRE_AUTHORIZED_CODE.equals(grantType)) {
            return generatePreAuthorizedCodeGrant(issuanceId);
        }
        return generateAuthorizationCodeGrant(issuanceId);
    }

    private Mono<GrantResult> generatePreAuthorizedCodeGrant(String issuanceId) {
        return preAuthorizedCodeService.issuePreAuthorizedCode("issuance", Mono.just(issuanceId))
                .map(preAuthResponse -> {
                    PreAuthorizedCodeGrant preAuthGrant = PreAuthorizedCodeGrant.builder()
                            .preAuthorizedCode(preAuthResponse.preAuthorizedCode())
                            .txCode(TxCode.builder()
                                    .length(TX_CODE_SIZE)
                                    .inputMode(TX_INPUT_MODE)
                                    .description("Enter the activation code")
                                    .build())
                            .build();

                    CredentialOfferGrants grants = CredentialOfferGrants.builder()
                            .preAuthorizedCode(preAuthGrant)
                            .build();

                    return new GrantResult(grants, preAuthResponse.txCodeValue());
                });
    }

    private Mono<GrantResult> generateAuthorizationCodeGrant(String issuanceId) {
        return generateCustomNonce()
                .flatMap(issuerState -> issuerStateCacheStore.add(issuerState, issuanceId)
                        .thenReturn(issuerState))
                .map(issuerState -> {
                    AuthorizationCodeGrant authCodeGrant = AuthorizationCodeGrant.builder()
                            .issuerState(issuerState)
                            .build();

                    CredentialOfferGrants grants = CredentialOfferGrants.builder()
                            .authorizationCode(authCodeGrant)
                            .build();

                    return new GrantResult(grants, null);
                });
    }

    private Mono<String> buildCredentialOfferUri(String baseUrl, String nonce) {
        String url = ensureUrlHasProtocol(baseUrl + OID4VCI_CREDENTIAL_OFFER_PATH + "/" + nonce);
        String encodedUrl = URLEncoder.encode(url, StandardCharsets.UTF_8);
        return Mono.just("openid-credential-offer://?credential_offer_uri=" + encodedUrl);
    }
}
