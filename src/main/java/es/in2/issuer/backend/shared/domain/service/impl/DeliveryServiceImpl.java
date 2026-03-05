package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferEmailNotificationInfo;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.shared.domain.service.DeliveryService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class DeliveryServiceImpl implements DeliveryService {

    private final EmailService emailService;
    private final AppConfig appConfig;

    @Override
    @Observed(name = "issuance.delivery", contextualName = "deliver-credential-offer")
    public Mono<IssuanceResponse> deliver(
            String delivery,
            String credentialOfferUri,
            String refreshToken,
            CredentialOfferEmailNotificationInfo emailInfo) {

        if (DELIVERY_UI.equals(delivery)) {
            log.info("Delivering credential offer via UI");
            return Mono.just(IssuanceResponse.builder()
                    .credentialOfferUri(credentialOfferUri)
                    .build());
        }

        log.info("Delivering credential offer via email to: {}", emailInfo.email());
        String refreshUrl = buildRefreshUrl(refreshToken);

        return emailService.sendCredentialOfferEmail(
                        emailInfo.email(),
                        CREDENTIAL_ACTIVATION_EMAIL_SUBJECT,
                        credentialOfferUri,
                        refreshUrl,
                        appConfig.getWalletFrontendUrl(),
                        emailInfo.organization()
                )
                .onErrorMap(ex -> new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE))
                .thenReturn(IssuanceResponse.builder().build());
    }

    private String buildRefreshUrl(String refreshToken) {
        return UriComponentsBuilder
                .fromUriString(appConfig.getIssuerBackendUrl())
                .path("/credential-offer/refresh/" + refreshToken)
                .build()
                .toUriString();
    }

}
