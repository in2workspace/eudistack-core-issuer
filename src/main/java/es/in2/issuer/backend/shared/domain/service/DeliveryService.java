package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferEmailNotificationInfo;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceResponse;
import reactor.core.publisher.Mono;

public interface DeliveryService {

    Mono<IssuanceResponse> deliver(
            String delivery,
            String credentialOfferUri,
            String refreshToken,
            CredentialOfferEmailNotificationInfo emailInfo
    );

}
