package es.in2.issuer.backend.shared.domain.service;

import reactor.core.publisher.Mono;

public interface EmailService {
    Mono<Void> sendTxCodeNotification(String to, String subject, String txCode);
    Mono<Void> sendCredentialOfferEmail(String to, String subject, String credentialOfferUri, String reissueUrl, String walletUrl, String organization, String txCode);
    Mono<Void> sendBrandedCredentialOfferEmail(String to, String subject, String credentialOfferUri, String reissueUrl, String walletUrl, String organization);
    Mono<Void> sendCredentialStatusChangeNotification(String to, String credentialId, String type, String status);
    Mono<Void> sendCredentialFailureNotification(String to, String eventDescription);
}
