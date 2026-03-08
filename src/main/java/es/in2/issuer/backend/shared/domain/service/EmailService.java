package es.in2.issuer.backend.shared.domain.service;

import reactor.core.publisher.Mono;

public interface EmailService {
    Mono<Void> sendTxCodeNotification(String to, String subject, String pin);
    Mono<Void> sendCredentialActivationEmail(String to, String subject, String link, String knowledgebaseWalletUrl, String organization);
    Mono<Void> sendCredentialOfferEmail(String to, String subject, String credentialOfferUri, String reissueUrl, String walletUrl, String organization, String txCode);
    Mono<Void> sendPendingCredentialNotification(String to, String subject);
    Mono<Void> sendCredentialSignedNotification(String to, String subject, String additionalInfo);
    Mono<Void> sendResponseUriFailed(String to, String productId, String guideUrl);
    Mono<Void> sendResponseUriAcceptedWithHtml(String to, String productId, String htmlContent);
    Mono<Void> sendPendingSignatureCredentialNotification(String to, String subject, String id, String domain);
    Mono<Void> sendCredentialStatusChangeNotification(String to, String organization, String credentialId, String type, String status);
}
