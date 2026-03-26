package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import es.in2.issuer.backend.oidc4vci.application.workflow.CredentialOfferWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOffer;
import es.in2.issuer.backend.oidc4vci.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialOfferWorkflowImpl implements CredentialOfferWorkflow {

    private final CredentialOfferCacheRepository credentialOfferCacheRepository;
    private final EmailService emailService;

    @Override
    public Mono<CredentialOffer> findCredentialOfferById(String processId, String id) {
        return credentialOfferCacheRepository.consumeCredentialOffer(id)
                .flatMap(credentialOfferData -> {
                    if (credentialOfferData.txCode() != null) {
                        return emailService
                            .sendTxCodeNotification(
                                credentialOfferData.credentialEmail(),
                                "email.tx-code",
                                credentialOfferData.txCode())
                            .then(Mono.just(credentialOfferData.credentialOffer()));
                    }
                    return Mono.just(credentialOfferData.credentialOffer());
                });
    }

}
