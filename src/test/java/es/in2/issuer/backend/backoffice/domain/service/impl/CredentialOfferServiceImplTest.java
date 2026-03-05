package es.in2.issuer.backend.backoffice.domain.service.impl;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferGrants;
import es.in2.issuer.backend.shared.domain.model.dto.PreAuthorizedCodeGrant;
import es.in2.issuer.backend.shared.domain.model.dto.TxCode;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialOfferServiceImplTest {

    @Mock
    private AppConfig appConfig;

    @InjectMocks
    private CredentialOfferServiceImpl credentialOfferService;

    @BeforeEach
    void setUp() {
        when(appConfig.getIssuerBackendUrl()).thenReturn("https://example.com");
    }

    @Test
    void testBuildCredentialOffer() {
        String credentialType = "type1";
        String preAuthCode = "code123";
        String email = "example@example.com";
        String pin = "1234";
        CredentialOfferGrants grants = CredentialOfferGrants.builder()
                .preAuthorizedCode(PreAuthorizedCodeGrant.builder()
                        .preAuthorizedCode(preAuthCode)
                        .txCode(TxCode.builder().length(4).build())
                        .build())
                .build();

        StepVerifier.create(credentialOfferService.buildCredentialOffer(credentialType, grants, email, pin))
                .expectNextMatches(offer ->
                        offer.credentialOffer().credentialIssuer().equals("https://example.com") &&
                                offer.credentialOffer().credentialConfigurationIds().equals(List.of(credentialType)) &&
                                offer.credentialOffer().grants().preAuthorizedCode().preAuthorizedCode().equals(preAuthCode) &&
                                offer.credentialOffer().grants().preAuthorizedCode().txCode().length() == 4 &&
                                offer.credentialEmail().equals(email) &&
                                offer.pin().equals(pin)
                )
                .verifyComplete();
    }

    @Test
    void testCreateCredentialOfferUriResponse() {
        String nonce = "abc123";
        Mono<String> result = credentialOfferService.createCredentialOfferUriResponse(nonce);
        StepVerifier.create(result)
                .expectNext("openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fexample.com%2Foid4vci%2Fv1%2Fcredential-offer%2Fabc123")
                .verifyComplete();
    }

}
