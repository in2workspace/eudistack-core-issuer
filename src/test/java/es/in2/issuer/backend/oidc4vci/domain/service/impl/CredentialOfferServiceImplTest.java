package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.backoffice.domain.service.impl.CredentialOfferServiceImpl;
import es.in2.issuer.backend.shared.domain.model.dto.Grants;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.test.StepVerifier;

import static es.in2.issuer.backend.shared.domain.util.Constants.AUTHORIZATION_CODE;
import static es.in2.issuer.backend.shared.domain.util.Constants.GRANT_TYPE;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialOfferServiceImplTest {

    @Mock
    private AppConfig appConfig;

    @InjectMocks
    private CredentialOfferServiceImpl credentialOfferService;

    @Test
    void buildAuthorizationCodeCredentialOffer_shouldBuildCorrectOffer() {
        when(appConfig.getIssuerBackendUrl()).thenReturn("https://issuer.example.com");

        StepVerifier.create(credentialOfferService.buildAuthorizationCodeCredentialOffer(
                        "LEARCredentialEmployee", "issuer-state-123", "user@example.com"))
                .assertNext(offerData -> {
                    assertNotNull(offerData.credentialOffer());
                    assertEquals("https://issuer.example.com", offerData.credentialOffer().credentialIssuer());
                    assertEquals(1, offerData.credentialOffer().credentialConfigurationIds().size());
                    assertEquals("LEARCredentialEmployee", offerData.credentialOffer().credentialConfigurationIds().getFirst());
                    assertTrue(offerData.credentialOffer().grants().containsKey(AUTHORIZATION_CODE));
                    Grants grants = offerData.credentialOffer().grants().get(AUTHORIZATION_CODE);
                    assertEquals("issuer-state-123", grants.issuerState());
                    assertEquals("user@example.com", offerData.credentialEmail());
                    assertNull(offerData.pin());
                })
                .verifyComplete();
    }

    @Test
    void buildCustomCredentialOffer_shouldBuildCorrectOffer() {
        when(appConfig.getIssuerBackendUrl()).thenReturn("https://issuer.example.com");

        Grants grants = Grants.builder()
                .preAuthorizedCode("pre-auth-123")
                .txCode(Grants.TxCode.builder().length(4).inputMode("numeric").build())
                .build();

        StepVerifier.create(credentialOfferService.buildCustomCredentialOffer(
                        "LEARCredentialEmployee", grants, "user@example.com", "1234"))
                .assertNext(offerData -> {
                    assertNotNull(offerData.credentialOffer());
                    assertTrue(offerData.credentialOffer().grants().containsKey(GRANT_TYPE));
                    assertEquals("1234", offerData.pin());
                    assertEquals("user@example.com", offerData.credentialEmail());
                })
                .verifyComplete();
    }

    @Test
    void createCredentialOfferUriResponse_shouldBuildCorrectUri() {
        when(appConfig.getIssuerBackendUrl()).thenReturn("https://issuer.example.com");

        StepVerifier.create(credentialOfferService.createCredentialOfferUriResponse("nonce-abc"))
                .assertNext(uri -> {
                    assertTrue(uri.startsWith("openid-credential-offer://?credential_offer_uri="));
                    assertTrue(uri.contains("nonce-abc"));
                })
                .verifyComplete();
    }
}
