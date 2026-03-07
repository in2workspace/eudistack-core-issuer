package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.issuance.domain.service.impl.CredentialOfferServiceImpl;
import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationCodeGrant;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferGrants;
import es.in2.issuer.backend.shared.domain.model.dto.PreAuthorizedCodeGrant;
import es.in2.issuer.backend.shared.domain.model.dto.TxCode;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialOfferServiceImplTest {

    @Mock
    private IssuerProperties appConfig;

    @InjectMocks
    private CredentialOfferServiceImpl credentialOfferService;

    @Test
    void buildCredentialOffer_withAuthorizationCodeGrant_shouldBuildCorrectOffer() {
        when(appConfig.getIssuerBackendUrl()).thenReturn("https://issuer.example.com");

        CredentialOfferGrants grants = CredentialOfferGrants.builder()
                .authorizationCode(AuthorizationCodeGrant.builder()
                        .issuerState("issuer-state-123")
                        .build())
                .build();

        StepVerifier.create(credentialOfferService.buildCredentialOffer(
                        "LEARCredentialEmployee", grants, "user@example.com", null))
                .assertNext(offerData -> {
                    assertNotNull(offerData.credentialOffer());
                    assertEquals("https://issuer.example.com", offerData.credentialOffer().credentialIssuer());
                    assertEquals(1, offerData.credentialOffer().credentialConfigurationIds().size());
                    assertEquals("LEARCredentialEmployee", offerData.credentialOffer().credentialConfigurationIds().getFirst());
                    assertNotNull(offerData.credentialOffer().grants().authorizationCode());
                    assertEquals("issuer-state-123", offerData.credentialOffer().grants().authorizationCode().issuerState());
                    assertEquals("user@example.com", offerData.credentialEmail());
                    assertNull(offerData.pin());
                })
                .verifyComplete();
    }

    @Test
    void buildCredentialOffer_withPreAuthorizedCodeGrant_shouldBuildCorrectOffer() {
        when(appConfig.getIssuerBackendUrl()).thenReturn("https://issuer.example.com");

        CredentialOfferGrants grants = CredentialOfferGrants.builder()
                .preAuthorizedCode(PreAuthorizedCodeGrant.builder()
                        .preAuthorizedCode("pre-auth-123")
                        .txCode(TxCode.builder().length(4).inputMode("numeric").build())
                        .build())
                .build();

        StepVerifier.create(credentialOfferService.buildCredentialOffer(
                        "LEARCredentialEmployee", grants, "user@example.com", "1234"))
                .assertNext(offerData -> {
                    assertNotNull(offerData.credentialOffer());
                    assertNotNull(offerData.credentialOffer().grants().preAuthorizedCode());
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
