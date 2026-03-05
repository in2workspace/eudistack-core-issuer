package es.in2.issuer.backend.shared.domain.model.dto;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CredentialOfferTest {

    @Test
    void testConstructorAndGetters() {
        String expectedCredentialIssuer = "https://credential-issuer.example.com";
        TxCode txCode = new TxCode(4, "numeric", "description");
        CredentialOfferGrants expectedGrants = new CredentialOfferGrants(
                new AuthorizationCodeGrant("issuer-state-1"),
                new PreAuthorizedCodeGrant("pre-auth-code-1", txCode)
        );
        List<String> expectedCredentialConfigurationIds = List.of("id1", "id2");

        CredentialOffer credentialOffer = new CredentialOffer(
                expectedCredentialIssuer,
                expectedCredentialConfigurationIds,
                expectedGrants
        );

        assertEquals(expectedCredentialIssuer, credentialOffer.credentialIssuer());
        assertEquals(expectedGrants, credentialOffer.grants());
        assertEquals(expectedCredentialConfigurationIds, credentialOffer.credentialConfigurationIds());
    }

    @Test
    void testBuilder() {
        String newCredentialIssuer = "https://new-credential-issuer.example.com";
        CredentialOfferGrants newGrants = CredentialOfferGrants.builder().build();

        CredentialOffer credentialOffer = CredentialOffer.builder()
                .credentialIssuer(newCredentialIssuer)
                .grants(newGrants)
                .build();

        assertEquals(newCredentialIssuer, credentialOffer.credentialIssuer());
        assertEquals(newGrants, credentialOffer.grants());
    }

    @Test
    void lombokGeneratedMethodsTest() {
        String expectedCredentialIssuer = "https://credential-issuer.example.com";
        TxCode txCode = new TxCode(4, "numeric", "description");
        CredentialOfferGrants expectedGrants = new CredentialOfferGrants(
                new AuthorizationCodeGrant("issuer-state-1"),
                new PreAuthorizedCodeGrant("pre-auth-code-1", txCode)
        );
        List<String> expectedCredentialConfigurationIds = List.of("id1", "id2");

        CredentialOffer offer1 = new CredentialOffer(
                expectedCredentialIssuer,
                expectedCredentialConfigurationIds,
                expectedGrants
        );
        CredentialOffer offer2 = new CredentialOffer(
                expectedCredentialIssuer,
                expectedCredentialConfigurationIds,
                expectedGrants
        );

        assertEquals(offer1, offer2);
        assertEquals(offer1.hashCode(), offer2.hashCode());
    }
}
