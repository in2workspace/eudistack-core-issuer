package es.in2.issuer.backend.oidc4vci.domain.model;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class AuthorizationServerMetadataTest {

    @Test
    void testBuilderAndGetters() {
        String issuer = "https://issuer.example.com";
        String tokenEndpoint = "https://issuer.example.com/oauth/token";
        Set<String> responseSupportedTypes = Set.of("token");

        AuthorizationServerMetadata metadata = AuthorizationServerMetadata.builder()
                .issuer(issuer)
                .tokenEndpoint(tokenEndpoint)
                .responseTypesSupported(responseSupportedTypes)
                .preAuthorizedGrantAnonymousAccessSupported(true)
                .build();

        assertEquals(issuer, metadata.issuer());
        assertEquals(tokenEndpoint, metadata.tokenEndpoint());
        assertEquals(responseSupportedTypes, metadata.responseTypesSupported());
        assertTrue(metadata.preAuthorizedGrantAnonymousAccessSupported());
    }

    @Test
    void testBuilderWithAllFields() {
        AuthorizationServerMetadata metadata = AuthorizationServerMetadata.builder()
                .issuer("https://issuer.example.com")
                .tokenEndpoint("https://issuer.example.com/oauth/token")
                .responseTypesSupported(Set.of("code", "token"))
                .preAuthorizedGrantAnonymousAccessSupported(false)
                .authorizationEndpoint("https://issuer.example.com/oid4vci/v1/authorize")
                .pushedAuthorizationRequestEndpoint("https://issuer.example.com/oid4vci/v1/par")
                .nonceEndpoint("https://issuer.example.com/oid4vci/v1/nonce")
                .requirePushedAuthorizationRequests(true)
                .authorizationResponseIssParameterSupported(true)
                .build();

        assertEquals("https://issuer.example.com/oid4vci/v1/authorize", metadata.authorizationEndpoint());
        assertEquals("https://issuer.example.com/oid4vci/v1/par", metadata.pushedAuthorizationRequestEndpoint());
        assertEquals("https://issuer.example.com/oid4vci/v1/nonce", metadata.nonceEndpoint());
        assertTrue(metadata.requirePushedAuthorizationRequests());
        assertTrue(metadata.authorizationResponseIssParameterSupported());
    }
}
