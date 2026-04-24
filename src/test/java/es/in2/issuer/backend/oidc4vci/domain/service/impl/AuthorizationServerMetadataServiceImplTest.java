package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.model.port.Oid4vciProfilePort;
import es.in2.issuer.backend.oidc4vci.infrastructure.config.Oid4vciProfileProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.test.StepVerifier;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthorizationServerMetadataServiceImplTest {


    @Mock
    private Oid4vciProfilePort profileProperties;

    @InjectMocks
    private AuthorizationServerMetadataServiceImpl metadataService;

    @Test
    void buildMetadata_shouldIncludeOnlyPreAuthFields() {
        when(profileProperties.isAuthorizationCodeEnabled()).thenReturn(false);
        when(profileProperties.isPreAuthorizedCodeEnabled()).thenReturn(true);
        when(profileProperties.grantsSupported()).thenReturn(
                List.of("urn:ietf:params:oauth:grant-type:pre-authorized_code"));

        StepVerifier.create(metadataService.buildAuthorizationServerMetadata("test-process", "https://issuer.example.com"))
                .assertNext(metadata -> {
                    assertEquals("https://issuer.example.com", metadata.issuer());
                    assertNotNull(metadata.tokenEndpoint());
                    assertTrue(metadata.preAuthorizedGrantAnonymousAccessSupported());
                    assertNull(metadata.authorizationEndpoint());
                    assertNull(metadata.pushedAuthorizationRequestEndpoint());
                    assertNull(metadata.nonceEndpoint());
                    assertNull(metadata.codeChallengeMethodsSupported());
                    assertNull(metadata.dpopSigningAlgValuesSupported());
                })
                .verifyComplete();
    }

    @Test
    void buildMetadata_shouldIncludeHaipFieldsWhenFullyConfigured() {
        var authCodeProps = new Oid4vciProfileProperties.AuthorizationCodeProperties(
                true, true, List.of("S256"),
                true, List.of("ES256"),
                "attest_jwt_client_auth", true
        );

        when(profileProperties.isAuthorizationCodeEnabled()).thenReturn(true);
        when(profileProperties.isPreAuthorizedCodeEnabled()).thenReturn(false);
        when(profileProperties.grantsSupported()).thenReturn(List.of("authorization_code"));
        when(profileProperties.authorizationCode()).thenReturn(authCodeProps);

        StepVerifier.create(metadataService.buildAuthorizationServerMetadata("test-process", "https://issuer.example.com"))
                .assertNext(metadata -> {
                    assertNotNull(metadata.authorizationEndpoint());
                    assertNotNull(metadata.pushedAuthorizationRequestEndpoint());
                    assertTrue(metadata.requirePushedAuthorizationRequests());
                    assertEquals(List.of("S256"), metadata.codeChallengeMethodsSupported());
                    assertEquals(List.of("ES256"), metadata.dpopSigningAlgValuesSupported());
                    assertEquals(List.of("attest_jwt_client_auth"), metadata.tokenEndpointAuthMethodsSupported());
                    assertNotNull(metadata.nonceEndpoint());
                    assertTrue(metadata.authorizationResponseIssParameterSupported());
                    assertTrue(metadata.grantTypesSupported().contains("authorization_code"));
                })
                .verifyComplete();
    }

    @Test
    void buildMetadata_shouldIncludePlainAuthCodeFields() {
        var authCodeProps = new Oid4vciProfileProperties.AuthorizationCodeProperties(
                false, true, List.of("S256"),
                false, List.of("ES256"),
                "none", false
        );

        when(profileProperties.isAuthorizationCodeEnabled()).thenReturn(true);
        when(profileProperties.isPreAuthorizedCodeEnabled()).thenReturn(true);
        when(profileProperties.grantsSupported()).thenReturn(
                List.of("authorization_code", "urn:ietf:params:oauth:grant-type:pre-authorized_code"));
        when(profileProperties.authorizationCode()).thenReturn(authCodeProps);

        StepVerifier.create(metadataService.buildAuthorizationServerMetadata("test-process", "https://issuer.example.com"))
                .assertNext(metadata -> {
                    assertNotNull(metadata.authorizationEndpoint());
                    assertNull(metadata.pushedAuthorizationRequestEndpoint());
                    assertNull(metadata.requirePushedAuthorizationRequests());
                    assertEquals(List.of("S256"), metadata.codeChallengeMethodsSupported());
                    assertNull(metadata.dpopSigningAlgValuesSupported());
                    assertNull(metadata.nonceEndpoint());
                    assertEquals(List.of("none"), metadata.tokenEndpointAuthMethodsSupported());
                    assertTrue(metadata.preAuthorizedGrantAnonymousAccessSupported());
                    assertEquals(2, metadata.grantTypesSupported().size());
                })
                .verifyComplete();
    }
}
