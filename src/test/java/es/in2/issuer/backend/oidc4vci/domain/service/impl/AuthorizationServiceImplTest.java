package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.model.AuthorizationCodeData;
import es.in2.issuer.backend.oidc4vci.domain.model.PushedAuthorizationRequest;
import es.in2.issuer.backend.oidc4vci.domain.model.port.Oid4vciProfilePort;
import es.in2.issuer.backend.oidc4vci.infrastructure.config.Oid4vciProfileProperties;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthorizationServiceImplTest {

    @Mock
    private TransientStore<PushedAuthorizationRequest> parCacheStore;

    @Mock
    private TransientStore<AuthorizationCodeData> authorizationCodeCacheStore;

    @Mock
    private Oid4vciProfilePort profileProperties;


    private AuthorizationServiceImpl authorizationService;

    @BeforeEach
    void setUp() {
        authorizationService = new AuthorizationServiceImpl(
                parCacheStore,
                authorizationCodeCacheStore,
                profileProperties
        );
    }

    @Test
    void authorize_shouldHandleDirectAuthorizationWithPkce() {
        var authCodeProps = new Oid4vciProfileProperties.AuthorizationCodeProperties(
                false, true, List.of("S256"),
                false, List.of("ES256"),
                "none", false
        );

        when(profileProperties.authorizationCode()).thenReturn(authCodeProps);
        when(authorizationCodeCacheStore.add(anyString(), any(AuthorizationCodeData.class)))
                .thenAnswer(invocation -> Mono.just(invocation.getArgument(0, String.class)));

        StepVerifier.create(authorizationService.authorize(
                        null, "client-id", "code", "openid",
                        "my-state", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                        "S256", "https://wallet/callback", null, "https://issuer.example.com"))
                .assertNext(uri -> {
                    assertNotNull(uri);
                    String uriStr = uri.toString();
                    assertTrue(uriStr.startsWith("https://wallet/callback?"));
                    assertTrue(uriStr.contains("code="));
                    assertTrue(uriStr.contains("state=my-state"));
                    assertTrue(uriStr.contains("iss="));
                })
                .verifyComplete();
    }

    @Test
    void authorize_shouldRejectInvalidResponseType() {
        StepVerifier.create(authorizationService.authorize(
                        null, "client-id", "token", null,
                        null, null, null, "https://wallet/callback", null, "https://issuer.example.com"))
                .expectErrorMatches(e -> e instanceof IllegalArgumentException
                        && e.getMessage().equals("response_type must be 'code'"))
                .verify();
    }

    @Test
    void authorize_shouldRejectMissingPkceWhenRequired() {
        var authCodeProps = new Oid4vciProfileProperties.AuthorizationCodeProperties(
                false, true, List.of("S256"),
                false, List.of("ES256"),
                "none", false
        );

        when(profileProperties.authorizationCode()).thenReturn(authCodeProps);

        StepVerifier.create(authorizationService.authorize(
                        null, "client-id", "code", null,
                        null, null, null, "https://wallet/callback", null, "https://issuer.example.com"))
                .expectErrorMatches(e -> e instanceof IllegalArgumentException
                        && e.getMessage().equals("code_challenge is required"))
                .verify();
    }

    @Test
    void authorize_shouldHandleParFlow() {
        PushedAuthorizationRequest parRequest = PushedAuthorizationRequest.builder()
                .clientId("wallet-client")
                .redirectUri("https://wallet/callback")
                .codeChallenge("challenge")
                .codeChallengeMethod("S256")
                .scope("openid")
                .state("par-state")
                .build();

        when(parCacheStore.get(anyString())).thenReturn(Mono.just(parRequest));
        when(parCacheStore.delete(anyString())).thenReturn(Mono.empty());
        when(authorizationCodeCacheStore.add(anyString(), any(AuthorizationCodeData.class)))
                .thenAnswer(invocation -> Mono.just(invocation.getArgument(0, String.class)));

        String requestUri = "urn:ietf:params:oauth:request_uri:test-uuid";

        StepVerifier.create(authorizationService.authorize(
                        requestUri, "wallet-client", null, null,
                        null, null, null, null, null, "https://issuer.example.com"))
                .assertNext(uri -> {
                    assertNotNull(uri);
                    String uriStr = uri.toString();
                    assertTrue(uriStr.startsWith("https://wallet/callback?"));
                    assertTrue(uriStr.contains("code="));
                    assertTrue(uriStr.contains("state=par-state"));
                })
                .verifyComplete();

        verify(parCacheStore).delete(requestUri);
    }

    @Test
    void authorize_shouldFailWithInvalidPar() {
        when(parCacheStore.get(anyString()))
                .thenReturn(Mono.error(new java.util.NoSuchElementException("Not found")));

        StepVerifier.create(authorizationService.authorize(
                        "urn:ietf:params:oauth:request_uri:invalid", "client", null, null,
                        null, null, null, null, null, "https://issuer.example.com"))
                .expectErrorMatches(e -> e instanceof IllegalArgumentException
                        && e.getMessage().contains("Invalid or expired request_uri"))
                .verify();
    }
}
