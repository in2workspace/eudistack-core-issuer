package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.exception.OAuthTokenException;
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
        var authCodeProps = new Oid4vciProfileProperties.AuthorizationCodeProperties(
                false, true, List.of("S256"),
                false, List.of("ES256"),
                "none", false
        );

        when(profileProperties.authorizationCode()).thenReturn(authCodeProps);

        StepVerifier.create(authorizationService.authorize(
                        null, "client-id", "token", null,
                        null, null, null, "https://wallet/callback", null, "https://issuer.example.com"))
                .expectErrorMatches(e -> e instanceof OAuthTokenException oAuthTokenException
                        && "invalid_request".equals(oAuthTokenException.getErrorCode())
                        && e.getMessage().equals("response_type must be 'code'"))
                .verify();
    }

    @Test
    void authorize_shouldRejectDirectRequestWhenParRequired() {
        // Regression test: RFC 9126 §5 - this Issuer advertises
        // require_pushed_authorization_requests=true whenever the profile requires PAR
        // (AuthorizationServerMetadataServiceImpl), but authorize() used to let a request
        // through processDirectAuthorization regardless, silently accepting an authorization
        // request that skipped PAR entirely. Caught by the OIDF conformance suite's
        // fapi2-security-profile-final-ensure-unsigned-authorization-request-without-using-par-fails test.
        var authCodeProps = new Oid4vciProfileProperties.AuthorizationCodeProperties(
                true, true, List.of("S256"),
                false, List.of("ES256"),
                "none", false
        );

        when(profileProperties.authorizationCode()).thenReturn(authCodeProps);

        StepVerifier.create(authorizationService.authorize(
                        null, "client-id", "code", "openid",
                        "my-state", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                        "S256", "https://wallet/callback", null, "https://issuer.example.com"))
                .expectErrorMatches(e -> e instanceof OAuthTokenException oAuthTokenException
                        && "invalid_request".equals(oAuthTokenException.getErrorCode())
                        && e.getMessage().equals("Pushed Authorization Request is required"))
                .verify();

        verifyNoInteractions(authorizationCodeCacheStore);
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
                .expectErrorMatches(e -> e instanceof OAuthTokenException oAuthTokenException
                        && "invalid_request".equals(oAuthTokenException.getErrorCode())
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
    void authorize_shouldIgnoreOuterStateParamWhenParPresent() {
        // Regression test: RFC 9126 §4 - once request_uri references a pushed authorization
        // request, the authorization server SHOULD ignore any other parameter accompanying
        // that request_uri on the /authorize call - only what was bound to the PAR is
        // authoritative. authorize() used to let a loose outer `state` query param override
        // the state already committed to the PAR (state != null ? state : parRequest.state()),
        // letting a client swap the state after the fact. Caught by the OIDF conformance
        // suite's fapi2-security-profile-final-ensure-different-state-inside-and-outside-request-object test.
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
                        "outer-state", null, null, null, null, "https://issuer.example.com"))
                .assertNext(uri -> {
                    String uriStr = uri.toString();
                    assertTrue(uriStr.contains("state=par-state"));
                    assertFalse(uriStr.contains("outer-state"));
                })
                .verifyComplete();
    }

    @Test
    void authorize_shouldOmitStateWhenParHasNoneEvenIfOuterStatePresent() {
        // Regression test: same RFC 9126 §4 gap, mirror case - if the PAR itself never
        // carried a state, the response must not gain one just because the /authorize call
        // added a loose outer `state` param. Caught by the OIDF conformance suite's
        // fapi2-security-profile-final-state-only-outside-request-object-not-used test.
        PushedAuthorizationRequest parRequest = PushedAuthorizationRequest.builder()
                .clientId("wallet-client")
                .redirectUri("https://wallet/callback")
                .codeChallenge("challenge")
                .codeChallengeMethod("S256")
                .scope("openid")
                .state(null)
                .build();

        when(parCacheStore.get(anyString())).thenReturn(Mono.just(parRequest));
        when(parCacheStore.delete(anyString())).thenReturn(Mono.empty());
        when(authorizationCodeCacheStore.add(anyString(), any(AuthorizationCodeData.class)))
                .thenAnswer(invocation -> Mono.just(invocation.getArgument(0, String.class)));

        String requestUri = "urn:ietf:params:oauth:request_uri:test-uuid";

        StepVerifier.create(authorizationService.authorize(
                        requestUri, "wallet-client", null, null,
                        "outer-state", null, null, null, null, "https://issuer.example.com"))
                .assertNext(uri -> {
                    String uriStr = uri.toString();
                    assertFalse(uriStr.contains("state="));
                })
                .verifyComplete();
    }

    @Test
    void authorize_shouldFailWithInvalidPar() {
        when(parCacheStore.get(anyString()))
                .thenReturn(Mono.empty());

        StepVerifier.create(authorizationService.authorize(
                        "urn:ietf:params:oauth:request_uri:invalid", "client", null, null,
                        null, null, null, null, null, "https://issuer.example.com"))
                .expectErrorMatches(e -> e instanceof OAuthTokenException oAuthTokenException
                        && "invalid_request".equals(oAuthTokenException.getErrorCode())
                        && e.getMessage().contains("Invalid or expired request_uri"))
                .verify();
    }
}
