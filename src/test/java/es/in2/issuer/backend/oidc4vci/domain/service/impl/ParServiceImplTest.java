package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.model.PushedAuthorizationRequest;
import es.in2.issuer.backend.oidc4vci.domain.model.port.Oid4vciProfilePort;
import es.in2.issuer.backend.oidc4vci.infrastructure.config.Oid4vciProfileProperties;
import es.in2.issuer.backend.shared.domain.service.ClientAttestationValidationService;
import es.in2.issuer.backend.shared.domain.service.DpopValidationService;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;

import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.PAR_CACHE_EXPIRY_SECONDS;
import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.PAR_REQUEST_URI_PREFIX;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ParServiceImplTest {

    @Mock
    private TransientStore<PushedAuthorizationRequest> parCacheStore;

    @Mock
    private Oid4vciProfilePort profileProperties;

    @Mock
    private DpopValidationService dpopValidationService;

    @Mock
    private ClientAttestationValidationService clientAttestationValidationService;

    @InjectMocks
    private ParServiceImpl parService;

    @Test
    void pushAuthorizationRequest_shouldSucceedWithValidHaipRequest() {
        PushedAuthorizationRequest request = PushedAuthorizationRequest.builder()
                .responseType("code")
                .clientId("wallet-client")
                .redirectUri("https://wallet.example.com/callback")
                .codeChallenge("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                .codeChallengeMethod("S256")
                .build();

        var authCodeProps = new Oid4vciProfileProperties.AuthorizationCodeProperties(
                true, true, List.of("S256"),
                true, List.of("ES256"),
                "attest_jwt_client_auth", true
        );

        when(profileProperties.authorizationCode()).thenReturn(authCodeProps);
        when(dpopValidationService.validate(anyString(), eq("POST"), anyString())).thenReturn("dpop-thumbprint");
        when(clientAttestationValidationService.validateHeaders(anyString(), anyString(), any())).thenReturn("wallet-client");
        when(parCacheStore.add(anyString(), any(PushedAuthorizationRequest.class)))
                .thenAnswer(invocation -> Mono.just(invocation.getArgument(0, String.class)));

        StepVerifier.create(parService.pushAuthorizationRequest(request, "dpop-proof", "wia-jwt", "pop-jwt", "https://issuer/par", "https://issuer"))
                .assertNext(response -> {
                    assertTrue(response.requestUri().startsWith(PAR_REQUEST_URI_PREFIX));
                    assertEquals(PAR_CACHE_EXPIRY_SECONDS, response.expiresIn());
                })
                .verifyComplete();
    }

    @Test
    void pushAuthorizationRequest_shouldFailWhenResponseTypeNotCode() {
        PushedAuthorizationRequest request = PushedAuthorizationRequest.builder()
                .responseType("token")
                .build();

        StepVerifier.create(parService.pushAuthorizationRequest(request, null, null, null, "https://issuer/par", null))
                .expectErrorMatches(e -> e instanceof IllegalArgumentException
                        && e.getMessage().equals("response_type must be 'code'"))
                .verify();
    }

    @Test
    void pushAuthorizationRequest_shouldFailWhenPkceRequiredButMissing() {
        PushedAuthorizationRequest request = PushedAuthorizationRequest.builder()
                .responseType("code")
                .build();

        var authCodeProps = new Oid4vciProfileProperties.AuthorizationCodeProperties(
                true, true, List.of("S256"),
                false, List.of("ES256"),
                "none", false
        );

        when(profileProperties.authorizationCode()).thenReturn(authCodeProps);

        StepVerifier.create(parService.pushAuthorizationRequest(request, null, null, null, "https://issuer/par", null))
                .expectErrorMatches(e -> e instanceof IllegalArgumentException
                        && e.getMessage().equals("code_challenge is required"))
                .verify();
    }

    @Test
    void pushAuthorizationRequest_shouldSucceedWithPlainProfile() {
        PushedAuthorizationRequest request = PushedAuthorizationRequest.builder()
                .responseType("code")
                .clientId("client")
                .redirectUri("https://wallet/callback")
                .codeChallenge("challenge")
                .codeChallengeMethod("S256")
                .build();

        var authCodeProps = new Oid4vciProfileProperties.AuthorizationCodeProperties(
                false, true, List.of("S256"),
                false, List.of("ES256"),
                "none", false
        );

        when(profileProperties.authorizationCode()).thenReturn(authCodeProps);
        when(parCacheStore.add(anyString(), any(PushedAuthorizationRequest.class)))
                .thenAnswer(invocation -> Mono.just(invocation.getArgument(0, String.class)));

        StepVerifier.create(parService.pushAuthorizationRequest(request, null, null, null, "https://issuer/par", null))
                .assertNext(response -> assertNotNull(response.requestUri()))
                .verifyComplete();

        verify(dpopValidationService, never()).validate(anyString(), anyString(), anyString());
        verify(clientAttestationValidationService, never()).validateHeaders(anyString(), anyString(), any());
    }
}
