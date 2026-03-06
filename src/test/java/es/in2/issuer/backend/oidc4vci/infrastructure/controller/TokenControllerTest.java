package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.domain.model.TokenRequest;
import es.in2.issuer.backend.oidc4vci.domain.model.TokenResponse;
import es.in2.issuer.backend.oidc4vci.domain.service.TokenService;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.BodyInserters;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Constants.REFRESH_TOKEN_GRANT_TYPE;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;

@WithMockUser
@MockBean(ReactiveAuthenticationManager.class)
@WebFluxTest(TokenController.class)
class TokenControllerTest {

    @MockBean
    TokenService tokenService;

    @Autowired
    WebTestClient webTestClient;

    @MockBean
    ErrorResponseFactory errorResponseFactory;

    @MockBean
    IssuanceMetrics issuanceMetrics;

    @Test
    void testHandleTokenRequest_RefreshTokenGrant_ShouldReturnOk() {
        String grantType = REFRESH_TOKEN_GRANT_TYPE;
        String refreshToken = "rt-123";
        TokenResponse tokenResponse = new TokenResponse(
                "access-token",
                "token-type",
                3600L,
                "1234");

        when(tokenService.exchangeToken(any(TokenRequest.class), isNull(), any(String.class)))
                .thenReturn(Mono.just(tokenResponse));

        webTestClient
                .mutateWith(csrf())
                .post()
                .uri("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters
                        .fromFormData("grant_type", grantType)
                        .with("refresh_token", refreshToken))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody(TokenResponse.class)
                .isEqualTo(tokenResponse);
    }
}
