package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.model.dto.OpenIDProviderMetadata;
import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static es.in2.issuer.backend.shared.domain.util.Constants.CONTENT_TYPE;
import static es.in2.issuer.backend.shared.domain.util.Constants.CONTENT_TYPE_APPLICATION_JSON;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class VerifierServiceImplTest {

    @Mock
    private UrlResolver urlResolver;

    private VerifierServiceImpl verifierService;

    @Test
    void getWellKnownInfo_composesUrlFromInternalBasePath_preservingContextPath() {
        // Internal URL carries the verifier base-path (/verifier). The service
        // must append /.well-known/openid-configuration AFTER the base-path,
        // not strip it by using a leading-slash string concatenation.
        String internalVerifierBase = "http://verifier-core.stg.eudistack.local:8080/verifier";
        String expectedEndpoint = internalVerifierBase + "/.well-known/openid-configuration";
        when(urlResolver.internalVerifierBaseUrl()).thenReturn(internalVerifierBase);

        ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);
        ClientResponse clientResponse = ClientResponse.create(HttpStatus.OK)
                .header(CONTENT_TYPE, CONTENT_TYPE_APPLICATION_JSON)
                .body("{\"issuer\":\"https://verifier.example.com\"," +
                        "\"authorization_endpoint\":\"https://verifier.example.com/authorize\"," +
                        "\"token_endpoint\":\"https://verifier.example.com/token\"}")
                .build();
        when(exchangeFunction.exchange(any())).thenReturn(Mono.just(clientResponse));
        WebClient webClient = WebClient.builder().exchangeFunction(exchangeFunction).build();

        verifierService = new VerifierServiceImpl(webClient, urlResolver);

        OpenIDProviderMetadata expected = OpenIDProviderMetadata.builder()
                .issuer("https://verifier.example.com")
                .authorizationEndpoint("https://verifier.example.com/authorize")
                .tokenEndpoint("https://verifier.example.com/token")
                .build();

        StepVerifier.create(verifierService.getWellKnownInfo())
                .expectNext(expected)
                .verifyComplete();

        verify(urlResolver).internalVerifierBaseUrl();
        verifyNoMoreInteractions(urlResolver);

        ArgumentCaptor<ClientRequest> requestCaptor = ArgumentCaptor.forClass(ClientRequest.class);
        verify(exchangeFunction).exchange(requestCaptor.capture());
        ClientRequest req = requestCaptor.getValue();
        assertEquals(expectedEndpoint, req.url().toString());
        assertEquals(HttpMethod.GET, req.method());
    }
}
