package es.in2.issuer.backend.signing.domain.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.model.dto.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.spi.QtspAuthPort;
import es.in2.issuer.backend.shared.infrastructure.util.HttpUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class QtspIssuerServiceImplTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    private QtspIssuerServiceImpl qtspIssuerService;

    @Mock private QtspAuthPort qtspAuthClient;
    @Mock private HttpUtils httpUtils;

    private RemoteSignatureDto cfg;

    @BeforeEach
    void setUp() {
        cfg = new RemoteSignatureDto(
                "https://domain",
                "clientId", "clientSecret",
                "credId", "pwd",
                "PT10M",
                "sign-hash"
        );

        qtspIssuerService = new QtspIssuerServiceImpl(
                objectMapper,
                qtspAuthClient,
                httpUtils
        );
    }

    @Test
    void validateCredentials_returnsTrueWhenValid() {
        when(qtspAuthClient.requestAccessToken(any(SigningRequest.class), anyString()))
                .thenReturn(Mono.just("token"));

        when(httpUtils.postRequest(contains("/csc/v2/credentials/list"), any(), any()))
                .thenReturn(Mono.just("{\"credentialIDs\":[\"credId\"]}"));

        StepVerifier.create(qtspIssuerService.validateCredentials(cfg))
                .assertNext(valid -> assertThat(valid).isTrue())
                .verifyComplete();
    }

    @Test
    void validateCredentials_returnsFalseWhenInvalid() {
        when(qtspAuthClient.requestAccessToken(any(SigningRequest.class), anyString()))
                .thenReturn(Mono.just("token"));

        when(httpUtils.postRequest(contains("/csc/v2/credentials/list"), any(), any()))
                .thenReturn(Mono.just("{\"credentialIDs\":[\"OTHER\"]}"));

        StepVerifier.create(qtspIssuerService.validateCredentials(cfg))
                .assertNext(valid -> assertThat(valid).isFalse())
                .verifyComplete();
    }

    @Test
    void requestCertificateInfo_serializationError_returnsError() throws Exception {
        ObjectMapper failingMapper = mock(ObjectMapper.class);

        QtspIssuerServiceImpl service = new QtspIssuerServiceImpl(
                failingMapper, qtspAuthClient, httpUtils
        );

        doThrow(new JsonProcessingException("Error serializing request body to JSON") {})
                .when(failingMapper)
                .writeValueAsString(anyMap());

        StepVerifier.create(service.requestCertificateInfo(cfg, "token", "credId"))
                .expectErrorMatches(e -> e.getMessage().contains("Error serializing request body to JSON"))
                .verify();

        verifyNoInteractions(httpUtils);
    }

    @Test
    void resolveRemoteDetailedIssuer_validCredentials_returnsIssuer() {
        when(qtspAuthClient.requestAccessToken(any(SigningRequest.class), anyString()))
                .thenReturn(Mono.just("token-1"));

        when(httpUtils.postRequest(contains("/csc/v2/credentials/list"), any(), any()))
                .thenReturn(Mono.just("{\"credentialIDs\":[\"credId\"]}"));

        String orgId = "ORGID";
        String base64Cert = Base64.getEncoder()
                .encodeToString(("organizationIdentifier=" + orgId).getBytes(StandardCharsets.UTF_8));

        String certInfoJson =
                "{ \"cert\": { " +
                        "\"subjectDN\": \"CN=Test,O=Org,C=ES\", " +
                        "\"serialNumber\": \"123\", " +
                        "\"certificates\": [\"" + base64Cert + "\"]" +
                        "} }";

        when(httpUtils.postRequest(contains("/csc/v2/credentials/info"), any(), any()))
                .thenReturn(Mono.just(certInfoJson));

        StepVerifier.create(qtspIssuerService.resolveRemoteDetailedIssuer(cfg))
                .assertNext(i -> {
                    assertThat(i.organizationIdentifier()).isEqualTo("ORGID");
                    assertThat(i.id()).isEqualTo("did:elsi:ORGID");
                    assertThat(i.organization()).isEqualTo("Org");
                    assertThat(i.country()).isEqualTo("ES");
                    assertThat(i.commonName()).isEqualTo("Test");
                    assertThat(i.serialNumber()).isEqualTo("123");
                })
                .verifyComplete();
    }

    @Test
    void resolveRemoteDetailedIssuer_invalidCredentials_returnsError() {
        RemoteSignatureDto expectedCfg = new RemoteSignatureDto(
                "https://domain",
                "clientId", "clientSecret",
                "EXPECTED_ID", "pwd",
                "PT10M",
                "sign-hash"
        );

        when(qtspAuthClient.requestAccessToken(any(SigningRequest.class), anyString()))
                .thenReturn(Mono.just("access-token"));

        when(httpUtils.postRequest(contains("/csc/v2/credentials/list"), anyList(), anyString()))
                .thenReturn(Mono.just("{\"credentialIDs\":[\"OTHER_ID\"]}"));

        StepVerifier.create(qtspIssuerService.resolveRemoteDetailedIssuer(expectedCfg))
                .expectErrorMatches(e -> e.getMessage().contains("Credentials mismatch"))
                .verify();
    }
}
